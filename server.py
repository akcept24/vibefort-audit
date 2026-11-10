#!/usr/bin/env python3
"""
VibeFort site server — serves the static site AND the order plumbing API.

Endpoints:
  GET  /, /index.html, /report.html, /style.css, /app.js,
       /.well-known/security.txt          (static, exact pre-existing files)
  POST /api/brief  {name, email, url, tier, notes}
       -> validate, persist order (SQLite, status NEW), alert email +
          client confirmation via Resend, Telegram alert to HQ group.
  POST /api/scan   {url, consent:true, email?}
       -> real gentle surface scan (widecheck port + bundle-secret and
          public-database probes), stores the lead, returns UI-shaped JSON.
  GET/POST/DELETE /api/orders..., /api/scans (X-Admin-Token register)

Stdlib only. Security headers replicate the old nginx.conf posture exactly
on every response.
"""

import contextvars
import datetime
import http.client
import io
import ipaddress
import json
import os
import re
import sqlite3
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import email_template

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("VF_DB_PATH", "/data/vibefort.db")
PORT = int(os.environ.get("PORT", "80"))
ALERT_EMAIL = "security@probcapital.com"  # internal HQ alert inbox (not public)
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
MAIL_FROM = os.environ.get("MAIL_FROM", "ShipAudit Lab <audit@probcapital.com>")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "-1004396317271")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
TIER_PRICES = {"Free scan": 0, "Deep Scan": 29, "Quick Audit": 299,
               "Full Audit": 899, "Deep Audit": 2999, "Monitoring": 79}
ORDER_STATUSES = ["NEW", "PAID", "IN_PROGRESS", "VERIFYING", "DELIVERED",
                  "RETEST"]
# Stripe (live links created 2026-11-09 in acct_1UXEPmL0Rfi91QqA).
# STRIPE_LINKS mirrors CHECKOUT_URLS in app.js — keep the two in sync.
STRIPE_LINKS = {
    "Deep Scan": "https://buy.stripe.com/8x2aEY3HTbe171xe3hdjO00",
    "Quick Audit": "https://buy.stripe.com/cNi6oI1zLci571xe3hdjO01",
    "Full Audit": "https://buy.stripe.com/8x28wQa6h2HvgC77ETdjO02",
    "Deep Audit": "https://buy.stripe.com/6oU28sa6hbe1fy34sHdjO03",
    "Monitoring": "https://buy.stripe.com/bJeaEYfqB6XL71xgbpdjO04",
}
# Webhook signing secret (whsec_...) — set in the app env once the
# endpoint is registered in the Stripe dashboard. While unset the
# webhook route answers 503 and payment matching stays manual.
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
# Paid amounts (cents) are unique per tier, so a completed checkout
# identifies its tier by amount alone.
AMOUNT_TO_TIER = {price * 100: tier for tier, price in TIER_PRICES.items()
                  if price > 0}
# The live payment-link ids (read from the dashboard 2026-11-09).
# When a checkout session carries a payment_link, it must be one of
# these and its amount must equal that tier's price.
PLINK_TO_TIER = {
    "plink_1Ua3hOL0Rfi91QqAUpx9XrMR": "Deep Scan",
    "plink_1Ua3iSL0Rfi91QqAuV4K6rV0": "Quick Audit",
    "plink_1Ua3jmL0Rfi91QqAGDN8Obgp": "Full Audit",
    "plink_1Ua3kgL0Rfi91QqADQWiQvPB": "Deep Audit",
    "plink_1Ua3lqL0Rfi91QqAZhEsUcOQ": "Monitoring",
}


def log(msg):
    sys.stderr.write(f"[{utcnow()}] {msg}\n")
    sys.stderr.flush()

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
    ("Content-Security-Policy",
     "default-src 'self'; script-src 'self'; style-src 'self' "
     "https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
     "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
     "object-src 'none'; base-uri 'self'; form-action 'self'; "
     "upgrade-insecure-requests"),
]

STATIC_FILES = {
    "/": ("index.html", "text/html"),
    "/index.html": ("index.html", "text/html"),
    "/report.html": ("report.html", "text/html"),
    "/style.css": ("style.css", "text/css"),
    "/app.js": ("app.js", "application/javascript"),
    "/.well-known/security.txt": (".well-known/security.txt", "text/plain"),
    "/terms.html": ("terms.html", "text/html"),
    "/privacy.html": ("privacy.html", "text/html"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
    "/robots.txt": ("robots.txt", "text/plain"),
    "/sitemap.xml": ("sitemap.xml", "application/xml"),
}

TIERS = ["Free scan", "Deep Scan", "Quick Audit", "Full Audit", "Deep Audit", "Monitoring"]
EMAIL_RX = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")

# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
# Round 23 (Codex delta-21): an RLock, not a plain Lock.
# The atomic send seams (_gated_send) hold this lock across
# a provider call, and a send's own call stack can re-enter
# lock-taking code on the SAME thread — the seam wraps in
# the invariant catalog do exactly this (an admin delete
# executed from inside a wrapped transport), and production
# bookkeeping adjacent to a send takes the lock in the same
# frame sequence. Cross-thread exclusion — the property
# every rule in this file relies on — is unchanged.
_db_lock = threading.RLock()
_webhook_lock = threading.RLock()


def db_connect():
    path = DB_PATH
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        path = os.path.join(BASE_DIR, "vibefort.db")
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE IF NOT EXISTS orders(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        name TEXT NOT NULL, email TEXT NOT NULL, url TEXT NOT NULL,
        tier TEXT NOT NULL, notes TEXT DEFAULT '',
        amount INTEGER DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'NEW',
        alert_sent INTEGER DEFAULT 0, confirm_sent INTEGER DEFAULT 0,
        tg_sent INTEGER DEFAULT 0)""")
    cols = [r[1] for r in conn.execute("PRAGMA table_info(orders)")]
    for col, ddl in (("amount", "INTEGER DEFAULT 0"),
                     ("tg_sent", "INTEGER DEFAULT 0"),
                     ("paid_event_id", "TEXT"),
                     ("paid_pi", "TEXT")):
        if col not in cols:
            conn.execute(f"ALTER TABLE orders ADD COLUMN {col} {ddl}")
    conn.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        order_id INTEGER, event TEXT NOT NULL, detail TEXT DEFAULT '')""")
    conn.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        url TEXT NOT NULL, email TEXT DEFAULT '',
        grade TEXT DEFAULT '', score INTEGER DEFAULT 0,
        results_json TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS rate_hits(
        bucket TEXT NOT NULL, ip TEXT NOT NULL, ts REAL NOT NULL)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rate_hits"
                 " ON rate_hits(bucket, ip, ts)")
    conn.execute("""CREATE TABLE IF NOT EXISTS monitors(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER UNIQUE NOT NULL,
        url TEXT NOT NULL, email TEXT NOT NULL, name TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        next_run_at REAL NOT NULL,
        last_run_at REAL DEFAULT 0,
        last_scan_id INTEGER,
        last_digest TEXT,
        active INTEGER NOT NULL DEFAULT 1)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS event_locks(
        event_id TEXT PRIMARY KEY,
        purpose TEXT NOT NULL,
        claimed_at REAL NOT NULL,
        owner TEXT)""")
    # Round 19 (Codex delta-18 (b)): the durable bookkeeping for
    # the post-window email rule, one row per logical email
    # notification ("receipt:<order_id>"). It is deliberately
    # NOT the receipt's event lock: pin A5 fixes that a failed
    # send leaves no lock row, while the first-unknown stamp and
    # the spent/settled flags below must survive lock releases.
    conn.execute("""CREATE TABLE IF NOT EXISTS email_delivery(
        notif_key TEXT PRIMARY KEY,
        first_unknown_at REAL,
        post_window_used INTEGER NOT NULL DEFAULT 0,
        settled INTEGER NOT NULL DEFAULT 0)""")
    # Round 21 (Codex delta-19 (a2)): the first-ATTEMPT stamp,
    # written before every receipt send (first-stamp-wins).
    # Round 19 stamped only the first UNKNOWN outcome, after
    # the send — a crash between an accepted send and that
    # stamp left the attempt unrecorded, and a recovery past
    # the window could not recognize the window had expired.
    ecols = [r[1] for r in conn.execute(
        "PRAGMA table_info(email_delivery)")]
    if "first_attempt_at" not in ecols:
        conn.execute(
            "ALTER TABLE email_delivery ADD COLUMN "
            "first_attempt_at REAL")
    # Round 22 (Codex delta-20): the email window basis is the
    # first UNKNOWN outcome again (the round-21 first-attempt
    # widening was rejected by the parent as a contract
    # change). Two outcome columns let a later decision tell a
    # recorded outcome from an attempt whose outcome was never
    # recorded (crash between acceptance and outcome write):
    # last_attempt_at moves at every pre-send stamp,
    # last_outcome_at moves only when an outcome is recorded.
    if "last_attempt_at" not in ecols:
        conn.execute(
            "ALTER TABLE email_delivery ADD COLUMN "
            "last_attempt_at REAL")
    if "last_outcome_at" not in ecols:
        conn.execute(
            "ALTER TABLE email_delivery ADD COLUMN "
            "last_outcome_at REAL")
    # Round 22: durable deleted-order tombstones. The admin
    # delete writes the tombstone FIRST, inside the same
    # _db_lock transaction that removes the order's rows;
    # every send seam re-consults existence+tombstone under
    # the same lock discipline before its HTTP call, so a
    # deletion that lands in the check-to-send gap aborts the
    # send instead of racing it. Order ids are AUTOINCREMENT
    # and never reused, so a tombstone can never condemn a
    # future order.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS deleted_orders("
        "order_id INTEGER PRIMARY KEY, deleted_at REAL NOT NULL)")
    lcols = [r[1] for r in conn.execute("PRAGMA table_info(event_locks)")]
    if "owner" not in lcols:
        conn.execute("ALTER TABLE event_locks ADD COLUMN owner TEXT")
    try:
        # One payment can win exactly ONE order, atomically, across
        # processes (Codex delta-10 #1): the partial unique index
        # is the fence; transition_order_status also pre-checks.
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_paid_pi "
            "ON orders(paid_pi) WHERE paid_pi IS NOT NULL")
    except Exception as e:
        log(f"paid_pi unique index not created: {e!r}")
    conn.execute("""CREATE TABLE IF NOT EXISTS fulfilment_requests(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER UNIQUE NOT NULL,
        kind TEXT NOT NULL,
        payload TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'queued',
        created_at TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS stripe_events(
        event_id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        order_id INTEGER,
        received_at TEXT NOT NULL)""")
    mcols = [r[1] for r in conn.execute("PRAGMA table_info(monitors)")]
    if "pending_alert" not in mcols:
        conn.execute("ALTER TABLE monitors ADD COLUMN pending_alert TEXT")
    scols = [r[1] for r in conn.execute("PRAGMA table_info(stripe_events)")]
    if "payment_intent" not in scols:
        conn.execute(
            "ALTER TABLE stripe_events ADD COLUMN payment_intent TEXT")
    if "amount" not in scols:
        conn.execute("ALTER TABLE stripe_events ADD COLUMN amount INTEGER")
    if "claim" not in scols:
        conn.execute("ALTER TABLE stripe_events ADD COLUMN claim TEXT")
    if "claimed_at" not in scols:
        conn.execute("ALTER TABLE stripe_events ADD COLUMN claimed_at REAL")
    return conn


def log_event(order_id, event, detail=""):
    """Write-then-emit (round 18, Codex delta-17 (b)): the
    durable events-table row is the record; the process-log line
    is its mirror and is emitted ONLY after the insert commits.
    The old order emitted the line even when the insert failed,
    so a courtesy log whose write was lost was emitted once by
    the fire and again by the reconcile that later wrote the
    record — two observable emissions for one event. Callers
    that need certainty already verify by reading the table
    back; nothing load-bearing rides on the stderr line.

    Round 23 (Codex delta-21 (b)): for an ORDER-KEYED event
    (order_id is not None) this writer is also the deletion
    guard, and the guard is ATOMIC: the aliveness check and
    the INSERT run inside ONE _db_lock acquisition. The
    admin delete transaction holds the same lock from its
    tombstone write to its commit (and removes the order's
    events inside that transaction), so check and insert
    cannot be split by a deletion: the row is written while
    the order lives — and a later delete removes it with the
    order's other events — or it is not written at all. The
    round-22 discipline (a separate alive check in
    _log_event_alive or _record_effects_ok, then this insert)
    left exactly that gap: a deletion landing between the
    check and the insert recreated an orphan event for a
    dead order. Events with order_id None are genuinely
    global and take the plain path. Returns True when the
    row was written, False when it was skipped (dead order)
    or the write failed."""
    try:
        with _db_lock:
            if order_id is not None and _order_dead(order_id):
                return False
            conn = db_connect()
            conn.execute(
                "INSERT INTO events(created_at,order_id,event,detail)"
                " VALUES(?,?,?,?)", (utcnow(), order_id, event, detail))
            conn.commit()
            conn.close()
    except Exception as e:
        log(f"event-log write failed: {e!r}")
        return False
    log(f"order={order_id} event={event} {detail}")
    return True


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Outbound notifications
# ---------------------------------------------------------------------------
class _SendOutcome(tuple):
    """A send result: the legacy (ok, detail) pair, plus the
    tri-state classification (.status) the paid/monitor paths
    judge by (round 18, Codex delta-17 (a1)). Tuple behaviour
    is unchanged — every existing caller unpacks (ok, detail)
    exactly as before. The classification:

    "delivered" — the provider definitively accepted the
        message (Resend 2xx + id; Telegram ok:true).
    "failed" — DEFINITE non-delivery: the provider rejected
        the request (HTTP 4xx / ok:false) or the channel is not
        configured (nothing was sent). A retry is a fresh send,
        never a duplicate.
    "unknown" — the transport failed ambiguously (exception,
        timeout, HTTP 5xx): the provider may have accepted the
        message before its answer was lost. Retrying blindly
        duplicates it; the callers' round-18 semantics (Resend
        idempotency key for email, intent-first at-most-once
        for Telegram) exist for exactly this arm.
    """

    def __new__(cls, ok, detail, status):
        self = super().__new__(cls, (ok, detail))
        self.status = status
        return self


def _send_status(result):
    """The tri-state of a send result. The real wrappers attach
    .status; a plain (ok, detail) tuple — e.g. a test stub —
    models a DEFINITE outcome: delivered iff ok."""
    st = getattr(result, "status", None)
    if st in ("delivered", "failed", "unknown"):
        return st
    return "delivered" if result[0] else "failed"


# The Resend Idempotency-Key for the logical notification the
# current call stack is sending, set by the paid/monitor paths
# (receipt:<order_id>; a per-alert key for monitoring). The
# wrapper below reads it — deliberately NOT a send_resend
# parameter, so the function's long-standing signature (and
# every stub of it) is untouched. A retry of the same logical
# notification re-sets the same key, and Resend dedupes the
# retry instead of delivering a second copy (round 18).
_MAIL_IDEM = contextvars.ContextVar("vf_mail_idem", default=None)


# Round 24 (Codex delta-22): the TOTAL wall-clock deadline
# for a gated send. Round 23 stated a delete's wait for an
# in-flight send as bounded by "the provider timeout
# (20 s)" — but urllib's timeout caps each socket
# operation, not the call: a provider dribbling its
# response (every read prompt, the body minutes long) held
# _db_lock far past 20 s. _gated_send therefore arms an
# absolute deadline (this constant, seconds) in the
# ContextVar below for the duration of the provider call,
# and the two wrappers enforce it on their transport.
# The cut surfaces inside the wrappers as a transport
# exception, so their own tri-state machinery classifies
# it — "unknown" (the provider may have accepted the
# message), exactly like a lost answer; the paid/monitor
# idempotency semantics govern the retry. The deadline is
# deliberately NOT a wrapper parameter (the _MAIL_IDEM
# pattern above): the wrappers' signatures — and every
# stub of them — are untouched, and a send outside
# _gated_send (the unmatched-payment alert) arms no
# deadline and behaves exactly as before.
#
# Round 25 (Codex delta-23): round 24 enforced the
# deadline at the response-body read and shortened the
# per-operation timeout — delta-23 showed that is not
# phase-complete: a HEADER dribble inside urlopen and a
# CHUNK-FRAMING dribble inside http.client's read1()
# chunk parsing both outlived the deadline (each socket
# operation prompt, the aggregate unbounded), and a
# deadline cut inside an HTTPError body read was
# swallowed by the wrappers' error arms and classified
# by status instead of unknown. Enforcement now sits
# BELOW http.client's parsing, on the raw socket: a
# gated send's exchange runs through deadline-aware
# http.client connection classes (swapped in for the
# urlopen call only — see _send_urlopen) whose connected
# socket is wrapped in _DeadlineSocket. Every blocking
# socket operation — connect is separately capped by the
# shortened urlopen timeout; request send, header read,
# body read including chunk framing and trailers, error
# body read — re-caps the socket timeout to what is left
# of the deadline before it starts and refuses with
# _SendDeadlineExceeded once the budget is spent, so no
# single operation can END after the deadline and the
# exchange as a whole is cut at the deadline (plus the
# negligible processing between operations). Expiry is
# the dedicated _SendDeadlineExceeded (a TimeoutError),
# and both HTTPError arms classify it "unknown" — see
# _deadline_blown. _read_body_bounded keeps its read1
# clock-check loop as the layer for scripted transports
# (which have no socket to shim) and routes HTTPError
# bodies — addinfourl has no read1 and its read() ignores
# a size argument — to the wrapped response's read1.
#
# Round 26 (Codex delta-24): delta-24 certified the
# read/write phases for exchanges that REACH the shim,
# but refuted the construction and the connect phase.
# (1) Under the class swap, Python 3.12's
# HTTPSConnection.__init__ resolves its explicit super()
# against the REPLACED global and construction raised
# TypeError — every armed HTTPS send (both providers
# are HTTPS) would have failed without sending; the
# catalog missed it because its specimens were HTTP.
# The deadline classes now initialise through CAPTURED
# original class objects (never a call-time global
# lookup) and take their TLS context from the module
# factory _HTTPS_CONTEXT_FACTORY, so they construct
# and operate identically under the swap or not, for
# armed and unarmed callers alike. (2) Connection
# establishment ran BEFORE the shim existed: DNS,
# per-address connects (each with the full timeout),
# proxy CONNECT and the TLS handshake were not
# aggregate-bounded. Armed connect now resolves once
# and iterates addresses itself, re-capping every
# attempt at the remaining budget; the tunnel runs
# over the shim; the handshake runs as one operation
# on a socket timed out at the remaining budget. The
# one sub-operation that remains uncappable by
# construction is the single getaddrinfo call itself,
# named as the bound's only exception in the JOURNAL
# statement. (3) Descriptor cleanup is deterministic:
# the shim emulates the real socket's makefile
# refcount (close() marks; the real close lands with
# the last reader, or immediately when no reader
# exists), connect-phase failures force-close in
# _deadline_connect, and the wrappers close HTTPError
# responses explicitly on armed exchanges.
#
# Round 27 (Codex delta-25): delta-25 certified the
# round-26 construction, per-attempt capping, tunnel,
# cleanup and catalog, and refuted three points.
# (1) The deadline HTTPS class DISCARDED a
# caller-supplied SSLContext and substituted a
# factory default — but on the genuine urllib path
# trust arrives exactly as a supplied context: the
# opener's HTTPS handler passes its context object
# into every construction. The class is now a faithful
# drop-in (see _DeadlineHTTPSConnection): a supplied
# context is used verbatim on both connect paths, and
# the factory serves context=None constructions only.
# (2) The factory ran per connection, inside the
# timed path. Rounds 27-28: on the gated path the
# question is structural — the opener is built at
# import (see the warm-up beside
# _HTTPS_CONTEXT_FACTORY), so its handler's context
# exists from process start, and the handler always
# supplies it; direct context=None constructions
# create fresh per construction, stdlib semantics,
# never on the gated path.
# (3) A redirect inside one exchange opened further
# connections, each resolving the host again; armed
# resolutions are now cached per exchange (see
# _SEND_RESOLUTION_CACHE), and the JOURNAL bound
# counts the resolver residual per distinct host
# within the exchange.
_GATED_SEND_DEADLINE = 30.0
_SEND_DEADLINE_AT = contextvars.ContextVar(
    "vf_send_deadline_at", default=None)

# Round 27 (Codex delta-25 finding 1): one gated
# exchange can open several connections — a provider
# redirect inside a single urlopen call constructs
# another connection — and EVERY connection used to
# resolve the host again, so the bound's resolver
# residual was per connection, not per exchange.
# _send_urlopen — the one place all of an armed
# exchange's connections are created — installs a
# fresh dict here for the duration of the call, and
# _deadline_tcp_connect consults it before resolving
# and populates it after a successful resolution:
# within one exchange each distinct host is resolved
# at most once, redirects included. Outside an armed
# _send_urlopen call the value is None and resolution
# keeps the legacy per-connection behaviour.
_SEND_RESOLUTION_CACHE = contextvars.ContextVar(
    "vf_send_resolution_cache", default=None)

# The providers' endpoints, as constants (round 25) so the
# catalog can point the genuine wrappers at a local test
# server; the values are the long-standing literals.
_RESEND_API_URL = "https://api.resend.com/emails"
_TELEGRAM_API_BASE = "https://api.telegram.org"


class _SendDeadlineExceeded(TimeoutError):
    """The armed gated-send deadline expired mid-exchange.
    A TimeoutError subclass so every pre-existing timeout
    handling keeps its shape; the dedicated type lets the
    wrappers' HTTPError arms tell a deadline cut from an
    ordinary body-read failure (delta-23 finding 3)."""


def _send_deadline_remaining():
    """Seconds left on the armed gated-send deadline, or
    None when no deadline is armed."""
    at = _SEND_DEADLINE_AT.get()
    if at is None:
        return None
    return at - time.monotonic()


def _deadline_blown(exc):
    """True when a transport failure IS the gated-send
    deadline expiring: the dedicated exception, or a plain
    socket TimeoutError raised by an operation whose
    timeout the deadline had capped, observed once the
    budget is spent."""
    if isinstance(exc, _SendDeadlineExceeded):
        return True
    if isinstance(exc, TimeoutError):
        remaining = _send_deadline_remaining()
        return remaining is not None and remaining <= 0
    return False


class _DeadlineSocket:
    """Delegating wrapper around a connected (possibly
    TLS-wrapped) socket, installed by the deadline-aware
    connection classes below for the duration of one gated
    send's exchange. Before every blocking operation the
    real socket's timeout is re-capped to what is left of
    the armed deadline — min(20, remaining), preserving
    the wrappers' long-standing per-operation ceiling —
    and once the budget is spent the operation refuses
    with _SendDeadlineExceeded. A socket timeout raised by
    an operation the deadline had capped, observed with
    the budget spent, is converted to _SendDeadlineExceeded.
    Because an operation's timeout is set to the time
    remaining at ITS start, no operation can end after
    the deadline: the aggregate exchange is bounded by
    the deadline in every phase http.client drives over
    this socket — request send, status line and headers,
    body (including the reads http.client's chunk parser
    performs internally), and error bodies. With no
    deadline armed IN THIS CONTEXT the wrapper delegates
    everything untouched (it can be constructed around a
    concurrent unarmed fetch's socket — see _send_urlopen
    — and must then be behaviourally invisible)."""

    def __init__(self, sock):
        self._sock = sock
        self._close_marked = False
        self._io_refs = 0
        self._real_closed = False

    def __getattr__(self, name):
        if name in ("_sock", "_close_marked", "_io_refs",
                    "_real_closed"):
            raise AttributeError(name)
        return getattr(self._sock, name)

    def _really_close(self):
        if self._real_closed:
            return
        self._real_closed = True
        try:
            self._sock.close()
        except Exception:
            pass

    def _force_close(self):
        """Close the real socket NOW, whatever the reader
        refcount says. Used by the connect-phase failure
        paths (round 26), where the exchange is being
        abandoned before any response reader can exist —
        deterministic cleanup there cannot wait for a
        reader that will never come."""
        self._close_marked = True
        self._really_close()

    def _reader_open(self):
        self._io_refs += 1

    def _reader_closed(self):
        if self._io_refs > 0:
            self._io_refs -= 1
        if self._close_marked and self._io_refs == 0:
            self._really_close()

    def close(self):
        # Deliberately does NOT necessarily close the
        # real socket. urllib's do_open calls sock.close()
        # on the connection's socket immediately after
        # getresponse() and then keeps reading the body
        # through the response: with a real socket that is
        # safe because close() only marks it — the OS
        # descriptor lives until the last makefile object
        # is done (the socket's io refcount). The shim
        # emulates exactly that contract with its own
        # refcount (round 26): close() records the mark,
        # and the real close lands when the last makefile
        # reader goes away (_reader_closed). When NO
        # reader exists — a connect-phase failure, a
        # connection closed before any response — the mark
        # closes the real socket immediately, so cleanup
        # on those paths is deterministic and never waits
        # for object destruction (delta-24 (c)).
        self._close_marked = True
        if self._io_refs == 0:
            self._really_close()

    def _cap(self):
        """Re-cap the real socket's timeout to the budget
        left; True when a deadline is armed in this
        context. Raises _SendDeadlineExceeded once the
        budget is spent."""
        remaining = _send_deadline_remaining()
        if remaining is None:
            return False
        if remaining <= 0:
            raise _SendDeadlineExceeded(
                "gated send deadline exceeded")
        try:
            self._sock.settimeout(min(20.0, remaining))
        except Exception:
            pass
        return True

    def _timed(self, fn, *args):
        armed = self._cap()
        try:
            return fn(*args)
        except TimeoutError:
            if armed:
                remaining = _send_deadline_remaining()
                if remaining is not None and remaining <= 0:
                    raise _SendDeadlineExceeded(
                        "gated send deadline exceeded") \
                        from None
            raise

    def recv(self, bufsize, flags=0):
        return self._timed(self._sock.recv, bufsize, flags)

    def recv_into(self, buffer, nbytes=0, flags=0):
        return self._timed(self._sock.recv_into, buffer,
                           nbytes, flags)

    def send(self, data, flags=0):
        return self._timed(self._sock.send, data, flags)

    def sendall(self, data, flags=0):
        # Manual loop over send() so every partial send is
        # re-capped like every other operation (the real
        # sendall would loop internally on one timeout).
        view = memoryview(data)
        total = 0
        while total < len(view):
            sent = self.send(view[total:], flags)
            if sent == 0:
                raise ConnectionError(
                    "socket connection broken during a "
                    "gated send")
            total += sent

    def settimeout(self, timeout):
        # Plain delegation: the deadline re-caps before
        # every operation regardless of what any caller
        # set in between.
        return self._sock.settimeout(timeout)

    def makefile(self, mode="r", buffering=None, *,
                 encoding=None, errors=None, newline=None):
        if _send_deadline_remaining() is None \
                or "r" not in mode:
            return self._sock.makefile(
                mode, buffering, encoding=encoding,
                errors=errors, newline=newline)
        # Armed: http.client reads the response through
        # this buffered layer, whose every raw read is a
        # deadline-capped recv_into on the shim — the
        # funnel through which status line, headers and
        # chunk parsing are all bounded. The reader is
        # refcounted on the shim (round 26): its close
        # drops the refcount, and the real socket closes
        # once the connection's close() mark has ALSO
        # landed — the real socket's own lifecycle, so a
        # temporary reader (the proxy tunnel's response)
        # closing mid-exchange cannot kill the descriptor
        # the exchange still needs.
        raw = _DeadlineRawIO(self)
        self._reader_open()
        if buffering is not None and buffering == 0:
            return raw
        bufsize = io.DEFAULT_BUFFER_SIZE \
            if buffering is None or buffering < 0 \
            else buffering
        return io.BufferedReader(raw, bufsize)


class _DeadlineRawIO(io.RawIOBase):
    """The raw layer under _DeadlineSocket.makefile: each
    readinto is one recv_into on the shim, so a buffered
    read1 keeps its at-most-one-socket-read meaning —
    the property _read_body_bounded's clock-checked loop
    relies on."""

    def __init__(self, dsock):
        self._dsock = dsock
        self._reader_close_done = False

    def readable(self):
        return True

    def close(self):
        # This reader is going away: drop its refcount on
        # the shim. The real socket closes here ONLY if
        # the connection's close() mark has already landed
        # (see _DeadlineSocket.close) — a temporary reader
        # (the proxy tunnel's response) must not close the
        # descriptor mid-exchange.
        if getattr(self, "_reader_close_done", True):
            return
        self._reader_close_done = True
        try:
            self._dsock._reader_closed()
        finally:
            super().close()

    def readinto(self, b):
        return self._dsock.recv_into(b)

    def readinto1(self, b):
        return self._dsock.recv_into(b)


# Captured originals (round 26, Codex delta-24 finding
# 1): the deadline connection classes below are swapped
# INTO http.client's globals for an armed urlopen call,
# and Python 3.12's HTTPSConnection.__init__ resolves
# its explicit super(HTTPSConnection, self) against the
# REPLACED global — constructing one under the swap
# raised TypeError, so every armed HTTPS send failed
# without sending. The classes here therefore NEVER
# initialise through the originals' __init__ by name:
# they call the CAPTURED original class objects
# directly, so no call-time global lookup can influence
# their construction, under the swap or not, for armed
# and unarmed callers alike.
_ORIG_HTTP_CONNECTION = http.client.HTTPConnection
_ORIG_HTTPS_CONNECTION = http.client.HTTPSConnection

# The stdlib connections' own default-timeout sentinel,
# captured the same way (this module's `import socket`
# sits far below, so the default in the signatures
# below cannot name it directly at class-creation
# time).
_SEND_TIMEOUT_DEFAULT = http.client.socket \
    ._GLOBAL_DEFAULT_TIMEOUT

# The module's HTTPS-context seam (rounds 26-27): a
# deadline HTTPS connection constructed with
# context=None takes its TLS context from this factory
# — in production the stdlib's own default-context
# creator, captured here at module level, so no
# call-time global lookup (and no eagerly evaluated
# globals().get fallback, the round-26 shape delta-25
# flagged) can influence construction. A construction
# WITH a supplied context never consults the factory:
# the caller's context is used verbatim, exactly as
# the stdlib constructor does (that is how trust
# arrives on the urllib path — the opener's HTTPS
# handler passes its context into every construction).
# The catalog patches this reference to observe and
# control factory consultations.
_HTTPS_CONTEXT_FACTORY = http.client._create_https_context

# Round 28 (Codex delta-26 finding 1): opener warm-up.
# urllib.request.urlopen builds the process-global
# opener LAZILY on its first call, and building it
# constructs the HTTPS handler, whose __init__ creates
# a default TLS context. On a process's FIRST gated
# send that lazy build would happen INSIDE the timed
# exchange, uncapped. Perform exactly that act here,
# at import: urlopen's lazy branch is the literal
# `_opener = opener = build_opener()` (urllib/request
# .py), so installing build_opener() with no arguments
# — when, and only when, the global opener is still
# unset — is the identical construction, moved to
# process start. The handler and its context then
# exist before any exchange, and no gated send ever
# creates either. An opener a host process installed
# before importing this module is never clobbered.
#
# Round 29 (Codex delta-27 finding 1): the install is
# NOT unconditional. The built opener is held in a
# local and installed only if the global is STILL
# unset at install time, so a host opener installed
# concurrently — while build_opener() was running —
# is never clobbered either. This double-check
# strictly exceeds stdlib's own lazy discipline:
# urlopen's lazy branch is a single check-then-act
# (urllib/request.py ~211) with no re-check and no
# lock. The one residual is a host install landing
# between the final check and the assignment itself —
# a single bytecode-store window, narrower than the
# pattern stdlib itself ships; no atomicity is
# claimed for it.
if urllib.request._opener is None:
    _warmed_opener = urllib.request.build_opener()
    if urllib.request._opener is None:
        urllib.request.install_opener(_warmed_opener)

# Round 28 (Codex delta-26 finding 3): there is NO
# cache of factory contexts. Round 27 cached them
# process-wide, which handed ONE MUTABLE context
# object to separate context=None callers — a caller's
# mutation, or a trust-store change between
# constructions, then diverged from the stdlib
# constructor's fresh-per-construction semantics.
# context=None in the deadline __init__ therefore
# calls the factory fresh on every construction,
# exactly as http.client.HTTPSConnection does. The
# gated path is structurally unaffected: the opener's
# handler always supplies its context (delta-26 (b)
# certified the factory is consulted 0 times there),
# and the warm-up above keeps that handler's creation
# out of the exchange.


def _armed_remaining_or_raise():
    """Remaining gated-send budget; raises
    _SendDeadlineExceeded once it is spent."""
    remaining = _send_deadline_remaining()
    if remaining is not None and remaining <= 0:
        raise _SendDeadlineExceeded(
            "gated send deadline exceeded")
    return remaining


def _deadline_tcp_connect(conn):
    """Armed TCP establishment, attempt by attempt
    (round 26): the name is resolved — a blocking
    getaddrinfo call, the one sub-operation that
    cannot be capped by construction and that the
    JOURNAL statement names as the bound's exception —
    and the addresses are then iterated HERE: before
    every attempt the remaining budget is recomputed
    and that attempt's socket timeout is capped at
    min(20, remaining), so an attempt starting inside
    the budget ends by the deadline at the latest, and
    a spent budget refuses the next attempt before it
    starts. Round 27 (delta-25 finding 1): the
    resolution consults the per-exchange cache
    _send_urlopen installs (keyed by host ALONE — round
    28, delta-26 finding 2; the call's family/type
    arguments are this call site's constants), so a
    host already resolved in this exchange — e.g. by
    the connection a redirect started from, even one
    the redirect retargets to another port — is not
    resolved again; the cached address set is reused
    with THIS connection's port substituted (see the
    loop below). With no cache installed the resolution
    is the legacy per-connection one."""
    sys.audit("http.client.connect", conn, conn.host,
              conn.port)
    cache = _SEND_RESOLUTION_CACHE.get()
    infos = cache.get(conn.host) if cache is not None else None
    if infos is None:
        infos = socket.getaddrinfo(conn.host, conn.port, 0,
                                   socket.SOCK_STREAM)
        if cache is not None:
            cache[conn.host] = infos
    last_exc = None
    for family, socktype, proto, _canon, sockaddr in infos:
        # A cached sockaddr carries the port of the
        # resolution that produced it; a connection to a
        # DIFFERENT port on the same host (a redirect)
        # substitutes its own port — everything past the
        # port (an IPv6 sockaddr's flowinfo/scope tail)
        # is the host's and is preserved verbatim.
        if sockaddr[1] != conn.port:
            sockaddr = (sockaddr[0], conn.port) \
                + sockaddr[2:]
        remaining = _armed_remaining_or_raise()
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(min(20.0, remaining))
            if conn.source_address is not None:
                sock.bind(conn.source_address)
            sock.connect(sockaddr)
        except BaseException as exc:
            try:
                sock.close()
            except Exception:
                pass
            if isinstance(exc, TimeoutError) and \
                    _send_deadline_remaining() is not None \
                    and _send_deadline_remaining() <= 0:
                raise _SendDeadlineExceeded(
                    "gated send deadline exceeded while "
                    "connecting") from None
            last_exc = exc
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP,
                            socket.TCP_NODELAY, 1)
        except OSError:
            pass
        return sock
    if last_exc is not None:
        raise last_exc
    raise OSError(
        f"getaddrinfo returned no addresses for "
        f"{conn.host}:{conn.port}")


def _deadline_connect(conn, tls):
    """connect() for the deadline connection classes.

    Unarmed (no deadline in THIS context — e.g. an
    unarmed send constructed inside another exchange's
    swap window): the CAPTURED original connect runs
    verbatim (legacy semantics), and the resulting
    socket is wrapped in a shim that, with no deadline
    armed in its caller's context, delegates everything
    untouched.

    Armed: connection establishment is brought under
    the deadline attempt by attempt — TCP connects via
    _deadline_tcp_connect; the proxy CONNECT tunnel,
    when one is configured, runs over the shim (every
    operation re-capped); the TLS handshake then runs
    as ONE operation on the raw socket whose timeout is
    the remaining budget at its start. After the
    handshake the round-25 shim governs the HTTP
    phases. On ANY failure after the raw socket exists,
    it is closed deterministically here (force close),
    never left to object destruction (delta-24 (c))."""
    if _send_deadline_remaining() is None:
        if tls:
            _ORIG_HTTPS_CONNECTION.connect(conn)
        else:
            _ORIG_HTTP_CONNECTION.connect(conn)
        if conn.sock is not None:
            conn.sock = _DeadlineSocket(conn.sock)
        return
    _armed_remaining_or_raise()
    raw = None
    try:
        raw = _deadline_tcp_connect(conn)
        conn.sock = raw
        if conn._tunnel_host:
            conn.sock = _DeadlineSocket(raw)
            _armed_remaining_or_raise()
            conn._tunnel()
            # The tunnel's response reader has closed by
            # now (its close only dropped a makefile
            # refcount — the descriptor lives); detach the
            # shim so the TLS handshake below runs on the
            # raw socket itself.
            conn.sock = raw
        if tls:
            remaining = _armed_remaining_or_raise()
            raw.settimeout(min(20.0, remaining))
            server_hostname = conn._tunnel_host or conn.host
            try:
                tls_sock = conn._context.wrap_socket(
                    raw, server_hostname=server_hostname)
            except BaseException as exc:
                if _deadline_blown(exc):
                    raise _SendDeadlineExceeded(
                        "gated send deadline exceeded "
                        "during the TLS handshake") from None
                raise
            conn.sock = _DeadlineSocket(tls_sock)
        elif not isinstance(conn.sock, _DeadlineSocket):
            conn.sock = _DeadlineSocket(raw)
    except BaseException:
        sock = conn.sock
        conn.sock = None
        if sock is not None:
            try:
                force = getattr(sock, "_force_close", None)
                if callable(force):
                    force()
                else:
                    sock.close()
            except Exception:
                pass
        raise


class _DeadlineHTTPConnection(_ORIG_HTTP_CONNECTION):
    def __init__(self, host, port=None, *,
                 timeout=_SEND_TIMEOUT_DEFAULT,
                 source_address=None, blocksize=8192):
        _ORIG_HTTP_CONNECTION.__init__(
            self, host, port, timeout=timeout,
            source_address=source_address,
            blocksize=blocksize)

    def connect(self):
        _deadline_connect(self, tls=False)


class _DeadlineHTTPSConnection(_ORIG_HTTPS_CONNECTION):
    def __init__(self, host, port=None, *,
                 timeout=_SEND_TIMEOUT_DEFAULT,
                 source_address=None, context=None,
                 blocksize=8192):
        _ORIG_HTTP_CONNECTION.__init__(
            self, host, port, timeout=timeout,
            source_address=source_address,
            blocksize=blocksize)
        # A faithful drop-in for the stdlib constructor
        # (round 27, Codex delta-25 findings 1 and 3):
        # mirror its context logic case by case — a
        # SUPPLIED context is used verbatim (self._context
        # IS the caller's object; on the urllib path this
        # is the opener handler's context, which is how
        # trust actually arrives), and context=None takes
        # a FRESH factory context, exactly as the stdlib
        # constructor creates one per construction (round
        # 28, Codex delta-26 finding 3: round 27's
        # process-wide cache handed one mutable object to
        # separate callers; the cache is removed — see
        # the note beside _HTTPS_CONTEXT_FACTORY). The
        # factory is read as the module global of that
        # name — the module's ordinary patch seam. The
        # original __init__ itself still never runs — its
        # explicit-super lookup is exactly what broke
        # under the swap — but everything it would have
        # decided about the context is decided here,
        # identically.
        if context is None:
            context = _HTTPS_CONTEXT_FACTORY(self._http_vsn)
        self._context = context

    def connect(self):
        _deadline_connect(self, tls=True)


# Serializes the http.client class swap in _send_urlopen.
# Gated sends already hold _db_lock for the whole call
# (round 23), so two armed exchanges never overlap; the
# lock makes the swap's own invariant local rather than
# derived from that fact.
_send_swap_lock = threading.Lock()


def _send_urlopen(req):
    """urlopen for the provider wrappers: the long-standing
    20 s per-operation timeout, shortened to whatever is
    left of the gated-send deadline when one is armed —
    and a refusal to start once it is spent (the
    _SendDeadlineExceeded lands in the wrappers' own
    exception arm and classifies as "unknown").

    Unarmed, this is exactly the long-standing plain
    urlopen call. Armed, the exchange additionally runs
    through the deadline-aware http.client connection
    classes for this call only: urllib's handlers resolve
    http.client.HTTPConnection / HTTPSConnection at call
    time, so the classes are swapped in around the call
    and restored in the finally — the global urlopen entry
    point (and every stub of it) is untouched, and the
    connection the handlers build wraps its socket in
    _DeadlineSocket at connect time. The swap window is
    the urlopen call itself (headers included); the
    shimmed socket outlives it inside the connection. A
    concurrent unarmed fetch constructed inside the
    window gets a shim whose context has no deadline
    armed and which therefore delegates everything
    untouched. Round 26 (Codex delta-24): the swapped
    classes initialise through captured original class
    objects, so constructing one inside the window —
    HTTPS included, armed or unarmed — cannot hit the
    replaced-global super() failure; and an armed
    exchange's connection establishment is itself
    budget-capped attempt by attempt (see
    _deadline_connect). Round 27 (Codex delta-25): for
    the duration of the call a fresh per-exchange
    resolution cache is installed in
    _SEND_RESOLUTION_CACHE (set/reset with the swap),
    so every connection this call creates — redirects
    included — resolves each distinct host at most
    once; the cache dies with the call."""
    remaining = _send_deadline_remaining()
    if remaining is None:
        return urllib.request.urlopen(req, timeout=20)
    if remaining <= 0:
        raise _SendDeadlineExceeded(
            "gated send deadline already spent before the "
            "provider call started")
    with _send_swap_lock:
        saved = (http.client.HTTPConnection,
                 http.client.HTTPSConnection)
        http.client.HTTPConnection = _DeadlineHTTPConnection
        http.client.HTTPSConnection = _DeadlineHTTPSConnection
        cache_tok = _SEND_RESOLUTION_CACHE.set({})
        try:
            return urllib.request.urlopen(
                req, timeout=min(20, remaining))
        finally:
            _SEND_RESOLUTION_CACHE.reset(cache_tok)
            http.client.HTTPConnection = saved[0]
            http.client.HTTPSConnection = saved[1]


def _send_socket(stream):
    """Best effort: the socket beneath a response stream
    (the resp.fp.raw._sock chain and its wrappers), or
    None. Scripted transports have none, and none is
    needed there: their reads return promptly, so the
    clock checks in _read_body_bounded are the whole
    enforcement for them."""
    obj = stream
    for _ in range(6):
        if obj is None:
            return None
        if callable(getattr(obj, "settimeout", None)):
            return obj
        nxt = None
        for attr in ("fp", "raw", "_dsock", "_sock"):
            nxt = getattr(obj, attr, None)
            if nxt is not None:
                break
        if nxt is None or nxt is obj:
            return None
        obj = nxt
    return None


def _read_body_bounded(stream):
    """Read a provider response body. With no gated-send
    deadline armed this is exactly the long-standing
    stream.read(). With a deadline armed the body is read
    in slices against the clock — read1 (at most one
    underlying read per slice, so the clock is consulted
    between socket reads) with the socket's own timeout
    tightened to the time remaining: a body still
    dribbling when the deadline passes is CUT, and the
    _SendDeadlineExceeded propagates into the calling
    wrapper's exception arm, which classifies it
    "unknown". Round 25: for a REAL response the socket
    beneath is _DeadlineSocket, whose per-operation caps
    are the primary enforcement (including the reads
    http.client's chunk parser performs inside one read1
    call — delta-23 finding 2); this loop's clock checks
    remain the layer for scripted transports, which have
    no socket to shim. A stream with no read1 is handled
    by _read_body_no_read1."""
    if _SEND_DEADLINE_AT.get() is None:
        return stream.read()
    read1 = getattr(stream, "read1", None)
    if not callable(read1):
        return _read_body_no_read1(stream)
    sock = _send_socket(stream)
    chunks = []
    while True:
        remaining = _send_deadline_remaining()
        if remaining is None:
            chunks.append(stream.read())
            break
        if remaining <= 0:
            raise _SendDeadlineExceeded(
                "gated send deadline exceeded while "
                "reading the provider response")
        if sock is not None:
            try:
                sock.settimeout(remaining)
            except Exception:
                pass
        chunk = read1(65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _read_body_no_read1(stream):
    """_read_body_bounded for a stream with no usable read1.
    An HTTPError (the wrappers' error-body case) has no
    usable read1 and its read() ignores a size argument —
    but its .fp IS the real response: read THAT through
    the read1 path, so an error body is bounded exactly
    like a success body (that detour is what removes the
    one unchecked-duration network read delta-23 named:
    the HTTPError body was the only read1-less body backed
    by a socket). Any OTHER read1-less stream is an
    in-memory or scripted body — never a real socket (see
    _send_socket) — read in the one long-standing call, as
    rounds 18–24 certified, after the same spent-deadline
    refusal; there is no socket operation beneath it for
    the deadline to bound."""
    inner = getattr(stream, "fp", None)
    if inner is not None and inner is not stream \
            and callable(getattr(inner, "read1", None)):
        return _read_body_bounded(inner)
    if _send_deadline_remaining() <= 0:
        raise _SendDeadlineExceeded(
            "gated send deadline spent before the "
            "provider response could be read")
    return stream.read()


def _close_error_response(err):
    """Deterministic cleanup for an HTTPError response
    on an ARMED exchange (round 26): the wrappers read
    the error body and then close the response
    explicitly, so the underlying socket's close is
    driven by this call — through the connection's
    close mark and the reader refcount — and never by
    object-destruction timing. Unarmed sends keep the
    historical behaviour exactly (no added close)."""
    if _SEND_DEADLINE_AT.get() is None:
        return
    try:
        err.close()
    except Exception:
        pass


def send_resend(to, subject, text, html=None):
    """Returns an _SendOutcome (ok, detail, .status). Never
    raises. When html is given the mail goes out multipart: the
    plain-text body is preserved byte-for-byte and the branded
    HTML renders alongside it. When the caller set an
    idempotency key for this logical notification it rides as
    the Idempotency-Key header."""
    if not RESEND_API_KEY:
        return _SendOutcome(False, "RESEND_API_KEY not configured",
                            "failed")
    body = {"from": MAIL_FROM, "to": [to],
            "subject": subject, "text": text}
    if html:
        body["html"] = html
    payload = json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {RESEND_API_KEY}",
               "Content-Type": "application/json",
               "User-Agent": "vibefort-server/1.0"}
    idem = _MAIL_IDEM.get()
    if idem:
        headers["Idempotency-Key"] = idem
    req = urllib.request.Request(
        _RESEND_API_URL, data=payload, method="POST",
        headers=headers)
    try:
        with _send_urlopen(req) as resp:
            rbody = json.loads(
                _read_body_bounded(resp).decode(
                    "utf-8", "replace"))
            # Round 19 (Codex delta-18 (a)): a 2xx is "delivered"
            # ONLY when the body carries the message id — that id
            # is the provider's receipt. A 2xx without one (an
            # empty {} from a proxy, a truncated answer) proves
            # nothing about acceptance: it is "unknown", and the
            # callers' idempotency semantics govern the retry.
            # Round 21 (Codex delta-19 (a1)): the id must be a
            # non-empty STRING — a truthy non-string (an object
            # from a mangled proxy answer) is no more a provider
            # receipt than a missing id, and is likewise
            # "unknown".
            rid = rbody.get("id") if isinstance(rbody, dict) \
                else None
            if isinstance(rid, str) and rid:
                return _SendOutcome(True, rid, "delivered")
            return _SendOutcome(
                False, f"2xx response without a message id: "
                       f"{str(rbody)[:120]}", "unknown")
    except urllib.error.HTTPError as e:
        try:
            detail = _read_body_bounded(e).decode(
                "utf-8", "replace")[:300]
        except Exception as ex:
            # Round 25 (Codex delta-23 finding 3): a
            # deadline cut inside the error-body read is a
            # lost answer, not evidence about acceptance —
            # it classifies "unknown", never the definite
            # failure the status code alone would suggest.
            # Every other body-read failure keeps the
            # long-standing empty-detail behaviour.
            if _deadline_blown(ex):
                _close_error_response(e)
                return _SendOutcome(
                    False,
                    "gated send deadline exceeded while "
                    "reading the provider error response",
                    "unknown")
            detail = ""
        status = "failed" if 400 <= e.code < 500 else "unknown"
        _close_error_response(e)
        return _SendOutcome(False, f"HTTP {e.code}: {detail}", status)
    except Exception as e:
        return _SendOutcome(False, f"{type(e).__name__}: {e}",
                            "unknown")


def send_telegram(text):
    """Returns an _SendOutcome (ok, detail, .status). Never
    raises. Known-working pattern on this machine: urllib POST
    (curl hangs). Telegram answers definitively (ok:true /
    ok:false, including 4xx rejections): those are delivered /
    failed. A transport exception or a 5xx is "unknown" — the
    message may have been accepted before the answer was lost,
    and Telegram offers no idempotency key to retry against."""
    if not TELEGRAM_BOT_TOKEN:
        return _SendOutcome(False, "TELEGRAM_BOT_TOKEN not configured",
                            "failed")
    data = urllib.parse.urlencode(
        {"chat_id": TELEGRAM_CHAT_ID, "text": text}).encode()
    req = urllib.request.Request(
        f"{_TELEGRAM_API_BASE}/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data=data, method="POST")
    try:
        with _send_urlopen(req) as resp:
            body = json.loads(
                _read_body_bounded(resp).decode(
                    "utf-8", "replace"))
            # Round 19 (Codex delta-18 (a)): "delivered" requires
            # ok:true and "failed" requires ok:false (or a 4xx,
            # handled below). A 2xx whose body has no valid ok
            # field is neither — it is "unknown": the answer's
            # shape proves nothing about acceptance.
            ok_flag = body.get("ok") \
                if isinstance(body, dict) else None
            if ok_flag is True:
                return _SendOutcome(True, str(body.get("ok")),
                                    "delivered")
            if ok_flag is False:
                return _SendOutcome(
                    False,
                    str(body.get("description", body.get("ok"))),
                    "failed")
            return _SendOutcome(
                False, f"2xx response without an ok field: "
                       f"{str(body)[:120]}", "unknown")
    except urllib.error.HTTPError as e:
        detail = ""
        ok_flag = None
        try:
            raw = _read_body_bounded(e).decode(
                "utf-8", "replace")
            parsed = json.loads(raw) if raw else {}
            ok_flag = parsed.get("ok")
            detail = str(parsed.get("description", "")) \
                or f"HTTP {e.code}"
        except Exception as ex:
            # Round 25 (Codex delta-23 finding 3): as in
            # send_resend — a deadline cut inside the
            # error-body read classifies "unknown", never
            # the definite failure the status suggests.
            if _deadline_blown(ex):
                _close_error_response(e)
                return _SendOutcome(
                    False,
                    "gated send deadline exceeded while "
                    "reading the provider error response",
                    "unknown")
            detail = f"HTTP {e.code}"
        _close_error_response(e)
        if e.code >= 500:
            return _SendOutcome(False, detail, "unknown")
        if ok_flag is False or 400 <= e.code < 500:
            return _SendOutcome(False, detail, "failed")
        return _SendOutcome(False, detail, "unknown")
    except Exception as e:
        return _SendOutcome(False, f"{type(e).__name__}: {e}",
                            "unknown")


# ---------------------------------------------------------------------------
# Validation (mirrors the site's form rules)
# ---------------------------------------------------------------------------
def valid_url(value):
    try:
        u = urllib.parse.urlparse(value)
        return u.scheme in ("http", "https") and bool(u.hostname)
    except Exception:
        return False


def _s(value):
    """String field or '' — JSON type confusion ({"url": 123}) must be a
    validation failure, never a 500."""
    return value.strip() if isinstance(value, str) else ""


def validate_brief(data):
    errors = {}
    name = _s(data.get("name"))
    email = _s(data.get("email"))
    url = _s(data.get("url"))
    tier = _s(data.get("tier"))
    notes = _s(data.get("notes"))
    if not name or len(name) > 200:
        errors["name"] = "Enter your name."
    if not EMAIL_RX.match(email) or len(email) > 254:
        errors["email"] = "Enter a valid work email."
    if not valid_url(url) or len(url) > 2000:
        errors["url"] = "Enter a valid app URL starting with http:// or https://."
    if tier not in TIERS:
        errors["tier"] = "Select an audit tier."
    if len(notes) > 2000:
        errors["notes"] = "Notes are too long."
    if data.get("authorized") is not True:
        errors["authorized"] = ("Please confirm you own this application or "
                                "have written authorization to test it.")
    clean = {"name": name, "email": email, "url": url,
             "tier": tier, "notes": notes}
    return clean, errors


# ---------------------------------------------------------------------------
# Surface scanner — port of widecheck 1.1 (gentle, read-only) plus
# JS-bundle secret heuristics and public-database probes.
# ---------------------------------------------------------------------------
import base64
import hashlib as _hl
import hmac
import http.client
import secrets as _secrets
import socket
import ssl
import time
from html.parser import HTMLParser

SCAN_UA = "widecheck/1.1 (owner-operated surface audit; read-only)"
EVIL_ORIGIN = "https://evil.example"
MIN_INTERVAL = 0.35
REQ_TIMEOUT = 8
MAX_BODY = 1024 * 1024
_scan_last = {}
_scan_lock = threading.Lock()


def _throttle(host):
    with _scan_lock:
        now = time.monotonic()
        last = _scan_last.get(host)
        if last is not None:
            wait = MIN_INTERVAL - (now - last)
            if wait > 0:
                time.sleep(wait)
        _scan_last[host] = time.monotonic()


def _resolve_ips(host):
    """Resolve host ONCE and return (ips, error).

    When the SSRF guard is active, ANY non-public resolved address is an
    error — the same semantics the old one-shot guard had. Callers connect
    to one of the returned addresses (pinning), so the address that was
    validated is the address that is used: there is no second resolution
    for DNS-rebinding / TOCTOU to exploit."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as e:
        return None, f"host does not resolve: {e}"
    ips = []
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if ip not in ips:
            ips.append(ip)
    if not ips:
        return None, "host does not resolve: no addresses"
    if os.environ.get("VF_ALLOW_PRIVATE_TARGETS") != "1":
        for ip in ips:
            if ip.is_private or ip.is_loopback or ip.is_link_local or \
                    ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                return None, f"target resolves to non-public address {ip}"
    return ips, None


_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
MAX_REDIRECTS = 3


def _pinned_request(url, headers, method="GET"):
    """A single HTTP(S) request whose TCP connection goes to an IP address
    returned by _resolve_ips for the URL's host — never to a fresh DNS
    answer. For HTTPS the TLS handshake still uses the original hostname
    for SNI and certificate verification, so a pinned IP serving a wrong
    certificate fails closed. Raises ValueError on guard refusal."""
    u = urllib.parse.urlparse(url)
    scheme = u.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"refused scheme: {scheme or '(none)'}")
    host = u.hostname
    if not host:
        raise ValueError("URL has no host")
    try:
        port = u.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise ValueError("bad port in URL")
    ips, err = _resolve_ips(host)
    if err:
        raise ValueError(err)
    ip = ips[0]
    _throttle(u.netloc)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    host_header = f"[{host}]" if ":" in host else host
    if (scheme == "https" and port != 443) or \
            (scheme == "http" and port != 80):
        host_header += f":{port}"
    hdrs = dict(headers)
    hdrs["Host"] = host_header
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(REQ_TIMEOUT)
    raw.connect((str(ip), port))
    if scheme == "https":
        ctx = ssl.create_default_context()
        raw = ctx.wrap_socket(raw, server_hostname=host)
        conn = http.client.HTTPSConnection(host, port, timeout=REQ_TIMEOUT)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=REQ_TIMEOUT)
    conn.sock = raw
    try:
        conn.request(method, path, headers=hdrs)
        resp = conn.getresponse()
        try:
            body = resp.read(MAX_BODY)
        except http.client.IncompleteRead as e:
            body = e.partial or b""
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, body
    finally:
        conn.close()


def _fetch(url, headers=None, follow_redirects=True, method="GET"):
    """Scanner fetch with manual redirect handling: EVERY hop — including
    redirect targets — is scheme-checked, resolved, guard-validated and
    pinned by _pinned_request before any byte is requested. A redirect to
    a non-public target yields an error result and NO content from that
    target. Redirects are capped at MAX_REDIRECTS hops."""
    hdrs = {"User-Agent": SCAN_UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    out = {"url": url, "status": None, "headers": {}, "body": b"",
           "error": None}
    current = url
    hops = 0
    while True:
        try:
            status, rheaders, body = _pinned_request(
                current, hdrs, method=method)
        except ValueError as e:
            # Guard refusal (incl. a redirect hop into non-public space):
            # fail closed — report NOTHING from the chain, so no status,
            # header or byte of any hop can leak into findings.
            return {"url": url, "status": None, "headers": {}, "body": b"",
                    "error": f"SSRF guard: {e}"}
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e}"
            return out
        out["status"] = status
        out["headers"] = rheaders
        out["body"] = body
        if not follow_redirects or status not in _REDIRECT_STATUSES:
            return out
        loc = rheaders.get("location")
        if not loc:
            return out
        hops += 1
        if hops > MAX_REDIRECTS:
            return {"url": url, "status": None, "headers": {}, "body": b"",
                    "error": f"too many redirects (>{MAX_REDIRECTS})"}
        current = urllib.parse.urljoin(current, loc)


def _fetch_retry(url, **kw):
    r = _fetch(url, **kw)
    if r["error"]:
        time.sleep(0.8)
        r2 = _fetch(url, **kw)
        if not r2["error"]:
            return r2
    return r


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])


def _doh_query(name, rtype):
    url = ("https://cloudflare-dns.com/dns-query?name=" +
           urllib.parse.quote(name) + f"&type={rtype}")
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json",
                                               "User-Agent": SCAN_UA})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.load(resp)
    out = []
    for ans in data.get("Answer", []):
        d = (ans.get("data") or "").strip()
        d = d.replace('" "', "")
        if len(d) >= 2 and d.startswith('"') and d.endswith('"'):
            d = d[1:-1]
        out.append(d)
    return out


def _dns_txt(name):
    try:
        return _doh_query(name, "TXT"), "DoH"
    except Exception:
        return [], "DoH"


def _resolver_alive(reg_domain):
    try:
        return bool(_doh_query(reg_domain, "NS"))
    except Exception:
        return False


def _registrable(host):
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _tls_info(host):
    """Origin TLS version + cert expiry. Uses the HTTPS_PROXY CONNECT tunnel
    when one is configured (sandbox), direct otherwise (production)."""
    ctx = ssl.create_default_context()
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    sock = None
    if proxy:
        # Sandbox-only path: the proxy resolves the name itself, so pinning
        # is impossible here; still run the guard as defense in depth.
        _, gerr = _resolve_ips(host)
        if gerr:
            raise OSError(gerr)
        u = urllib.parse.urlparse(proxy)
        sock = socket.create_connection((u.hostname, u.port or 8080),
                                        timeout=REQ_TIMEOUT)
        auth = ""
        if u.username:
            creds = base64.b64encode(
                f"{urllib.parse.unquote(u.username)}:"
                f"{urllib.parse.unquote(u.password or '')}".encode()).decode()
            auth = f"Proxy-Authorization: Basic {creds}\r\n"
        sock.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n"
                     f"{auth}\r\n".encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        if b" 200" not in resp.split(b"\r\n", 1)[0]:
            sock.close()
            raise OSError(f"proxy CONNECT failed: {resp[:80]!r}")
    else:
        # Direct path (production): connect to a guard-validated IP,
        # pinned exactly like _pinned_request; SNI/cert still use `host`.
        ips, gerr = _resolve_ips(host)
        if gerr:
            raise OSError(gerr)
        sock = socket.create_connection((str(ips[0]), 443),
                                        timeout=REQ_TIMEOUT)
    with ctx.wrap_socket(sock, server_hostname=host) as tls:
        version = tls.version()
        cert = tls.getpeercert()
    na = cert.get("notAfter")
    exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z") \
        .replace(tzinfo=datetime.timezone.utc)
    days = (exp - datetime.datetime.now(datetime.timezone.utc)).days
    return {"version": version, "not_after": na, "days_left": days}


SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|secret|password|passwd|token|private[_-]?key)\s*[:=]"),
     "key=value-style secret assignment"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id pattern"),
    (re.compile(r"sk-[A-Za-z0-9\-_]{16,}"), "sk- API key pattern"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "PEM private key header"),
    (re.compile(r"eyJ[A-Za-z0-9\-_]{10,}\."), "JWT-looking token"),
]
JWT_RX = re.compile(r"eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{5,}")
SUPABASE_RX = re.compile(r"https://[a-z0-9]{10,}\.supabase\.co")
FIREBASE_RX = re.compile(r"https://[a-z0-9\-]+\.(?:firebaseio\.com|firebasedatabase\.app)")


def _jwt_role(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data.get("role")
    except Exception:
        return None


def _sig(resp):
    return (resp["status"], len(resp["body"]),
            _hl.sha1(resp["body"][:512]).hexdigest()[:12])


def _guard_public_target(host):
    """SSRF hygiene pre-check for /api/scan (fast path with a clear error
    message). The fetch layer independently re-validates and PINS every
    connection it makes — including every redirect hop — so this check is
    advisory; enforcement lives in _resolve_ips/_pinned_request.
    VF_ALLOW_PRIVATE_TARGETS=1 disables the check (local development only;
    filtered sandbox resolvers map every name into 198.18.0.0/15)."""
    if os.environ.get("VF_ALLOW_PRIVATE_TARGETS") == "1":
        return None
    _, err = _resolve_ips(host)
    return err


def run_surface_scan(base_url):
    """Returns (findings, meta) in the widecheck results shape:
    findings: [{target, check, severity(lowercase), title, evidence, status}],
    meta: dict with target/host/tls info/errors."""
    host = urllib.parse.urlparse(base_url).netloc
    origin = f"https://{host}"
    findings = []
    meta = {"target": base_url, "host": host, "errors": []}

    def add(check, severity, title, evidence):
        findings.append({"target": base_url, "check": check,
                         "severity": severity, "title": title,
                         "evidence": evidence, "status": "[raw]"})

    # ---- TLS -------------------------------------------------------------
    http_probe = _fetch(f"http://{host}/", follow_redirects=False)
    if http_probe["status"] in (301, 302, 307, 308):
        loc = http_probe["headers"].get("location", "")
        meta["http_redirect"] = f"{http_probe['status']} -> {loc}"
        if not loc.startswith("https://"):
            add("tls", "medium", "HTTP redirects somewhere other than HTTPS",
                f"GET http://{host}/ -> {http_probe['status']} Location: {loc}")
    elif http_probe["status"] == 200:
        add("tls", "medium", "Homepage served over plain HTTP (no redirect to HTTPS)",
            f"GET http://{host}/ -> 200")
    elif http_probe["error"]:
        meta["errors"].append(f"http probe: {http_probe['error']}")

    tls_ok = False
    try:
        ti = _tls_info(host)
        meta["tls_version"] = ti["version"]
        meta["cert_days_left"] = ti["days_left"]
        tls_ok = ti["days_left"] >= 0
        if ti["days_left"] < 0:
            add("tls", "critical", "TLS certificate is EXPIRED",
                f"notAfter={ti['not_after']} ({ti['days_left']} days)")
        elif ti["days_left"] < 14:
            add("tls", "high", "TLS certificate expires very soon",
                f"notAfter={ti['not_after']} ({ti['days_left']} days left)")
        elif ti["days_left"] < 30:
            add("tls", "medium", "TLS certificate expires within 30 days",
                f"notAfter={ti['not_after']} ({ti['days_left']} days left)")
        if ti["version"] in ("TLSv1", "TLSv1.1"):
            add("tls", "high", f"Obsolete TLS protocol negotiated: {ti['version']}",
                f"TLS handshake negotiated {ti['version']}")
        if tls_ok and ti["version"] not in ("TLSv1", "TLSv1.1"):
            add("tls", "info",
                f"TLS available ({ti['version']}, certificate valid {ti['days_left']} more days)",
                f"TLS handshake negotiated {ti['version']}; cert notAfter={ti['not_after']}")
    except Exception as e:
        meta["errors"].append(f"tls handshake: {type(e).__name__}: {e}")

    home = _fetch_retry(origin + "/")
    if home["error"]:
        meta["errors"].append(f"homepage: {home['error']}")
        return findings, meta
    hh = home["headers"]
    body_text = home["body"].decode("utf-8", "replace")
    meta["homepage_status"] = home["status"]

    nonsense = _fetch(origin + f"/widecheck-nonexistent-{_secrets.token_hex(4)}")
    fallback_sig = _sig(nonsense) if not nonsense["error"] else None
    meta["fallback_signature"] = str(fallback_sig)

    def is_fallback(resp):
        return fallback_sig is not None and _sig(resp) == fallback_sig

    # ---- headers -----------------------------------------------------------
    csp = hh.get("content-security-policy")
    if not csp:
        add("headers", "medium", "Missing Content-Security-Policy",
            "no content-security-policy header on /")
    else:
        meta["csp"] = csp[:200]
        if "unsafe-inline" in csp and "script-src" in csp:
            add("headers", "low", "CSP allows 'unsafe-inline' scripts (weakened XSS value)",
                f"CSP: {csp[:200]}")
    hsts = hh.get("strict-transport-security")
    if not hsts:
        add("headers", "medium", "Missing Strict-Transport-Security",
            "no strict-transport-security header on /")
    else:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 15552000:
            add("headers", "low", "HSTS max-age below 180 days",
                f"strict-transport-security: {hsts}")
    if not hh.get("x-frame-options") and not (csp and "frame-ancestors" in csp):
        add("headers", "medium",
            "No clickjacking protection (no X-Frame-Options, no CSP frame-ancestors)",
            "x-frame-options absent; CSP has no frame-ancestors")
    if (hh.get("x-content-type-options") or "").lower() != "nosniff":
        add("headers", "low", "Missing X-Content-Type-Options: nosniff",
            f"x-content-type-options: {hh.get('x-content-type-options')}")
    if not hh.get("referrer-policy"):
        add("headers", "low", "Missing Referrer-Policy", "no referrer-policy header on /")
    if not hh.get("permissions-policy"):
        add("headers", "low", "Missing Permissions-Policy",
            "no permissions-policy header on /")
    for leak_hdr in ("x-powered-by", "server", "x-aspnet-version", "x-generator"):
        if hh.get(leak_hdr):
            sev = "low" if re.search(r"\d+\.\d+", hh[leak_hdr]) else "info"
            add("headers", sev, f"Technology/version disclosure via {leak_hdr}",
                f"{leak_hdr}: {hh[leak_hdr]}")

    # ---- cookies (homepage) -------------------------------------------------
    seen_cookies = set()

    def check_cookies(resp, where):
        raw = resp["headers"].get("set-cookie")
        if not raw:
            return
        for cookie in re.split(r", (?=[^;,]+?=)", raw):
            name = cookie.split("=", 1)[0].strip()
            if name in seen_cookies:
                continue
            seen_cookies.add(name)
            low = cookie.lower()
            missing = [f for f, p in (("Secure", "secure"), ("HttpOnly", "httponly"),
                                      ("SameSite", "samesite")) if p not in low]
            if missing:
                sev = "medium" if ("HttpOnly" in missing or "Secure" in missing) else "low"
                add("cookies", sev,
                    f"Cookie '{name}' missing flags: {', '.join(missing)}",
                    f"Set-Cookie on {where}: {cookie[:160]}")
    check_cookies(home, "/")

    # ---- page parse / framework markers ------------------------------------
    parser = _PageParser()
    try:
        parser.feed(body_text)
    except Exception:
        pass
    next_markers = []
    if any(h.startswith("x-nextjs") for h in hh):
        next_markers.append("x-nextjs-* response header")
    if "_next/static" in body_text:
        next_markers.append("/_next/static asset reference")
    if "__NEXT_DATA__" in body_text:
        next_markers.append("__NEXT_DATA__ script block")
    meta["nextjs_markers"] = next_markers
    is_next = bool(next_markers)
    auth_links = [ln for ln in parser.links
                  if re.search(r"(?i)(login|log-in|signin|sign-in|signup|sign-up|register|auth)", ln)]

    # ---- CORS ----------------------------------------------------------------
    for path in ("/", "/api", "/api/auth"):
        r = _fetch(origin + path, headers={"Origin": EVIL_ORIGIN})
        acao = r["headers"].get("access-control-allow-origin")
        acac = (r["headers"].get("access-control-allow-credentials") or "").lower()
        if acao == EVIL_ORIGIN and acac == "true":
            add("cors", "critical",
                f"CORS reflects arbitrary Origin WITH credentials on {path}",
                f"Origin: {EVIL_ORIGIN} -> ACAO: {acao}, ACAC: {acac} (status {r['status']})")
        elif acao == EVIL_ORIGIN:
            add("cors", "high", f"CORS reflects arbitrary Origin on {path}",
                f"Origin: {EVIL_ORIGIN} -> ACAO: {acao} (status {r['status']})")
        elif acao == "*" and acac == "true":
            add("cors", "high", f"CORS wildcard origin with credentials allowed on {path}",
                f"ACAO: *, ACAC: true (status {r['status']})")
        elif acao == "*":
            sev = "medium" if path.startswith("/api") else "low"
            add("cors", sev, f"CORS wildcard origin (ACAO: *) on {path}",
                f"ACAO: * (status {r['status']})")

    # ---- exposed files --------------------------------------------------------
    sec_present = False
    for path in ("/.env", "/.git/config", "/.git/HEAD",
                 "/.well-known/security.txt", "/security.txt"):
        r = _fetch(origin + path)
        if r["status"] != 200 or not r["body"]:
            continue
        if is_fallback(r):
            add("exposed-files", "info",
                f"{path} returns the app fallback page (same as a nonexistent path) — "
                "not a real file exposure",
                f"GET {path} -> 200, {len(r['body'])} bytes, signature matches "
                f"nonexistent-path response {fallback_sig}")
            continue
        text = r["body"].decode("utf-8", "replace")
        if path == "/.env":
            hits = [label for rx, label in SECRET_PATTERNS if rx.search(text)]
            if hits:
                add("exposed-files", "critical",
                    "/.env is publicly accessible AND contains secret-looking patterns "
                    f"({'; '.join(hits)}) — secret values NOT copied",
                    f"GET /.env -> 200, {len(r['body'])} bytes, patterns: {'; '.join(hits)}")
            else:
                add("exposed-files", "high", "/.env is publicly accessible",
                    f"GET /.env -> 200, {len(r['body'])} bytes, no known secret pattern matched")
        elif path.startswith("/.git"):
            looks_git = ("[core]" in text or text.startswith("ref:") or
                         "repositoryformatversion" in text)
            if looks_git:
                add("exposed-files", "high",
                    f"{path} is publicly accessible (git metadata exposure)",
                    f"GET {path} -> 200, {len(r['body'])} bytes, git-format content markers present")
            else:
                add("exposed-files", "medium",
                    f"{path} returns 200 but content does not look like git metadata (verify manually)",
                    f"GET {path} -> 200, {len(r['body'])} bytes")
        else:
            sec_present = True
            add("exposed-files", "info", "security.txt present (good practice)",
                f"GET {path} -> 200, {len(r['body'])} bytes")
    if not sec_present:
        add("exposed-files", "low", "No security.txt (responsible-disclosure contact missing)",
            "/.well-known/security.txt and /security.txt did not return a distinct 200")

    rob = _fetch(origin + "/robots.txt")
    if rob["status"] == 200 and not is_fallback(rob):
        rtext = rob["body"].decode("utf-8", "replace")
        sens = [ln.strip() for ln in rtext.splitlines()
                if ln.strip().lower().startswith("disallow:")
                and re.search(r"(?i)(admin|api|config|backup|private|internal|debug|staging)", ln)]
        if sens:
            add("exposed-files", "low", "robots.txt discloses sensitive-looking paths",
                "; ".join(sens[:6]))

    js_assets = [s for s in parser.scripts if s.split("?")[0].endswith(".js")]
    if js_assets:
        main_js = urllib.parse.urljoin(origin + "/", js_assets[0])
        r = _fetch(main_js + ".map")
        if r["status"] == 200 and r["body"] and not is_fallback(r):
            add("exposed-files", "medium", "JavaScript source map publicly accessible",
                f"GET {main_js}.map -> 200, {len(r['body'])} bytes")

    # ---- CVE-2025-29927 probe (only when Next.js markers detected) ------------
    probe_note = "framework not detected (no Next.js markers)"
    if is_next:
        cand = None
        for ln in auth_links + parser.links:
            if re.search(r"(?i)(dashboard|account|profile|admin|app)", ln):
                cand = urllib.parse.urljoin(origin + "/", ln)
                break
        cand = cand or (origin + "/dashboard")
        baseline = _fetch(cand)
        probe = _fetch(cand, headers={
            "x-middleware-subrequest":
                "middleware:middleware:middleware:middleware:middleware"})
        b, p = baseline["status"], probe["status"]
        blen, plen = len(baseline["body"]), len(probe["body"])
        probe_note = (f"Next.js markers: {'; '.join(next_markers)}; probe target {cand}: "
                      f"baseline {b} ({blen}B) vs subrequest {p} ({plen}B)")
        if b in (301, 302, 303, 307, 308, 401, 403) and p == 200 and abs(plen - blen) > 200:
            add("framework-cve", "critical",
                "Possible CVE-2025-29927 middleware bypass: protected path answers 200 "
                "with x-middleware-subrequest while baseline is gated", probe_note)
        elif p != b or abs(plen - blen) > 200:
            add("framework-cve", "medium",
                "CVE-2025-29927 probe changed the response on a Next.js app "
                "(inconclusive — verify manually)", probe_note)
    meta["cve_2025_29927_probe"] = probe_note

    # ---- rate-limit signal (indicative only) -----------------------------------
    if auth_links:
        auth_url = urllib.parse.urljoin(origin + "/", auth_links[0])
        statuses, signal = [], False
        for _ in range(3):
            r = _fetch(auth_url)
            statuses.append(r["status"])
            if r["status"] == 429:
                signal = True
            if re.search(rb"(?i)(captcha|recaptcha|hcaptcha|turnstile)", r["body"] or b""):
                signal = True
            check_cookies(r, auth_url)
        if not signal:
            add("rate-limit", "low",
                "No rate-limit signal observed on auth page (INDICATIVE ONLY — "
                "3 gentle page loads, no credential attempts)",
                f"GET {auth_url} x3 -> statuses {statuses}, no 429/captcha seen")
    else:
        meta["rate_limit_probe"] = "no auth link discovered on homepage; skipped"

    # ---- cache deception ---------------------------------------------------------
    cd = _fetch(origin + "//widecheck-probe.css")
    cc = (cd["headers"].get("cache-control") or "").lower()
    ctype = cd["headers"].get("content-type", "")
    m = re.search(r"max-age=(\d+)", cc)
    if (cd["status"] == 200 and "text/html" in ctype and "public" in cc
            and m and int(m.group(1)) >= 300 and not is_fallback(cd)):
        add("cache-deception", "medium",
            "Cache-deception signal: static-looking suffix path returned HTML "
            "with genuinely cacheable headers",
            f"GET //widecheck-probe.css -> 200, content-type {ctype}, cache-control: {cc}")

    # ---- JS bundle secret heuristics + backend discovery -------------------------
    haystacks = [("homepage HTML", body_text)]
    for src in js_assets[:3]:
        js_url = urllib.parse.urljoin(origin + "/", src)
        r = _fetch(js_url)
        if r["status"] == 200 and r["body"]:
            haystacks.append((f"JS bundle {urllib.parse.urlparse(js_url).path}",
                              r["body"].decode("utf-8", "replace")))

    supabase_urls, firebase_urls, anon_keys = set(), set(), []
    service_role_found = []
    for where, text in haystacks:
        supabase_urls.update(SUPABASE_RX.findall(text))
        firebase_urls.update(FIREBASE_RX.findall(text))
        for token in JWT_RX.findall(text):
            role = _jwt_role(token)
            if role == "service_role":
                service_role_found.append(where)
            elif role == "anon":
                anon_keys.append(token)
        if where.startswith("JS bundle"):
            # Bundles only: high-confidence patterns only. The loose
            # key=value heuristic matches ordinary minified code and would
            # cry wolf; concrete key material is the real signal.
            for rx, label in SECRET_PATTERNS:
                if label not in ("AWS access key id pattern", "sk- API key pattern",
                                 "PEM private key header"):
                    continue
                if rx.search(text):
                    add("bundle-secrets", "high",
                        f"Secret-looking pattern in {where}: {label} (value NOT copied)",
                        f"pattern '{label}' matched in {where}")
                    break  # one bundle-secrets finding per bundle is enough
    for where in service_role_found:
        add("bundle-secrets", "critical",
            f"Supabase SERVICE-ROLE key embedded in {where} — bypasses all row-level security (value NOT copied)",
            f"a JWT with role=service_role was found in {where}")
    meta["supabase_urls"] = sorted(supabase_urls)
    meta["firebase_urls"] = sorted(firebase_urls)

    # ---- public database probes (read-only, no data rows fetched) -----------------
    for sb in sorted(supabase_urls):
        if anon_keys:
            key = anon_keys[0]
            hdrs = {"apikey": key, "Authorization": f"Bearer {key}"}
            root = _fetch(sb + "/rest/v1/", headers=hdrs)
            tables = []
            if root["status"] == 200 and root["body"]:
                try:
                    spec = json.loads(root["body"].decode("utf-8", "replace"))
                    tables = [p.lstrip("/") for p in spec.get("paths", {})
                              if p.startswith("/") and "{" not in p][:40]
                except Exception:
                    pass
            if tables:
                open_tables = []
                for t in tables[:8]:
                    probe = _fetch(
                        f"{sb}/rest/v1/{urllib.parse.quote(t)}?select=*&limit=0",
                        headers={**hdrs, "Prefer": "count=exact"})
                    cr = probe["headers"].get("content-range", "")
                    tm = re.search(r"/(\d+)$", cr)
                    if probe["status"] == 200 and tm:
                        open_tables.append(f"{t} ({tm.group(1)} rows)")
                if open_tables:
                    add("db-probe", "high",
                        "Supabase tables readable by the public anon key (row counts only — no rows fetched)",
                        f"anon key GET /rest/v1/<table>?limit=0 returned counts for: "
                        f"{'; '.join(open_tables)}")
                else:
                    add("db-probe", "info",
                        "Supabase detected; anon key cannot read table data (RLS appears enforced)",
                        f"project {sb}; {len(tables)} tables in schema listing, "
                        "count probes denied/empty")
            else:
                add("db-probe", "info",
                    "Supabase project detected in client code; REST root did not list tables to the anon key",
                    f"GET {sb}/rest/v1/ with anon key -> {root['status']}")
        else:
            add("db-probe", "info",
                "Supabase project URL found in client code, but no anon key was found to probe with",
                f"project {sb}; probe skipped (an anon key is normally public by design)")
    for fb in sorted(firebase_urls):
        probe = _fetch(fb + "/.json?shallow=true")
        if probe["status"] == 200 and probe["body"]:
            try:
                keys = list(json.loads(probe["body"].decode("utf-8", "replace")).keys())
            except Exception:
                keys = []
            if keys:
                add("db-probe", "critical",
                    "Firebase Realtime Database is WORLD-READABLE (top-level keys listed; no values fetched)",
                    f"GET {fb}/.json?shallow=true -> 200, top-level keys: "
                    f"{', '.join(keys[:10])}")
            else:
                add("db-probe", "info",
                    "Firebase Realtime Database answered the public probe with an empty payload",
                    f"GET {fb}/.json?shallow=true -> 200, empty")
        elif probe["status"] in (401, 403):
            add("db-probe", "info",
                "Firebase Realtime Database denies public reads (rules appear enforced)",
                f"GET {fb}/.json?shallow=true -> {probe['status']}")

    # ---- email DNS ------------------------------------------------------------------
    _dns_checks(host, findings)
    return findings, meta


def _dns_checks(host, findings):
    reg = _registrable(host)
    base = {"target": f"https://{host}", "check": "email-dns", "status": "[raw]"}
    if not _resolver_alive(reg):
        findings.append({**base, "severity": "info",
                         "title": "Email DNS checks inconclusive — resolver returned no data at all",
                         "evidence": "NS lookup for the registrable domain came back "
                                     "empty via DoH; absence of records NOT established"})
        return
    txts, via = _dns_txt(reg)
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spf:
        findings.append({**base, "severity": "medium",
                         "title": f"No SPF record on {reg}",
                         "evidence": f"TXT {reg} via {via} -> records: {txts[:3]} (no v=spf1)"})
    elif spf[0].strip().endswith("~all") or spf[0].strip().endswith("?all"):
        findings.append({**base, "severity": "low",
                         "title": f"SPF on {reg} uses softfail/neutral (~all/?all)",
                         "evidence": spf[0][:160]})
    dmarc_found = None
    for dmarc_name in (f"_dmarc.{host}", f"_dmarc.{reg}"):
        txts, via = _dns_txt(dmarc_name)
        dmarc = [t for t in txts if t.lower().startswith("v=dmarc1")]
        if dmarc:
            dmarc_found = (dmarc_name, dmarc[0])
            break
    if dmarc_found:
        pol = re.search(r"p=([a-z]+)", dmarc_found[1])
        if pol and pol.group(1) == "none":
            findings.append({**base, "severity": "low",
                             "title": f"DMARC policy is p=none (monitoring only) at {dmarc_found[0]}",
                             "evidence": dmarc_found[1][:160]})
    else:
        findings.append({**base, "severity": "medium",
                         "title": f"No DMARC record for {host} or {reg}",
                         "evidence": "TXT _dmarc.<host> and _dmarc.<registrable> -> no v=DMARC1"})
    findings.append({**base, "severity": "info",
                     "title": "DKIM: not checkable without selector",
                     "evidence": "DKIM requires knowing the mail provider's selector; skipped by design"})


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_DEDUCT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}


def score_findings(findings):
    score = 100
    for f in findings:
        score -= SEV_DEDUCT.get(f["severity"], 0)
    score = max(0, score)
    if score >= 97:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    elif score >= 50:
        grade = "E"
    else:
        grade = "F"
    return grade, score


def ui_findings(findings):
    """Map widecheck-shaped findings to the shape app.js renders."""
    out = []
    for f in sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
        sev = f["severity"]
        out.append({
            "severity": sev.upper(),
            "finding": f["title"],
            "evidence": f["evidence"],
            "status": "INFO" if sev == "info" else "OBSERVED",
        })
    return out


# ---------------------------------------------------------------------------
# Rate limiting (per-IP sliding window, DURABLE — counts live in the same
# SQLite register as the orders, on the persistent volume)
#
# The previous implementation kept counters in process memory keyed on
# X-Forwarded-For[0]. Both halves were wrong in production: the state died
# with the process (and would split across any replicas), and XFF[0] is
# client-controlled — GLM's pass showed requests carrying one fixed XFF
# being keyed by a different, rotating address on every hit, so the limit
# never accumulated. Counts are now stored in SQLite (survive restarts,
# shared by every thread/process using this register), and the bucket key
# comes from _client_ip(), which trusts only the hop Traefik appended.
# ---------------------------------------------------------------------------
RATE_LIMITS = {"brief": (5, 600), "scan": (3, 600)}  # (max hits, window sec)


def rate_ok(bucket, ip):
    limit, window = RATE_LIMITS[bucket]
    now = time.time()
    with _db_lock:
        conn = db_connect()
        try:
            conn.execute("DELETE FROM rate_hits WHERE ts < ?",
                         (now - 3600.0,))
            count = conn.execute(
                "SELECT COUNT(*) FROM rate_hits WHERE bucket=? AND ip=?"
                " AND ts > ?", (bucket, ip, now - window)).fetchone()[0]
            if count >= limit:
                conn.commit()
                return False
            conn.execute("INSERT INTO rate_hits(bucket, ip, ts)"
                         " VALUES(?,?,?)", (bucket, ip, now))
            conn.commit()
            return True
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # -- plumbing ------------------------------------------------------------
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def send_error(self, code, message=None, explain=None):
        # Minimal error body: no version strings, no stack traces, ever.
        try:
            self._send(code, f"{code}\n", "text/plain")
        except Exception:
            pass

    def _client_ip(self):
        """Bucket key for rate limiting and logs.

        The app is reachable ONLY through Coolify's Traefik (the container
        port is not published), and Traefik APPENDS the address it directly
        observed to X-Forwarded-For. The LAST parseable XFF entry is
        therefore the trustworthy hop; every earlier entry is
        client-supplied and spoofable, so it is never used as a key.
        Without XFF (direct/local access) the TCP peer is the key."""
        xff = self.headers.get("X-Forwarded-For") or ""
        for cand in reversed([p.strip() for p in xff.split(",")] ):
            if not cand:
                continue
            try:
                ipaddress.ip_address(cand)
                return cand
            except ValueError:
                continue
        return self.client_address[0]

    # Hard cap for up-front body reads: every body this API legitimately
    # accepts is <= 16 KB. Anything larger is refused AND the connection
    # is closed after the response, so unread bytes can never be mistaken
    # for the next request on a pooled keep-alive connection.
    _BODY_HARD_CAP = 262144

    def _take_body(self):
        """Read the request body exactly once, before routing.

        This is the desync fix: previously, early exits (unknown path 404,
        failed admin-token 404, rate-limit 429, oversize 400) responded
        WITHOUT reading the body, leaving its bytes in the socket; the
        next request Traefik pooled onto that connection was then parsed
        out of the leftover body and answered with a bare 400. Now the
        body is always consumed up front — or, when it cannot be framed
        safely (chunked encoding, bogus or absurd Content-Length), the
        connection is marked for closure after the response."""
        self._raw_body = b""
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            self.close_connection = True
            return
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            return
        try:
            length = int(raw_len)
        except ValueError:
            self.close_connection = True
            return
        if length <= 0:
            return
        if length > self._BODY_HARD_CAP:
            self.close_connection = True
            return
        try:
            self._raw_body = self.rfile.read(length) or b""
        except Exception:
            self._raw_body = b""
            self.close_connection = True
            return
        if len(self._raw_body) < length:
            self.close_connection = True

    def _send(self, code, body, content_type):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        for k, v in SECURITY_HEADERS:
            self.send_header(k, v)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

    def _read_json(self, max_bytes=65536):
        """Parse the body buffered by _take_body. Returns a dict or None:
        non-object JSON (list, number, string) is invalid here too —
        previously it reached .get() and produced a 500."""
        raw = getattr(self, "_raw_body", b"")
        if not raw or len(raw) > max_bytes:
            return None
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return None
        return data if isinstance(data, dict) else None

    def _admin_ok(self):
        if not ADMIN_TOKEN:
            return False
        import hmac
        given = self.headers.get("X-Admin-Token") or ""
        return hmac.compare_digest(given, ADMIN_TOKEN)

    # -- routing ---------------------------------------------------------------
    def do_GET(self):
        try:
            self._take_body()
            path = urllib.parse.urlparse(self.path).path
            if path.startswith("/api/"):
                self._api_admin_get(path)
            else:
                self._route()
        except BrokenPipeError:
            pass
        except Exception as e:
            log(f"unhandled GET error: {e!r}")
            try:
                self._send_json(500, {"ok": False, "error": "internal error"})
            except Exception:
                pass

    def do_HEAD(self):
        try:
            self._take_body()
            self._route()
        except Exception as e:
            log(f"unhandled HEAD error: {e!r}")

    def do_POST(self):
        try:
            self._take_body()
            path = urllib.parse.urlparse(self.path).path
            if path == "/api/brief":
                self._api_brief()
            elif path == "/api/scan":
                self._api_scan()
            elif path == "/api/stripe-webhook":
                self._api_stripe_webhook()
            elif path.startswith("/api/orders/"):
                self._api_admin_post(path)
            else:
                self._send_json(404, {"ok": False, "error": "not found"})
        except BrokenPipeError:
            pass
        except Exception as e:
            log(f"unhandled POST error: {e!r}")
            try:
                self._send_json(500, {"ok": False, "error": "internal error"})
            except Exception:
                pass

    def do_DELETE(self):
        try:
            self._take_body()
            path = urllib.parse.urlparse(self.path).path
            if path.startswith("/api/orders/") or \
                    path.startswith("/api/scans/"):
                self._api_admin_delete(path)
            else:
                self._send_json(404, {"ok": False, "error": "not found"})
        except BrokenPipeError:
            pass
        except Exception as e:
            log(f"unhandled DELETE error: {e!r}")
            try:
                self._send_json(500, {"ok": False, "error": "internal error"})
            except Exception:
                pass

    def _route(self):
        path = urllib.parse.urlparse(self.path).path
        entry = STATIC_FILES.get(path)
        if entry is None:
            self._send(404, "404 Not Found\n", "text/plain")
            return
        fname, ctype = entry
        fpath = os.path.join(BASE_DIR, fname)
        try:
            with open(fpath, "rb") as fh:
                data = fh.read()
        except OSError:
            self._send(404, "404 Not Found\n", "text/plain")
            return
        mtime = int(os.path.getmtime(fpath))
        etag = '"%x-%x"' % (mtime, len(data))
        self.send_response(200)
        for k, v in SECURITY_HEADERS:
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("ETag", etag)
        self.send_header("Last-Modified",
                         self.date_time_string(mtime))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    # -- admin (token-guarded register) ---------------------------------------
    def _order_dict(self, conn, row):
        d = dict(row)
        evs = conn.execute(
            "SELECT created_at,event,detail FROM events WHERE order_id=?"
            " ORDER BY id", (d["id"],)).fetchall()
        d["events"] = [dict(e) for e in evs]
        return d

    def _api_admin_get(self, path):
        if not self._admin_ok():
            self._send_json(404, {"ok": False, "error": "not found"})
            return
        conn = db_connect()
        conn.row_factory = sqlite3.Row
        try:
            if path == "/api/monitors":
                rows = conn.execute(
                    "SELECT * FROM monitors ORDER BY id DESC LIMIT 100"
                ).fetchall()
                self._send_json(200, {"ok": True,
                                      "monitors": [dict(r) for r in rows]})
            elif path == "/api/orders":
                rows = conn.execute(
                    "SELECT * FROM orders ORDER BY id DESC LIMIT 100"
                ).fetchall()
                self._send_json(200, {"ok": True,
                                      "orders": [dict(r) for r in rows]})
            elif path.startswith("/api/orders/"):
                try:
                    oid = int(path.rsplit("/", 1)[1])
                except ValueError:
                    self._send_json(400, {"ok": False, "error": "bad id"})
                    return
                row = conn.execute("SELECT * FROM orders WHERE id=?",
                                   (oid,)).fetchone()
                if row is None:
                    self._send_json(404, {"ok": False, "error": "no such order"})
                    return
                self._send_json(200, {"ok": True,
                                      "order": self._order_dict(conn, row)})
            elif path == "/api/scans":
                rows = conn.execute(
                    "SELECT id,created_at,url,email,grade,score,results_json"
                    " FROM scans ORDER BY id DESC LIMIT 20").fetchall()
                out = []
                for r in rows:
                    d = dict(r)
                    d["results"] = json.loads(d.pop("results_json"))
                    out.append(d)
                self._send_json(200, {"ok": True, "scans": out})
            else:
                self._send_json(404, {"ok": False, "error": "not found"})
        finally:
            conn.close()

    def _api_stripe_webhook(self):
        """Stripe webhook: a signature-verified checkout completion
        marks the matching NEW order PAID through the same transition
        path as the admin API. Matching is deliberately conservative:
        the tier comes from the paid amount (unique per tier) and the
        order is chosen by payer email among NEW orders of that tier;
        exactly one candidate auto-pays — anything else goes to HQ as
        an alert and a human matches it. Events dedupe by id.
        Fail-closed: while STRIPE_WEBHOOK_SECRET is unset the route
        answers 503 and payment matching stays manual."""
        if not STRIPE_WEBHOOK_SECRET:
            self._send_json(503, {"ok": False,
                                  "error": "webhook not configured"})
            return
        raw = getattr(self, "_raw_body", b"")
        sig = self.headers.get("Stripe-Signature") or ""
        if not _stripe_signature_ok(raw, sig, STRIPE_WEBHOOK_SECRET):
            self._send_json(400, {"ok": False, "error": "bad signature"})
            return
        try:
            event = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send_json(400, {"ok": False, "error": "bad payload"})
            return
        etype = event.get("type") or ""
        eid = event.get("id") or ""
        if etype not in ("checkout.session.completed",
                         "checkout.session.async_payment_succeeded"):
            self._send_json(200, {"ok": True, "ignored": etype})
            return
        session = (event.get("data") or {}).get("object") or {}
        if session.get("payment_status") != "paid":
            self._send_json(200, {"ok": True, "ignored": "not paid"})
            return
        try:
            self._stripe_process(event, session)
        except Exception as e:
            # The dedupe rollback already happened inside the webhook
            # lock (see _stripe_process); here we only answer 500 so
            # Stripe retries the event from scratch.
            log(f"stripe webhook processing failed for {eid}: {e!r}")
            self._send_json(500, {"ok": False, "error": "processing"})

    def _stripe_process(self, event, session):
        # One delivery at a time: candidate selection, event linking
        # and the transition must be atomic as a unit — two
        # concurrent deliveries could otherwise both claim the same
        # NEW order (Codex delta-5 finding 1). Payment volume is
        # small; correctness beats parallelism here.
        claim = _secrets.token_hex(8)
        with _webhook_lock:
            try:
                self._stripe_process_locked(event, session, claim)
            except Exception:
                # Roll the dedupe record back INSIDE the lock: a
                # concurrent retry of the same event must never be
                # mid-processing on a row that disappears under it
                # (Codex delta-6 finding 1). The delete is scoped to
                # THIS delivery's claim token and to unlinked rows:
                # another process that has since claimed the event
                # keeps its row, and a linked row is the recovery
                # consult's evidence and stays (delta-7 finding 1).
                try:
                    with _db_lock:
                        conn = db_connect()
                        conn.execute(
                            "DELETE FROM stripe_events WHERE "
                            "event_id=? AND order_id IS NULL AND "
                            "claim=?", (event.get("id") or "", claim))
                        conn.commit()
                        conn.close()
                except Exception:
                    pass
                raise

    def _stripe_process_locked(self, event, session, claim):
        etype = event.get("type") or ""
        eid = event.get("id") or ""
        amount = session.get("amount_total")
        currency = _s(session.get("currency") or "").lower()
        pi = session.get("payment_intent")
        email = _s((session.get("customer_details") or {}).get("email")
                   or session.get("customer_email") or "").lower()
        # Dedupe with completion awareness and cross-process claim
        # ownership (Codex delta-7 finding 1): an event row is
        # owned by the delivery that holds its claim token. A
        # concurrent delivery of the same event sees a live claim
        # and steps aside (500 — Stripe retries); a stale claim
        # (no activity for 120 s) may be stolen. The rollback in
        # _stripe_process deletes only our own claim, and a row
        # whose processing reached a terminal log (crash between
        # the dedupe commit and the transition — Codex/GLM
        # 2026-11-09) is reprocessed now, not acked as a duplicate.
        now = time.time()
        with _db_lock:
            conn = db_connect()
            try:
                existing = conn.execute(
                    "SELECT order_id, claim, claimed_at FROM "
                    "stripe_events WHERE event_id=?",
                    (eid,)).fetchone()
                if existing is None:
                    try:
                        conn.execute(
                            "INSERT INTO stripe_events(event_id, type,"
                            " order_id, received_at, payment_intent,"
                            " amount, claim, claimed_at) VALUES(?,?,"
                            "NULL,?,?,?,?,?)",
                            (eid, etype, utcnow(), pi,
                             session.get("amount_total"), claim, now))
                        conn.commit()
                        state = "fresh"
                    except sqlite3.IntegrityError:
                        conn.rollback()
                        existing = conn.execute(
                            "SELECT order_id, claim, claimed_at FROM "
                            "stripe_events WHERE event_id=?",
                            (eid,)).fetchone()
                if existing is not None:
                    if existing[0] is not None:
                        state = "done"
                    else:
                        done_log = conn.execute(
                            "SELECT 1 FROM events WHERE event IN "
                            "('STRIPE_PAID','STRIPE_UNMATCHED') AND "
                            "detail LIKE ?",
                            (f"%event={eid}%",)).fetchone()
                        if done_log:
                            state = "done"
                        elif existing[2] is not None and \
                                now - existing[2] < 120:
                            raise RuntimeError(
                                "event in flight in another process")
                        else:
                            # Stale or legacy (claim NULL) row: take
                            # ownership before processing it — with a
                            # CONDITIONAL update keyed on the stale
                            # state we just read, so two thieves
                            # cannot both win (Codex delta-8 #1).
                            # The payment_intent is refreshed here —
                            # the row may predate it, and the
                            # duplicate check below keys on it.
                            cur = conn.execute(
                                "UPDATE stripe_events SET claim=?, "
                                "claimed_at=?, payment_intent=COALESCE"
                                "(?, payment_intent) WHERE event_id=? "
                                "AND (claimed_at IS NULL OR "
                                "claimed_at<?)",
                                (claim, now, pi, eid, now - 120))
                            conn.commit()
                            if cur.rowcount == 0:
                                raise RuntimeError(
                                    "event claim raced; another "
                                    "process owns it now")
                            state = "incomplete"
            finally:
                conn.close()
        if not pi:
            # A paid session without a payment_intent can prove
            # nothing about which payment it was: by the standing
            # contract (delta-8 #5, delta-9 #3) it NEVER matches —
            # it surfaces as unmatched for a manual decision.
            _fire_unmatched_alert(
                eid,
                f"ShipAudit Lab: Stripe payment NOT matched — "
                f"the paid session carries no payment_intent "
                f"(amount={amount}, email={email}, event={eid}); "
                f"it needs a manual match or refund.",
                f"event={eid} no-payment-intent amount={amount} "
                f"email={email}")
            self._send_json(200, {"ok": True, "matched": False})
            return
        if state == "done":
            # Recovery consult: a linked order whose PAID side
            # effects or receipt never completed (crash in the
            # window after the status commit) is finished here,
            # on Stripe's retry, before the duplicate ack. The
            # link alone is NOT proof of a match — orders.paid_pi,
            # committed atomically with the winning transition,
            # is the authority (Codex delta-7 finding 2).
            linked_id = existing[0] if existing else None
            if linked_id:
                conn = db_connect()
                conn.row_factory = sqlite3.Row
                try:
                    orow = conn.execute(
                        "SELECT * FROM orders WHERE id=?",
                        (linked_id,)).fetchone()
                finally:
                    conn.close()
                if orow is not None:
                    order_d = dict(orow)
                    winner_pi = order_d.get("paid_pi")
                    proven = bool(winner_pi and pi
                                  and winner_pi == pi)
                    if order_d["status"] == "NEW":
                        # Crash between linking and the transition:
                        # the verified payment stands — finish the
                        # transition, recording this event as the
                        # winning payment in the same update. CHECK
                        # the result: another process may have
                        # claimed the order with a different payment
                        # in the meantime (Codex delta-8 #3) — then
                        # re-read and re-judge on the real winner.
                        if transition_order_status(
                                order_d, "PAID", paid_event_id=eid,
                                paid_pi=pi):
                            proven = True
                        else:
                            conn = db_connect()
                            conn.row_factory = sqlite3.Row
                            try:
                                orow2 = conn.execute(
                                    "SELECT * FROM orders WHERE "
                                    "id=?", (linked_id,)).fetchone()
                            finally:
                                conn.close()
                            if orow2 is not None:
                                order_d = dict(orow2)
                                winner_pi = order_d.get("paid_pi")
                                proven = bool(winner_pi and pi
                                              and winner_pi == pi)
                    if order_d["status"] == "NEW" and not proven:
                        # The transition was FENCED (the status
                        # never moved): this payment already won a
                        # different order (Codex delta-11 #1). This
                        # event belongs to THAT order — relink it
                        # there and ack as its duplicate; never
                        # fire this NEW order's side effects or
                        # receipt.
                        won_order = None
                        conn = db_connect()
                        try:
                            grow = conn.execute(
                                "SELECT id FROM orders WHERE "
                                "paid_pi=?", (pi,)).fetchone()
                            if grow:
                                won_order = grow[0]
                        finally:
                            conn.close()
                        if won_order is not None and \
                                won_order != linked_id:
                            with _db_lock:
                                conn = db_connect()
                                conn.execute(
                                    "UPDATE stripe_events SET "
                                    "order_id=? WHERE event_id=?",
                                    (won_order, eid))
                                conn.commit()
                                conn.close()
                            log_event(won_order, "STRIPE_DUP_EVENT",
                                      f"event={eid} pi={pi} already "
                                      "matched to this order")
                            self._send_json(200, {"ok": True,
                                                  "duplicate": True})
                            return
                        raise RuntimeError(
                            "transition fenced but no winning "
                            "order found for this payment")
                    if order_d["status"] != "NEW" and not proven:
                        # Provisional loser — or an order whose
                        # winner was never recorded (admin-paid /
                        # legacy). Contract (delta-8 #5): an
                        # unrecorded winner NEVER validates a
                        # payment as matched. Settle as unmatched:
                        # alert FIRST, unlink only once the alert
                        # is on record — a failed alert must leave
                        # the link as the sweep's retry evidence
                        # (Codex delta-9 #5).
                        _fire_unmatched_alert(
                            eid,
                            f"ShipAudit Lab: Stripe payment NOT "
                            f"matched — order #{linked_id} is not "
                            f"recorded as won by this payment "
                            f"(pi={pi}, amount={amount}, "
                            f"email={email}, event={eid}); it "
                            f"needs a manual match or refund.",
                            f"event={eid} lost-claim "
                            f"order={linked_id} pi={pi} "
                            f"amount={amount}")
                        with _db_lock:
                            conn = db_connect()
                            conn.execute(
                                "UPDATE stripe_events SET "
                                "order_id=NULL WHERE event_id=? "
                                "AND order_id=?",
                                (eid, linked_id))
                            conn.commit()
                            conn.close()
                        self._send_json(200, {"ok": True,
                                              "matched": False})
                        return
                    ensure_paid_side_effects(order_d)
                    if not _ensure_paid_receipt(order_d, amount):
                        raise RuntimeError("receipt resend failed")
            self._send_json(200, {"ok": True, "duplicate": True})
            return
        # One payment can arrive as two events (completed +
        # async_payment_succeeded, different ids, same payment_intent):
        # the second is a quiet duplicate, not an unmatched alert.
        if pi:
            conn = db_connect()
            try:
                prow = conn.execute(
                    "SELECT se.order_id, o.paid_pi FROM stripe_events "
                    "se JOIN orders o ON o.id = se.order_id WHERE "
                    "se.payment_intent=? AND se.order_id IS NOT NULL "
                    "AND se.event_id<>? AND o.paid_pi="
                    "se.payment_intent", (pi, eid)).fetchone()
            finally:
                conn.close()
            # The duplicate shortcut is taken only when the order's
            # recorded winner IS this payment (Codex delta-8 #2): a
            # merely provisional link proves nothing — such an event
            # falls through and is settled by the normal flow.
            prior = prow if (prow and prow[1] == pi) else None
            if prior:
                with _db_lock:
                    conn = db_connect()
                    cur = conn.execute(
                        "UPDATE stripe_events SET order_id=? "
                        "WHERE event_id=? AND claim=?",
                        (prior[0], eid, claim))
                    conn.commit()
                    conn.close()
                if cur.rowcount == 0:
                    raise RuntimeError(
                        "stripe event row vanished or claim lost "
                        "before linking")
                log_event(prior[0], "STRIPE_DUP_EVENT",
                          f"event={eid} pi={pi} already matched")
                self._send_json(200, {"ok": True, "duplicate": True})
                return
        plink = session.get("payment_link")
        tier = None
        if currency == "usd":
            if plink:
                ptier = PLINK_TO_TIER.get(plink)
                if ptier and TIER_PRICES[ptier] * 100 == amount:
                    tier = ptier
            else:
                tier = AMOUNT_TO_TIER.get(amount)
        order = None
        ambiguous = False
        lost_claim = False
        lost_claim_order = None
        if tier and email:
            conn = db_connect()
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    "SELECT * FROM orders WHERE status='NEW' AND tier=? "
                    "AND lower(email)=? ORDER BY id",
                    (tier, email)).fetchall()
            finally:
                conn.close()
            if len(rows) == 1:
                order = dict(rows[0])
            elif len(rows) > 1:
                ambiguous = True
        if order is not None:
            # Link the event to the order BEFORE the transition: if
            # the process dies inside the transition's side effects,
            # the retry's recovery consult finds this link and
            # finishes the job instead of reporting a duplicate.
            with _db_lock:
                conn = db_connect()
                try:
                    cur = conn.execute(
                        "UPDATE stripe_events SET order_id=? "
                        "WHERE event_id=? AND claim=?",
                        (order["id"], eid, claim))
                    conn.commit()
                finally:
                    conn.close()
            if cur.rowcount == 0:
                raise RuntimeError(
                    "stripe event row vanished or claim lost "
                    "before linking")
            won = transition_order_status(order, "PAID",
                                          paid_event_id=eid,
                                          paid_pi=pi)
            if not won:
                # The transition was claimed by someone else. If a
                # DIFFERENT payment claimed this order (the claim
                # window spans processes — the webhook lock is
                # per-process, Codex delta-6 finding 3), this
                # payment is not matched at all: unlink and let the
                # unmatched flow below alert HQ. The winner is read
                # from the order itself (paid_pi, committed with
                # the winning transition — delta-7 finding 2), never
                # from a possibly provisional event link. Same
                # payment (a duplicate event) or an admin's manual
                # PAID: the money is real, make the order whole.
                winner_pi = None
                conn = db_connect()
                try:
                    wrow = conn.execute(
                        "SELECT paid_pi FROM orders WHERE id=?",
                        (order["id"],)).fetchone()
                    if wrow:
                        winner_pi = wrow[0]
                finally:
                    conn.close()
                if pi and winner_pi != pi:
                    # Did THIS payment win a DIFFERENT order (the
                    # paid_pi fence rejected a second claim —
                    # delta-10 #1)? Then this is that payment's
                    # second event: link it to the order it
                    # actually paid for and ack as a duplicate.
                    won_order = None
                    conn = db_connect()
                    try:
                        grow = conn.execute(
                            "SELECT id FROM orders WHERE paid_pi=?",
                            (pi,)).fetchone()
                        if grow:
                            won_order = grow[0]
                    finally:
                        conn.close()
                    if won_order is not None:
                        with _db_lock:
                            conn = db_connect()
                            conn.execute(
                                "UPDATE stripe_events SET order_id=? "
                                "WHERE event_id=? AND claim=?",
                                (won_order, eid, claim))
                            conn.commit()
                            conn.close()
                        log_event(won_order, "STRIPE_DUP_EVENT",
                                  f"event={eid} pi={pi} already "
                                  "matched to this order")
                        self._send_json(200, {"ok": True,
                                              "duplicate": True})
                        return
                    # A genuinely different winner: this payment
                    # is unmatched. Do NOT unlink yet — the link
                    # is the sweep's evidence until the alert
                    # below is on record (delta-10 #2); the tail
                    # unlinks after a successful alert,
                    # conditionally on the judged link (the
                    # event may have been relinked to a winner
                    # in the meantime — delta-14 #2).
                    lost_claim = True
                    lost_claim_order = order["id"]
                    order = None
                else:
                    ensure_paid_side_effects(order)
            if order is not None:
                log_event(order["id"], "STRIPE_PAID",
                          f"event={eid} amount={amount} tier={tier} "
                          f"race={'won' if won else 'lost-recovered'}")
                # The payer hears from us immediately — a payment
                # with no acknowledgement reads as money into a
                # void. A failed receipt raises: Stripe retries,
                # and the recovery consult resends it (the order
                # itself is already PAID and fulfilled — only the
                # courtesy is outstanding).
                if not _ensure_paid_receipt(order, amount):
                    raise RuntimeError("receipt send failed")
                _gated_send(
                    order["id"], send_telegram,
                    f"ShipAudit Lab: Stripe payment matched — order "
                    f"#{order['id']} ({tier}, ${amount / 100:,.2f}) "
                    f"marked PAID automatically.")
                self._send_json(200, {"ok": True,
                                      "order_id": order["id"]})
                return
        # The alert fires through _fire_unmatched_alert: single-
        # fire across processes, alert BEFORE the durable log (a
        # crash between them must re-alert, not ack in silence —
        # Codex delta-3), and a failed alert raises so the rollback
        # clears our dedupe claim and Stripe retries the event.
        _fire_unmatched_alert(
            eid,
            f"ShipAudit Lab: Stripe payment NOT matched — "
            f"tier={tier} email={email} amount={amount} "
            f"currency={currency} ambiguous={ambiguous} "
            f"event={eid}. Match it manually in the admin register.",
            f"event={eid} tier={tier} email={email} "
            f"amount={amount} currency={currency} "
            f"ambiguous={ambiguous}")
        if lost_claim:
            # The alert is on record; only now may the provisional
            # link come off (delta-10 #2) — and only if it is
            # still the link this delivery judged, under its own
            # claim (delta-14 #2).
            with _db_lock:
                conn = db_connect()
                conn.execute(
                    "UPDATE stripe_events SET order_id=NULL "
                    "WHERE event_id=? AND order_id=? AND claim=?",
                    (eid, lost_claim_order, claim))
                conn.commit()
                conn.close()
        self._send_json(200, {"ok": True, "matched": False})

    def _api_admin_post(self, path):
        if not self._admin_ok():
            self._send_json(404, {"ok": False, "error": "not found"})
            return
        parts = path.split("/")  # /api/orders/<id>/status
        if len(parts) != 5 or parts[4] != "status":
            self._send_json(404, {"ok": False, "error": "not found"})
            return
        try:
            oid = int(parts[3])
        except ValueError:
            self._send_json(400, {"ok": False, "error": "bad id"})
            return
        data = self._read_json(4096) or {}
        new_status = _s(data.get("status"))
        if new_status not in ORDER_STATUSES:
            self._send_json(400, {"ok": False,
                                  "error": f"status must be one of "
                                           f"{ORDER_STATUSES}"})
            return
        conn = db_connect()
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute("SELECT * FROM orders WHERE id=?",
                               (oid,)).fetchone()
            if row is None:
                self._send_json(404, {"ok": False, "error": "no such order"})
                return
            cur_status = row["status"]
            if ORDER_STATUSES.index(new_status) <= \
                    ORDER_STATUSES.index(cur_status):
                self._send_json(400, {"ok": False,
                                      "error": f"cannot move {cur_status} "
                                               f"-> {new_status} (forward only)"})
                return
            row = dict(row)
        finally:
            conn.close()
        try:
            won = transition_order_status(row, new_status)
        except ValueError as e:
            self._send_json(400, {"ok": False, "error": str(e)})
            return
        except Exception as e:
            log(f"admin transition {oid} -> {new_status} blocked: "
                f"{e!r}")
            self._send_json(500, {"ok": False,
                                  "error": "paid side effects are "
                                           "incomplete; fix those "
                                           "before advancing"})
            return
        if not won:
            self._send_json(409, {"ok": False,
                                  "error": "concurrent transition; "
                                           "status already moved"})
            return
        self._send_json(200, {"ok": True, "id": oid, "status": new_status})

    def _api_admin_delete(self, path):
        """Operator register hygiene: remove one order (with its events)
        or one scan. Same token model as the rest of the admin API —
        without the token this endpoint does not exist (404)."""
        if not self._admin_ok():
            self._send_json(404, {"ok": False, "error": "not found"})
            return
        parts = path.split("/")  # /api/(orders|scans)/<id>
        if len(parts) != 4:
            self._send_json(404, {"ok": False, "error": "not found"})
            return
        kind = parts[2]
        try:
            oid = int(parts[3])
        except ValueError:
            self._send_json(400, {"ok": False, "error": "bad id"})
            return
        fr_left = None
        with _db_lock:
            conn = db_connect()
            try:
                if kind == "orders":
                    # Round 22 (Codex delta-20): the tombstone
                    # goes FIRST — before any row is removed,
                    # inside this same _db_lock transaction.
                    # Send seams serialize against this write
                    # through the same lock (see _send_gate):
                    # a seam check that runs before this
                    # transaction is legitimately in-flight (the
                    # accepted residual); a check that runs
                    # after it sees the tombstone and aborts
                    # with no send and no writes. Only an order
                    # that exists is tombstoned.
                    if conn.execute(
                            "SELECT 1 FROM orders WHERE id=?",
                            (oid,)).fetchone():
                        conn.execute(
                            "INSERT OR IGNORE INTO deleted_orders"
                            "(order_id, deleted_at) VALUES(?,?)",
                            (oid, time.time()))
                    # The order's monitor ids first (round 21):
                    # their monitor:<id> locks are deleted by id
                    # below, in this same transaction.
                    mon_ids = [r[0] for r in conn.execute(
                        "SELECT id FROM monitors WHERE order_id=?",
                        (oid,)).fetchall()]
                    cur = conn.execute("DELETE FROM orders WHERE id=?",
                                       (oid,))
                    if cur.rowcount:
                        conn.execute(
                            "DELETE FROM events WHERE order_id=?", (oid,))
                        conn.execute(
                            "DELETE FROM monitors WHERE order_id=?", (oid,))
                        # Round 19 (Codex delta-18 (c2)): the
                        # order's notification locks and its
                        # stripe_events link rows go in the SAME
                        # transaction — a deleted order must not
                        # leave a pending ping for the driver to
                        # chase, nor a payment link pointing at
                        # nothing.
                        conn.execute(
                            "DELETE FROM event_locks WHERE "
                            "event_id IN (?,?,?)",
                            (f"notify:{oid}", f"receipt:{oid}",
                             f"monitor-activate:{oid}"))
                        conn.execute(
                            "DELETE FROM stripe_events WHERE "
                            "order_id=?", (oid,))
                        # Round 21 (Codex delta-19 (c)): the
                        # two durable families rounds 19/20
                        # left behind go in the same transaction
                        # too — the order's email_delivery row
                        # (its receipt's post-window bookkeeping)
                        # and the monitor:<id> run locks of the
                        # order's monitors. No per-order
                        # notification bookkeeping survives the
                        # order.
                        conn.execute(
                            "DELETE FROM email_delivery WHERE "
                            "notif_key=?", (f"receipt:{oid}",))
                        for _mid in mon_ids:
                            conn.execute(
                                "DELETE FROM event_locks WHERE "
                                "event_id=?", (f"monitor:{_mid}",))
                        # Round 20: a fulfilment request still
                        # in its queued (unconsumed) state goes
                        # in the same transaction too — the
                        # engine worker must never be offered
                        # work for an order that no longer
                        # exists. A row in any other status was
                        # already picked up by the worker: it is
                        # left standing (cancelling it from here
                        # would fake a cancellation that did not
                        # happen) and the fact is logged after
                        # the commit, below.
                        conn.execute(
                            "DELETE FROM fulfilment_requests WHERE "
                            "order_id=? AND status='queued'", (oid,))
                        frow = conn.execute(
                            "SELECT status FROM fulfilment_requests "
                            "WHERE order_id=?", (oid,)).fetchone()
                        if frow is not None:
                            fr_left = frow[0]
                elif kind == "scans":
                    cur = conn.execute("DELETE FROM scans WHERE id=?",
                                       (oid,))
                else:
                    self._send_json(404, {"ok": False,
                                          "error": "not found"})
                    return
                conn.commit()
                deleted = cur.rowcount
            finally:
                conn.close()
        if not deleted:
            self._send_json(404, {"ok": False,
                                  "error": f"no such {kind[:-1]}"})
            return
        log(f"admin deleted {kind[:-1]} id={oid}")
        if fr_left is not None:
            log(f"admin deleted order id={oid}: fulfilment "
                f"request already {fr_left} — picked up by the "
                f"engine worker; left standing, not cancelled "
                f"from here")
        self._send_json(200, {"ok": True, "deleted": oid})

    # -- /api/brief ---------------------------------------------------------------
    def _api_brief(self):
        ip = self._client_ip()
        if not rate_ok("brief", ip):
            log(f"brief rate-limited ip={ip}")
            self._send_json(429, {"ok": False,
                                  "error": "too many requests — please try again later"})
            return
        data = self._read_json(16384)
        if data is None:
            self._send_json(400, {"ok": False, "error": "invalid JSON body"})
            return
        # Honeypot: humans never see or fill this field. Pretend success so
        # bots learn nothing; store nothing, send nothing.
        hp = data.get("company_website")
        if (isinstance(hp, str) and hp.strip()) or \
                (hp and not isinstance(hp, str)):
            log(f"HONEYPOT hit on /api/brief from ip={ip} — discarded")
            self._send_json(200, {"ok": True})
            return
        clean, errors = validate_brief(data)
        if errors:
            self._send_json(400, {"ok": False, "errors": errors})
            return
        amount = TIER_PRICES.get(clean["tier"], 0)
        amount_label = (f"${amount}/mo" if clean["tier"] == "Monitoring"
                        else f"${amount}")
        with _db_lock:
            conn = db_connect()
            cur = conn.execute(
                "INSERT INTO orders(created_at,name,email,url,tier,notes,"
                "amount,status) VALUES(?,?,?,?,?,?,?,'NEW')",
                (utcnow(), clean["name"], clean["email"], clean["url"],
                 clean["tier"], clean["notes"], amount))
            order_id = cur.lastrowid
            conn.commit()
            conn.close()
        log_event(order_id, "ORDER_CREATED",
                  f"tier={clean['tier']} amount=${amount} url={clean['url']}")

        alert_text = (
            f"New audit brief #{order_id}\n"
            f"Tier: {clean['tier']} ({amount_label})\n"
            f"Name: {clean['name']}\n"
            f"Work email: {clean['email']}\n"
            f"App URL: {clean['url']}\n"
            f"Notes: {clean['notes'] or '—'}\n"
            f"Status: NEW (awaiting payment link / payment)")
        # Round 23: the brief flow's sends go through the
        # atomic seam too — the order row is committed and
        # admin-visible from this moment, so a deletion
        # landing mid-flow must not be followed by new sends
        # (an abort reads as a definite failure below, and
        # the flags UPDATE no-ops on the removed row).
        _alert_res = _gated_send(
            order_id, send_resend,
            ALERT_EMAIL,
            f"New brief: {clean['tier']} ({amount_label}) — {clean['url']}",
            alert_text)
        alert_ok, alert_detail = _alert_res if _alert_res \
            is not None else (False, "send aborted: the order "
                                    "was deleted")
        log_event(order_id, "ALERT_EMAIL_SENT" if alert_ok
                  else "ALERT_EMAIL_FAILED", alert_detail)

        pay_url = STRIPE_LINKS.get(clean["tier"])
        if pay_url:
            pay_step_text = (
                f"1. Pay whenever you are ready, here: {pay_url}\n"
                "   We have not charged you anything — no charge "
                "happens until you complete that payment.\n")
        else:
            pay_step_text = "1. No payment is needed for a free scan.\n"
        confirm_text = (
            f"Hi {clean['name']},\n\n"
            f"Thanks — we've received your brief for a {clean['tier']} of "
            f"{clean['url']}.\n\n"
            "What happens next:\n"
            + pay_step_text +
            "2. We confirm the scope of your app within one business "
            "day. If the work cannot run as briefed, we write to you "
            "before starting — and refund any payment in full.\n"
            "3. Your audit starts as soon as the payment lands — the delivery "
            "clock in the pricing section of our site runs from payment, not from this brief.\n\n"
            "If anything in the brief needs correcting, just reply to this "
            "email.\n\n"
            "— ShipAudit Lab\n"
            "Security for what you shipped.")
        confirm_html = email_template.render_email(
            eyebrow="Brief received",
            headline="We've received your brief.",
            body_html=(
                email_template.para(f"Hi {clean['name']},")
                + email_template.para(
                    f"Thanks — we've received your brief for a "
                    f"{clean['tier']} of {clean['url']}.")
                + email_template.details_table([
                    ("Reference", f"Brief #{order_id}"),
                    ("Service", f"{clean['tier']} ({amount_label})"),
                    ("Target", clean["url"]),
                    ("Status", "Received — ready for payment"
                     if pay_url else "Received"),
                ])
                + email_template.list_heading("What happens next")
                + email_template.steps([
                    ("Pay whenever you're ready.",
                     "Use the secure Stripe link below. We have not "
                     "charged you anything — no charge happens until "
                     "you complete that payment."
                     if pay_url else
                     "No payment is needed for a free scan."),
                    ("Scope confirmed.",
                     "We confirm the scope of your app within one "
                     "business day. If the work cannot run as "
                     "briefed, we write to you before starting — and "
                     "refund any payment in full."),
                    ("Audit starts at payment.",
                     "Your audit starts as soon as the payment "
                     "lands — the delivery clock in the pricing "
                     "section of our site runs from payment, not "
                     "from this brief."),
                ])
                + (f'<p style="font-family:{email_template.SANS};'
                   f'font-size:15px;line-height:1.65;margin:0 0 16px 0;">'
                   f'<a href="{pay_url}" style="color:'
                   f'{email_template.RED};font-weight:bold;">'
                   f"Continue to secure payment</a></p>"
                   if pay_url else "")
                + email_template.para(
                    "If anything in the brief needs correcting, just "
                    "reply to this email.")),
            reason="You received this email because you submitted an "
                   "audit brief at shipauditlab.com.")
        _confirm_res = _gated_send(
            order_id, send_resend,
            clean["email"],
            f"We received your brief — {clean['tier']}", confirm_text,
            html=confirm_html)
        confirm_ok, confirm_detail = _confirm_res if _confirm_res \
            is not None else (False, "send aborted: the order "
                                    "was deleted")
        log_event(order_id, "CONFIRM_EMAIL_SENT" if confirm_ok
                  else "CONFIRM_EMAIL_FAILED", confirm_detail)

        # Telegram carries the delivery status of BOTH emails — failures are
        # loud here, never silent.
        tg_text = (
            f"🛡 ShipAudit Lab: new brief #{order_id}\n"
            f"Tier: {clean['tier']} ({amount_label})\nApp: {clean['url']}\n"
            f"From: {clean['name']} <{clean['email']}>\n"
            f"Alert email: {'SENT' if alert_ok else 'FAILED — ' + alert_detail}\n"
            f"Client confirmation: {'SENT' if confirm_ok else 'FAILED — ' + confirm_detail}")
        _tg_res = _gated_send(order_id, send_telegram, tg_text)
        tg_ok, tg_detail = _tg_res if _tg_res is not None else \
            (False, "send aborted: the order was deleted")
        log_event(order_id, "TELEGRAM_SENT" if tg_ok else "TELEGRAM_FAILED",
                  tg_detail)

        if not tg_ok:
            # Last-resort loud channel: email HQ about the Telegram failure
            # (and restate the email results, in case those failed too).
            _fb_res = _gated_send(
                order_id, send_resend,
                ALERT_EMAIL,
                f"DELIVERY PROBLEM: Telegram alert failed for brief #{order_id}",
                f"The Telegram alert for brief #{order_id} "
                f"({clean['tier']}, {clean['url']}) FAILED: {tg_detail}\n"
                f"Alert email: {'SENT' if alert_ok else 'FAILED — ' + alert_detail}\n"
                f"Client confirmation: {'SENT' if confirm_ok else 'FAILED — ' + confirm_detail}\n"
                f"The order IS stored in the register (id {order_id}).")
            fb_ok, fb_detail = _fb_res if _fb_res is not None else \
                (False, "send aborted: the order was deleted")
            log_event(order_id, "FALLBACK_EMAIL_SENT" if fb_ok
                      else "FALLBACK_EMAIL_FAILED", fb_detail)

        with _db_lock:
            conn = db_connect()
            conn.execute("UPDATE orders SET alert_sent=?, confirm_sent=?, "
                         "tg_sent=? WHERE id=?",
                         (1 if alert_ok else 0, 1 if confirm_ok else 0,
                          1 if tg_ok else 0, order_id))
            conn.commit()
            conn.close()
        self._send_json(200, {"ok": True, "id": order_id,
                              "confirmation": "sent" if confirm_ok else "failed"})

    # -- /api/scan ------------------------------------------------------------------
    def _api_scan(self):
        ip = self._client_ip()
        if not rate_ok("scan", ip):
            log(f"scan rate-limited ip={ip}")
            self._send_json(429, {"ok": False,
                                  "error": "too many scans — please try again later"})
            return
        data = self._read_json(8192)
        if data is None:
            self._send_json(400, {"ok": False, "error": "invalid JSON body"})
            return
        url = _s(data.get("url"))
        consent = data.get("consent")
        email = _s(data.get("email"))
        if consent is not True:
            self._send_json(400, {"ok": False,
                                  "error": "consent confirmation is required"})
            return
        if not valid_url(url):
            self._send_json(400, {"ok": False, "error": "invalid URL"})
            return
        if email and not EMAIL_RX.match(email):
            self._send_json(400, {"ok": False, "error": "invalid email"})
            return
        host = urllib.parse.urlparse(url).hostname or ""
        guard = _guard_public_target(host)
        if guard:
            self._send_json(400, {"ok": False,
                                  "error": f"target refused: {guard}"})
            return
        log(f"scan started url={url} ip={ip}")
        try:
            findings, meta = run_surface_scan("https://" + host)
        except Exception as e:
            log(f"scan CRASHED for {url}: {e!r}")
            self._send_json(502, {"ok": False,
                                  "error": "scan could not be completed"})
            return
        findings.sort(key=lambda x: SEV_ORDER.get(x["severity"], 9))
        grade, score = score_findings(findings)
        results = {
            "tool": "widecheck 1.1 (shipauditlab server port)",
            "generated_at": utcnow(),
            "note": "Automated surface evidence — findings receive an "
                    "independent verification pass in paid audits.",
            "targets": [meta],
            "findings": findings,
        }
        with _db_lock:
            conn = db_connect()
            conn.execute(
                "INSERT INTO scans(created_at,url,email,grade,score,"
                "results_json) VALUES(?,?,?,?,?,?)",
                (utcnow(), url, email, grade, score, json.dumps(results)))
            conn.commit()
            conn.close()
        log(f"scan finished url={url} grade={grade} score={score} "
            f"findings={len(findings)}")
        self._send_json(200, {"ok": True, "grade": grade, "score": score,
                              "findings": ui_findings(findings)})


# ---------------------------------------------------------------------------
# Deep Scan fulfilment hook — the seam where payment confirmation plugs in.
#
# STRIPE SEAM (activation day): Stripe is not live yet, so no webhook
# handler exists and nothing here calls Stripe. When it lands, the
# webhook receiver will move the paid order NEW -> PAID through the same
# admin transition used today (_api_admin_post), and this hook fires
# unchanged. Do not grow Stripe-specific code in this function.
#
# What the hook does (and all it does): record a durable fulfilment
# request carrying everything the delivery chain needs, log an order
# event, and ping HQ on Telegram. The actual delivery — engine job,
# client report, report email — lives on the engine side in
# engine/engine/fulfil.py (`python3 -m engine.fulfil from-json <file>`),
# which consumes exactly this payload shape:
#   {"order_id", "tier", "name", "email", "url", "amount", "queued_at"}
# A worker picks up rows with status='queued' and marks them done; the
# transport between this register and the engine host is wired on
# activation day (the payload is the contract, not the channel).
# ---------------------------------------------------------------------------
def transition_order_status(row, new_status, paid_event_id=None,
                            paid_pi=None):
    """The one status-transition path: DB update + event log + the
    PAID side effects (monitoring activation, Deep Scan fulfilment
    hook). Callers validate the move first (admin API: forward-only;
    webhook: a signature-verified payment for a NEW order). When the
    webhook drives a NEW -> PAID move it passes the winning event's
    identity, committed in the SAME guarded update as the status:
    orders.paid_event_id / paid_pi are the authoritative record of
    which payment won the order (Codex delta-7 finding 2)."""
    oid = row["id"]
    if row["status"] == "NEW" and new_status != "PAID" and \
            ORDER_STATUSES.index(new_status) > \
            ORDER_STATUSES.index("PAID"):
        # Skipping PAID skips its side effects, and every recovery
        # path (consult, sweep) keys on PAID — the order would
        # strand, paid and unfulfilled (Codex delta-5 finding 2).
        raise ValueError(
            f"cannot move NEW -> {new_status}: an order must pass "
            "through PAID, where its side effects live")
    if row["status"] == "PAID" and new_status != "PAID":
        # Leaving PAID is allowed only once the paid side effects
        # are complete; past PAID no recovery path can see the
        # order (Codex delta-5 finding 2). Round 18: "complete"
        # means every side effect is DONE or DURABLY QUEUED —
        # a courtesy notification that failed or whose outcome
        # is unknown has a durable pending record with a live
        # retry path (the boot sweep's status-independent
        # driver), so it no longer blocks the advance; the
        # guard still blocks when a side effect is neither
        # (reachable only via a crash mid-hook, which the
        # consult recovers as before).
        ensure_paid_side_effects(row)
    with _db_lock:
        conn = db_connect()
        try:
            if new_status == "PAID" and paid_pi is not None and \
                    conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE "
                        "type='index' AND "
                        "name='idx_orders_paid_pi'").fetchone() \
                    is None:
                # The fence could not be installed (legacy
                # duplicate paid_pi data): fail CLOSED — no
                # identity transition without the atomic fence
                # (Codex delta-11 #3). Reads and other flows are
                # unaffected; the webhook answers 500 and Stripe
                # retries while ops clean the register.
                raise RuntimeError(
                    "paid_pi unique index unavailable; refusing "
                    "an unfenced payment transition")
            won = None
            if new_status == "PAID" and paid_pi is not None:
                # The same payment must never win a second order
                # (Codex delta-10 #1): pre-check for a clean loss,
                # the partial unique index on paid_pi is the
                # atomic fence behind it.
                clash = conn.execute(
                    "SELECT 1 FROM orders WHERE paid_pi=? AND "
                    "id<>?", (paid_pi, oid)).fetchone()
                if clash:
                    won = False
            if won is None:
                if new_status == "PAID" and paid_event_id is not None:
                    cur = conn.execute(
                        "UPDATE orders SET status=?, paid_event_id=?, "
                        "paid_pi=? WHERE id=? AND status=?",
                        (new_status, paid_event_id, paid_pi, oid,
                         row["status"]))
                else:
                    cur = conn.execute(
                        "UPDATE orders SET status=? WHERE id=? AND "
                        "status=?", (new_status, oid, row["status"]))
                conn.commit()
                won = cur.rowcount > 0
        except sqlite3.IntegrityError:
            conn.rollback()
            won = False
        finally:
            conn.close()
    if not won:
        # A concurrent transition (webhook vs admin) got there first;
        # its side effects are the ones that count.
        log_event(oid, "STATUS_RACE",
                  f"{row['status']} -> {new_status} lost to a "
                  "concurrent transition; side effects skipped")
        return False
    log_event(oid, "STATUS_CHANGED", f"{row['status']} -> {new_status}")
    if new_status == "PAID":
        # The status is committed; the side effects are the second
        # half of the transition. Their completion is recorded so a
        # crash between the commit and the appliers is recoverable
        # (ensure_paid_side_effects / the boot sweep re-fire them —
        # both appliers are INSERT OR IGNORE, so re-firing is safe).
        try:
            if row["tier"] == "Monitoring":
                activate_monitor(row)
            if row["tier"] == "Deep Scan":
                on_deep_scan_paid(row)
        except Exception:
            log_event(oid, "SIDE_EFFECT_FAILED",
                      "PAID side effects raised; the recovery "
                      "consult will re-fire them")
            raise
        _record_effects_ok(oid, row["tier"])
    return True


def _paid_effects_done(order_id):
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT 1 FROM events WHERE order_id=? AND "
            "event='SIDE_EFFECTS_OK'", (order_id,)).fetchone() is not None
    finally:
        conn.close()


def _record_effects_ok(order_id, tier, note=""):
    """The SIDE_EFFECTS_OK marker is the recovery contract — the
    consult, the sweep and the leave-PAID guard all key on it.
    log_event deliberately swallows write errors (it serves
    courtesy logs too), so the marker is verified by reading it
    back; an unpersisted marker raises instead of letting the
    order advance on a completion that exists only in memory
    (Codex delta-6 finding 2).

    Round 22 (Codex delta-20): a caller that paused after its
    entry check and resumes after the order was deleted must
    not recreate the marker as an orphan event — the marker
    is skipped entirely for a dead order (no write, and no
    raise: nothing is owed for an order that no longer
    exists, and the read-back below would otherwise report
    the skip as a persistence failure).

    Round 23 (Codex delta-21 (b)): the skip no longer rides
    on this function's own pre-check — round 22 checked
    _order_dead here and THEN called log_event, and a
    deletion landing between the two recreated the orphan.
    The check now lives inside log_event's single critical
    section, atomic with the insert; this function writes
    unconditionally and lets the read-back arbitrate: a
    marker that is absent because the order is dead is a
    skip (return, no raise — the round-22 semantics), a
    marker absent for a LIVE order is the persistence
    failure the raise exists for."""
    log_event(order_id, "SIDE_EFFECTS_OK",
              f"tier={tier}" + (f" {note}" if note else ""))
    if _paid_effects_done(order_id):
        return
    if _order_dead(order_id):
        return
    raise RuntimeError(
        "SIDE_EFFECTS_OK marker did not persist; the paid "
        "side effects are not treated as complete")


def ensure_paid_side_effects(order):
    """Re-fire a PAID order's side effects when their completion was
    never recorded. No-op when SIDE_EFFECTS_OK is already logged."""
    if _paid_effects_done(order["id"]):
        return
    if not _order_alive(order["id"]):
        # Round 21 (Codex delta-19 (c)): recovery driven for
        # a deleted order fires nothing — the appliers below
        # are existence-guarded individually as well, and the
        # completion marker must not be written for an order
        # that no longer exists. Round 22: tombstone-aware —
        # a tombstoned order's row may still exist mid-delete,
        # and its work is already dead.
        return
    if order["tier"] == "Monitoring":
        activate_monitor(order)
    if order["tier"] == "Deep Scan":
        on_deep_scan_paid(order)
    _record_effects_ok(order["id"], order["tier"], "(recovered)")


def _monitor_alive(monitor_id):
    """Existence re-check for a monitor row (round 21, Codex
    delta-19 (c)): a run holding a snapshot re-reads this at
    its send seams, so a monitor deleted mid-run (its order
    deleted) gets no send attempted and no state written."""
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT 1 FROM monitors WHERE id=?",
            (monitor_id,)).fetchone() is not None
    finally:
        conn.close()


def _gc_notification_orphans():
    """Collect the durable notification bookkeeping whose
    owner is gone (round 21, Codex delta-19 (c)) — the two
    families the round-19 notify-lock GC did not cover:
    monitor:<id> run locks whose monitor row no longer
    exists, and email_delivery rows whose receipt:<order_id>
    order no longer exists. The admin delete path removes
    both families itself since round 21; this pass is for
    rows orphaned before that, and for anything a deletion
    race could leave. A lock or row whose owner EXISTS is
    never touched — a live monitor's run lock is its mutex.
    Every item is isolated, like the driver's items below.

    Round 22: "owner gone" is tombstone-aware — an owner
    under a deleted-order tombstone counts as gone even
    while its row still exists mid-delete."""
    conn = db_connect()
    try:
        mlocks = [r[0] for r in conn.execute(
            "SELECT event_id FROM event_locks WHERE "
            "event_id LIKE 'monitor:%'").fetchall()]
        erows = [r[0] for r in conn.execute(
            "SELECT notif_key FROM email_delivery WHERE "
            "notif_key LIKE 'receipt:%'").fetchall()]
    finally:
        conn.close()
    for eid in mlocks:
        try:
            mid = int(eid.split(":", 1)[1])
            if _monitor_alive(mid):
                # Round 22: a live monitor whose ORDER is
                # tombstoned is dead work too — its lock is
                # collected even while both rows still exist
                # (the delete transaction is mid-flight).
                _mrow = None
                conn = db_connect()
                try:
                    _mrow = conn.execute(
                        "SELECT order_id FROM monitors WHERE "
                        "id=?", (mid,)).fetchone()
                finally:
                    conn.close()
                if _mrow is not None and _order_alive(_mrow[0]):
                    continue
            with _db_lock:
                conn = db_connect()
                conn.execute(
                    "DELETE FROM event_locks WHERE event_id=?",
                    (eid,))
                conn.commit()
                conn.close()
            log(f"pending-notification driver: collected "
                f"orphan lock {eid} (its monitor no longer "
                f"exists)")
        except Exception as e:
            log(f"pending-notification driver: GC of lock "
                f"{eid} deferred: {e!r}")
    for nkey in erows:
        try:
            oid = int(nkey.split(":", 1)[1])
            # Round 22: tombstone-aware — a tombstoned order's
            # receipt row is collected even while the order
            # row still exists mid-delete.
            if _order_alive(oid):
                continue
            with _db_lock:
                conn = db_connect()
                conn.execute(
                    "DELETE FROM email_delivery WHERE "
                    "notif_key=?", (nkey,))
                conn.commit()
                conn.close()
            log(f"pending-notification driver: collected "
                f"orphan email_delivery row {nkey} (its order "
                f"no longer exists)")
        except Exception as e:
            log(f"pending-notification driver: GC of email "
                f"row {nkey} deferred: {e!r}")


def _drive_pending_notifications():
    """Drive the durable pending notification states (round 18),
    independently of the order's status: under the decoupled
    guard semantics an order leaves PAID with its HQ ping
    durably QUEUED, and this driver — not the order's status —
    is what resolves the queue. Every state on a notify:<id>
    row is dispatched by _fire_deep_scan_notification itself
    (definite-pending rows are taken over and re-fired; stale
    intents and unknown-outcome rows are reconciled, never
    re-sent). Receipt pending states need no row here: they are
    the absence of PAID_EMAIL_SENT under a live stripe_events
    link and are driven by the sweep's event loop below.

    Round 19 (Codex delta-18 (c2)/(c3)): every item — the order
    lookup included — is isolated: an exception on one item is
    logged and the sweep CONTINUES with the remaining items
    (before, a database failure on one lookup escaped the loop
    and silently skipped every later item). And a lock whose
    order no longer exists is an orphan — the admin delete path
    removes such rows itself since round 19, but rows orphaned
    before that are collected HERE instead of being skipped on
    every pass forever."""
    try:
        _gc_notification_orphans()
    except Exception as e:
        log(f"pending-notification driver: orphan GC failed: "
            f"{e!r}")
    conn = db_connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT event_id FROM event_locks WHERE "
            "event_id LIKE 'notify:%' AND purpose IN "
            "('deepscan-notify-pending', 'deepscan-notify-intent', "
            "'deepscan-notify-pending-unknown', "
            "'deepscan-notified-unconfirmed')").fetchall()
    finally:
        conn.close()
    for r in rows:
        try:
            oid = int(r["event_id"].split(":", 1)[1])
            conn = db_connect()
            conn.row_factory = sqlite3.Row
            try:
                orow = conn.execute(
                    "SELECT * FROM orders WHERE id=?",
                    (oid,)).fetchone()
            finally:
                conn.close()
            if orow is None or _order_dead(oid):
                # Round 22: a tombstoned order's pending work
                # is dead even while its row still exists
                # mid-delete — drop it; never fire it.
                with _db_lock:
                    conn = db_connect()
                    conn.execute(
                        "DELETE FROM event_locks WHERE "
                        "event_id=?", (r["event_id"],))
                    conn.commit()
                    conn.close()
                log(f"pending-notification driver: collected "
                    f"orphan lock {r['event_id']} (its order no "
                    f"longer exists)")
                continue
            _fire_deep_scan_notification(dict(orow))
        except Exception as e:
            log(f"pending-notification driver: item "
                f"{r['event_id']} deferred: {e!r}")


def sweep_paid_side_effects():
    """Boot sweep: every PAID order gets its side-effect completion
    verified (and re-fired if missing), and
    every matched Stripe event gets its receipt email verified (and
    resent if it never landed). Idempotent; runs once at startup
    and, since round 20, again on every production scheduler
    tick (_monitor_tick) — receipts are a pending paid
    side-effect state like the notifications round 19 wired
    into the tick, and driving them only at boot left an
    unknown-outcome receipt dormant once the webhook's own
    retries were exhausted."""
    conn = db_connect()
    conn.row_factory = sqlite3.Row
    try:
        linked_new = conn.execute(
            "SELECT o.*, se.event_id AS ev_id, "
            "se.payment_intent AS ev_pi FROM stripe_events se "
            "JOIN orders o ON o.id = se.order_id "
            "WHERE o.status='NEW'").fetchall()
    finally:
        conn.close()
    for row in linked_new:
        # A verified payment linked to an order that never got its
        # transition (crash in the link window): the money stands,
        # finish the transition at boot — recording the linking
        # event as the winning payment in the same update. A link
        # with NO payment_intent can never become a recorded
        # winner (delta-9 #3): settle it as unmatched instead.
        if not row["ev_pi"]:
            try:
                _fire_unmatched_alert(
                    row["ev_id"],
                    f"ShipAudit Lab: Stripe payment NOT matched — "
                    f"event {row['ev_id']} linked to order "
                    f"#{row['id']} carries no payment_intent; it "
                    f"needs a manual match or refund.",
                    f"event={row['ev_id']} lost-claim "
                    f"order={row['id']} pi=None "
                    f"amount={row['amount']} (boot sweep)")
                with _db_lock:
                    conn = db_connect()
                    conn.execute(
                        "UPDATE stripe_events SET order_id=NULL "
                        "WHERE event_id=? AND order_id=?",
                        (row["ev_id"], row["id"]))
                    conn.commit()
                    conn.close()
            except Exception as e:
                log(f"boot sweep: settle for pi-less event "
                    f"{row['ev_id']} deferred: {e!r}")
            continue
        try:
            moved = transition_order_status(
                dict(row), "PAID", paid_event_id=row["ev_id"],
                paid_pi=row["ev_pi"])
            if not moved:
                # Fenced: this payment already won another order
                # (Codex delta-11 #2). The event belongs to the
                # winning order — relink it there as a duplicate.
                conn = db_connect()
                try:
                    grow = conn.execute(
                        "SELECT id FROM orders WHERE paid_pi=?",
                        (row["ev_pi"],)).fetchone()
                finally:
                    conn.close()
                if grow and grow[0] != row["id"]:
                    with _db_lock:
                        conn = db_connect()
                        conn.execute(
                            "UPDATE stripe_events SET order_id=? "
                            "WHERE event_id=?",
                            (grow[0], row["ev_id"]))
                        conn.commit()
                        conn.close()
                    log_event(grow[0], "STRIPE_DUP_EVENT",
                              f"event={row['ev_id']} "
                              f"pi={row['ev_pi']} already matched "
                              "to this order")
                else:
                    log(f"boot sweep: transition for linked order "
                        f"{row['id']} lost without a recorded "
                        f"winner; left for the next pass")
        except Exception as e:
            log(f"boot sweep: transition for linked order "
                f"{row['id']} failed: {e!r}")
    # Snapshot AFTER the transitions: an order that landed PAID a
    # moment ago must be effect-checked in this same run, not wait
    # for the next restart (Codex delta-5 finding 3).
    conn = db_connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM orders WHERE status='PAID'").fetchall()
        evs = conn.execute(
            "SELECT event_id, order_id, amount, payment_intent "
            "FROM stripe_events WHERE order_id IS NOT NULL").fetchall()
    finally:
        conn.close()
    for row in rows:
        try:
            ensure_paid_side_effects(dict(row))
        except Exception as e:
            log(f"boot sweep: side effects for order {row['id']} "
                f"failed: {e!r}")
    for ev in evs:
        try:
            conn = db_connect()
            conn.row_factory = sqlite3.Row
            orow = conn.execute("SELECT * FROM orders WHERE id=?",
                                (ev["order_id"],)).fetchone()
            conn.close()
            if orow is None:
                continue
            order_d = dict(orow)
            if order_d["status"] == "NEW":
                # A link to a still-NEW order is in-flight or
                # recoverable state, owned by the delivery, its
                # retry consult and the linked-NEW loop above —
                # never settled here. Settling it would race a
                # live payment in another process, and would
                # terminally ack a payment whose transition is
                # only fenced off (Codex delta-12 #1/#2).
                continue
            winner_pi = order_d.get("paid_pi")
            proven = bool(winner_pi and ev["payment_intent"]
                          and ev["payment_intent"] == winner_pi)
            if not proven:
                # A provisional link from a payment that lost the
                # claim — or an order with no recorded winner
                # (Codex delta-7 finding 2, delta-8 #5): not a
                # match. Alert FIRST through the single-fire
                # helper and unlink only once the alert is on
                # record; if the alert cannot fire, the link stays
                # for the next sweep (delta-8 #4). The link is
                # re-read before judging and the unlink is
                # conditional on it: the event may have been
                # relinked to its true winner since the snapshot
                # (Codex delta-13 #1).
                conn = db_connect()
                cur_link = conn.execute(
                    "SELECT order_id FROM stripe_events WHERE "
                    "event_id=?", (ev["event_id"],)).fetchone()
                conn.close()
                if cur_link is None or \
                        cur_link[0] != ev["order_id"]:
                    continue
                try:
                    _fire_unmatched_alert(
                        ev["event_id"],
                        f"ShipAudit Lab: Stripe payment NOT "
                        f"matched — order #{ev['order_id']} is not "
                        f"recorded as won by this payment; event "
                        f"{ev['event_id']} "
                        f"(pi={ev['payment_intent']}, "
                        f"amount={ev['amount']}) needs a manual "
                        f"match or refund.",
                        f"event={ev['event_id']} lost-claim "
                        f"order={ev['order_id']} "
                        f"pi={ev['payment_intent']} "
                        f"amount={ev['amount']} (boot sweep)")
                except RuntimeError as e:
                    log(f"boot sweep: unmatched alert for event "
                        f"{ev['event_id']} deferred: {e!r}")
                    continue
                with _db_lock:
                    conn = db_connect()
                    conn.execute(
                        "UPDATE stripe_events SET order_id=NULL "
                        "WHERE event_id=? AND order_id=?",
                        (ev["event_id"], ev["order_id"]))
                    conn.commit()
                    conn.close()
                continue
            # Never tell a payer the audit is queued while the
            # queueing itself failed (Codex delta-5 finding 3):
            # the receipt goes only once the effects are on record.
            if not _paid_effects_done(ev["order_id"]):
                continue
            _ensure_paid_receipt(order_d, ev["amount"])
        except Exception as e:
            log(f"boot sweep: receipt for event {ev['event_id']} "
                f"failed: {e!r}")
    # Round 18: orders that already left PAID can still hold a
    # durably queued notification (the decoupled guard let them
    # advance); the driver resolves those queues here, where
    # the order's status no longer matters.
    try:
        _drive_pending_notifications()
    except Exception as e:
        log(f"boot sweep: pending-notification driver failed: "
            f"{e!r}")


def _send_paid_receipt(order, amount_cents):
    """The payment-received email; returns the tri-state send
    status (round 18). Logged either way; a non-delivered
    outcome is recoverable — while no PAID_EMAIL_SENT is on
    record, the boot sweep and the webhook recovery consult
    resend it. Every attempt carries the same Resend
    idempotency key (receipt:<order_id>, set as the context
    below), so an attempt the provider accepted before its
    answer was lost is deduped by the retry, never delivered
    twice."""
    tier = order["tier"]
    if amount_cents:
        amt_label = f"${amount_cents / 100:,.2f}"
    else:
        amt_label = f"${order['amount']:,.2f}"
    rcpt_text = (
        f"Hi {order['name']},\n\n"
        f"We've received your payment of {amt_label} for a "
        f"{tier} of {order['url']}.\n\n"
        "Your audit is now in the queue, and the delivery "
        "times in the pricing section of our site run from "
        "today. We confirm the scope of your app within one "
        "business day; if the work cannot run as briefed, we "
        "will write to you before starting and refund your "
        "payment in full.\n\n"
        "Questions — just reply to this email.\n\n"
        "— ShipAudit Lab\n"
        "Security for what you shipped.")
    rcpt_html = email_template.render_email(
        eyebrow="Payment received",
        headline="Payment received.",
        body_html=(
            email_template.para(f"Hi {order['name']},")
            + email_template.para(
                f"We've received your payment of {amt_label} "
                f"for a {tier} of {order['url']}.")
            + email_template.details_table([
                ("Reference", f"Order #{order['id']}"),
                ("Service", tier),
                ("Amount paid", amt_label),
                ("Target", order["url"]),
                ("Status", "Paid — in the queue"),
            ])
            + email_template.para(
                "Your audit is now in the queue, and the "
                "delivery times in the pricing section of our "
                "site run from today. We confirm the scope of "
                "your app within one business day; if the work "
                "cannot run as briefed, we will write to you "
                "before starting and refund your payment in "
                "full.")
            + email_template.para(
                "Questions — just reply to this email.")),
        reason="You received this email because a payment "
               "was completed for your ShipAudit Lab order.")
    _idem_tok = _MAIL_IDEM.set(f"receipt:{order['id']}")
    try:
        res = _gated_send(
            order["id"], send_resend,
            order["email"], f"Payment received — {tier}",
            rcpt_text, html=rcpt_html)
        if res is None:
            # Round 23: the FINAL receipt seam, atomic inside
            # _gated_send — every earlier check a caller made
            # may be stale by the time composition finishes,
            # so the gate and this HTTP call are one critical
            # section. An abort means the tombstone landed
            # first: no HTTP call started; the caller reads
            # the definite outcome and retries nothing (its
            # own entry check stops it first).
            return "failed"
    finally:
        _MAIL_IDEM.reset(_idem_tok)
    status = _send_status(res)
    _log_event_alive(
        order["id"],
        "PAID_EMAIL_SENT" if status == "delivered"
        else "PAID_EMAIL_FAILED",
        res[1] if status != "unknown"
        else f"transport outcome unknown: {res[1]}")
    return status


def _lock_key_alive(key):
    """Round 23 (Codex delta-21 (b)): whether an event-lock
    key's owner is alive — consulted by the claim and the
    takeover INSIDE their own _db_lock acquisition, so the
    check and the INSERT/UPDATE are atomic with respect to
    the delete transaction (which holds the same lock from
    tombstone to commit). Before, a worker could pass its
    entry check, watch the deletion complete, and still
    INSERT a fresh order-keyed lock row — state created
    after the tombstone, left standing by a crash until the
    GC. The order-keyed namespaces carry an order id
    (receipt:, notify:, monitor-activate:); monitor: carries
    a monitor id, alive when the monitor row exists and its
    order is not dead. An unparseable id in a keyed
    namespace is refused (fail closed — the namespaces are
    constructed from database ids only). Every other
    namespace (alert:<stripe event id>) is not order-keyed
    and is always claimable."""
    ns, _, ident = key.partition(":")
    if ns in ("receipt", "notify", "monitor-activate"):
        try:
            oid = int(ident)
        except ValueError:
            return False
        return not _order_dead(oid)
    if ns == "monitor":
        try:
            mid = int(ident)
        except ValueError:
            return False
        conn = db_connect()
        try:
            row = conn.execute(
                "SELECT order_id FROM monitors WHERE id=?",
                (mid,)).fetchone()
        finally:
            conn.close()
        return row is not None and not _order_dead(row[0])
    return True


def _claim_event_lock(key, purpose):
    """Single-fire guard for non-idempotent side effects across
    processes (Codex delta-8 #1/#4), keyed by a namespaced string
    ("alert:<event_id>", "receipt:<order_id>" — the namespaces
    keep the two purposes from blocking each other, delta-9 #6).
    The primary key admits one holder; a lock older than 3600 s
    belongs to a crashed holder and is reclaimed once (the send
    calls take seconds; an hour of suspension is beyond plausible
    for a live holder — delta-10 #3). Returns the owner token.
    A lock taken for a SUCCESSFUL fire is never released — it is
    the fired record; a failed fire releases it — scoped to the
    owner's token, so a reclaimed lock is never deleted by its
    previous owner (delta-9 #2)."""
    now = time.time()
    token = _secrets.token_hex(8)
    with _db_lock:
        if not _lock_key_alive(key):
            # Round 23: a claim for a dead order/monitor is
            # refused HERE, inside the claim's own critical
            # section — no row is inserted after the
            # tombstone. Callers already read None as "held
            # elsewhere -> skip", the safe direction.
            return None
        conn = db_connect()
        try:
            for _attempt in range(2):
                try:
                    conn.execute(
                        "INSERT INTO event_locks(event_id, purpose,"
                        " claimed_at, owner) VALUES(?,?,?,?)",
                        (key, purpose, now, token))
                    conn.commit()
                    return token
                except sqlite3.IntegrityError:
                    conn.rollback()
                    row = conn.execute(
                        "SELECT claimed_at FROM event_locks "
                        "WHERE event_id=?", (key,)).fetchone()
                    if row is None or now - row[0] <= 3600:
                        return None
                    conn.execute(
                        "DELETE FROM event_locks WHERE event_id=? "
                        "AND claimed_at=?", (key, row[0]))
                    conn.commit()
            return None
        finally:
            conn.close()


def _release_event_lock(key, token):
    with _db_lock:
        conn = db_connect()
        try:
            conn.execute(
                "DELETE FROM event_locks WHERE event_id=? "
                "AND owner=?", (key, token))
            conn.commit()
        finally:
            conn.close()


def _lock_still_mine(key, token):
    conn = db_connect()
    try:
        row = conn.execute(
            "SELECT owner FROM event_locks WHERE event_id=?",
            (key,)).fetchone()
        return row is not None and row[0] == token
    finally:
        conn.close()


def _lock_purpose(key):
    conn = db_connect()
    try:
        row = conn.execute(
            "SELECT purpose FROM event_locks WHERE event_id=?",
            (key,)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def _set_lock_purpose(key, token, purpose):
    """Owner-scoped purpose update on a held event lock: the
    durable 'sent, unconfirmed' record for a fire whose event-log
    record did not persist (round 16, 2026-11-10 incident). The
    write commits like every lock operation and is verified by
    rowcount — unlike log_event, it cannot fail silently."""
    with _db_lock:
        conn = db_connect()
        try:
            cur = conn.execute(
                "UPDATE event_locks SET purpose=? WHERE event_id=? "
                "AND owner=?", (purpose, key, token))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def _lock_row(key):
    """The full event-lock row (purpose, claimed_at, owner), or
    None when no row exists (round 18 state dispatch)."""
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT purpose, claimed_at, owner FROM event_locks "
            "WHERE event_id=?", (key,)).fetchone()
    finally:
        conn.close()


def _cas_lock_purpose(key, owner, from_purpose, to_purpose):
    """Owner+purpose compare-and-swap on an event-lock row
    (round 18): the transition lands only when the row still
    carries exactly the owner and purpose the caller observed,
    so two drivers resolving the same durable state cannot both
    act on it. Verified by rowcount, like _set_lock_purpose."""
    with _db_lock:
        conn = db_connect()
        try:
            cur = conn.execute(
                "UPDATE event_locks SET purpose=? WHERE event_id=? "
                "AND owner IS ? AND purpose=?",
                (to_purpose, key, owner, from_purpose))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def _takeover_event_lock(key, from_purpose, to_purpose, seen_owner):
    """Take ownership of a durable PENDING event-lock row
    (round 18): owner, purpose and claimed_at are swapped in
    one update guarded by the owner and purpose the caller
    observed. Returns the new owner token, or None when
    another driver won the swap — the single-flight discipline
    for retries of a recorded pending notification."""
    token = _secrets.token_hex(8)
    with _db_lock:
        if not _lock_key_alive(key):
            # Round 23: the takeover is refused for a dead
            # order/monitor inside the same critical section
            # — a pending row for a deleted owner is the
            # delete transaction's (or the GC's) to remove,
            # never a new driver's to adopt. Callers read
            # None as "another driver won" and skip.
            return None
        conn = db_connect()
        try:
            cur = conn.execute(
                "UPDATE event_locks SET owner=?, purpose=?, "
                "claimed_at=? WHERE event_id=? AND owner IS ? "
                "AND purpose=?",
                (token, to_purpose, time.time(), key, seen_owner,
                 from_purpose))
            conn.commit()
            return token if cur.rowcount > 0 else None
        finally:
            conn.close()


def _unmatched_logged(event_id):
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT 1 FROM events WHERE event='STRIPE_UNMATCHED' "
            "AND detail LIKE ?",
            (f"%event={event_id}%",)).fetchone() is not None
    finally:
        conn.close()


def _fire_unmatched_alert(event_id, telegram_text, log_detail):
    """Fire the HQ unmatched alert exactly once per event, across
    processes and crashes: alert BEFORE the terminal log (a crash
    between them re-alerts, Codex delta-3), single-fire via the
    event lock (delta-8 #1), and a failed send releases the lock
    and raises so the caller retries instead of acking in silence
    (delta-8 #4). Returns 'fired' or 'duplicate'."""
    if _unmatched_logged(event_id):
        return "duplicate"
    key = f"alert:{event_id}"
    token = _claim_event_lock(key, "unmatched-alert")
    if not token:
        if _unmatched_logged(event_id):
            return "duplicate"
        raise RuntimeError(
            "unmatched alert in flight in another process")
    if not _lock_still_mine(key, token):
        raise RuntimeError(
            "unmatched alert lock lost before firing")
    tok, _ = send_telegram(telegram_text)
    if not tok:
        _release_event_lock(key, token)
        raise RuntimeError("unmatched alert telegram failed")
    log_event(None, "STRIPE_UNMATCHED", log_detail)
    if not _unmatched_logged(event_id):
        # The send happened but its durable record did not (log
        # writes can fail silently): never ack a fire we cannot
        # prove — release and raise so the retry re-fires
        # (Codex delta-9 #6).
        _release_event_lock(key, token)
        raise RuntimeError("unmatched alert log did not persist")
    return "fired"


def _receipt_logged(order_id):
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT 1 FROM events WHERE order_id=? AND "
            "event='PAID_EMAIL_SENT'",
            (order_id,)).fetchone() is not None
    finally:
        conn.close()


# Resend retains an idempotency key for 24 hours; inside that
# window a same-key retry is deduped by the provider, so an
# UNKNOWN email outcome may be retried freely. The post-window
# rule (round 19, Codex delta-18 (b)) works to the SAFE side of
# the window: 23h from the first unknown outcome, retries are
# unrestricted; past it, exactly one further same-key resend is
# permitted and the notification then settles as
# sent-unconfirmed, whatever that resend's outcome.
_RESEND_IDEM_SAFE_AGE = 23 * 3600


def _email_state(notif_key):
    """The email_delivery row for one logical notification as
    (first_unknown_at, post_window_used, settled,
    first_attempt_at, last_attempt_at, last_outcome_at), or
    None. The first four indices are the round-19/21 shape;
    the round-22 pair is appended, never reordered."""
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT first_unknown_at, post_window_used, settled, "
            "first_attempt_at, last_attempt_at, last_outcome_at "
            "FROM email_delivery WHERE notif_key=?",
            (notif_key,)).fetchone()
    finally:
        conn.close()


def _email_window_basis(state):
    """Round 22: the post-window clock's basis for one
    email_delivery state row — the first UNKNOWN outcome's
    time, restored as the basis after the parent rejected
    round 21's first-attempt widening as a contract change.
    Three arms: (i) a recorded unknown outcome starts the
    window at that outcome's time (first_unknown_at, stamped
    from the pre-send stamp of THAT attempt); (ii) definite
    failures NEVER start it — an attempt whose outcome was
    recorded as definite contributes nothing; (iii) the
    conservative crash arm — an attempt whose outcome was
    never recorded (last_attempt_at with no outcome at or
    after it) counts its own pre-send attempt stamp: the
    earliest such stamp when no outcome was ever recorded
    (first_attempt_at), otherwise the unrecorded attempt's
    own stamp (last_attempt_at)."""
    if state is None:
        return None
    cands = []
    if state[0]:
        cands.append(state[0])
    if state[4]:
        if state[5] is None:
            cands.append(state[3] or state[4])
        elif state[5] < state[4]:
            cands.append(state[4])
    return min(cands) if cands else None


def _email_note_attempt(notif_key):
    """Stamp an attempt's time for a logical email
    notification, BEFORE the send it belongs to (round 21's
    pre-send stamp, kept; round 22 re-bases its meaning).
    first_attempt_at is first-stamp-wins; last_attempt_at
    moves at EVERY attempt. Before last_attempt_at is
    overwritten, a previous attempt whose outcome was never
    recorded is promoted into first_unknown_at (the crash
    arm of the basis): its stamp becomes the window start,
    so a later-recorded unknown cannot move the start later
    than the crashed attempt. Round 22 also makes this
    writer tombstone-aware IN THE SAME locked transaction:
    the row is the receipt bookkeeping of one order, and a
    send path resuming for a deleted order must not recreate
    the row the delete transaction removed."""
    with _db_lock:
        conn = db_connect()
        try:
            if notif_key.startswith("receipt:"):
                try:
                    _oid = int(notif_key.split(":", 1)[1])
                except ValueError:
                    _oid = None
                if _oid is not None and conn.execute(
                        "SELECT 1 FROM deleted_orders WHERE "
                        "order_id=?", (_oid,)).fetchone():
                    return
                if _oid is not None and not conn.execute(
                        "SELECT 1 FROM orders WHERE id=?",
                        (_oid,)).fetchone():
                    return
            stamp = time.time()
            row = conn.execute(
                "SELECT first_unknown_at, first_attempt_at, "
                "last_attempt_at, last_outcome_at FROM "
                "email_delivery WHERE notif_key=?",
                (notif_key,)).fetchone()
            promote = None
            if row is not None and row[2] and (
                    row[3] is None or row[3] < row[2]):
                promote = row[0] or (
                    row[1] if row[3] is None else row[2])
            conn.execute(
                "INSERT INTO email_delivery(notif_key,"
                " first_attempt_at, last_attempt_at) VALUES(?,?,?)"
                " ON CONFLICT(notif_key) DO UPDATE SET"
                " first_attempt_at = COALESCE(first_attempt_at,"
                " excluded.first_attempt_at),"
                " last_attempt_at = excluded.last_attempt_at,"
                " first_unknown_at = COALESCE(first_unknown_at,"
                " ?)",
                (notif_key, stamp, stamp, promote))
            conn.commit()
        finally:
            conn.close()


def _email_note_outcome(notif_key):
    """Round 22: record that the latest attempt's outcome WAS
    recorded (delivered or definite). UPDATE-only: a row the
    delete transaction removed is never recreated — the
    write is a no-op for a dead notification."""
    with _db_lock:
        conn = db_connect()
        try:
            conn.execute(
                "UPDATE email_delivery SET last_outcome_at=? "
                "WHERE notif_key=?",
                (time.time(), notif_key))
            conn.commit()
        finally:
            conn.close()


def _email_claim_post_window(notif_key):
    """Atomically claim the ONE post-window resend for a
    logical email notification (round 21, Codex delta-19
    (a2)): the conditional update lands only while the spent
    flag is still 0, and the rowcount is the verdict — the
    winner owns the attempt, the loser observes the spent
    state and settles WITHOUT attempting. Round 19 marked
    the flag from a state read taken BEFORE the receipt lock
    was claimed, so two racing drivers could both read the
    unspent state and both spend; the spend decision is now
    this write itself, taken under the receipt lock, never
    a pre-claim snapshot."""
    with _db_lock:
        conn = db_connect()
        try:
            cur = conn.execute(
                "UPDATE email_delivery SET post_window_used=1 "
                "WHERE notif_key=? AND post_window_used=0",
                (notif_key,))
            conn.commit()
            return cur.rowcount == 1
        finally:
            conn.close()


def _order_exists(order_id):
    """Existence re-check for the recovery paths (round 21,
    Codex delta-19 (c)): a caller holding an order snapshot
    across a gap re-reads this before writing order-keyed
    state or sending, so work for an order the admin deleted
    in the gap starts nothing and recreates nothing."""
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT 1 FROM orders WHERE id=?",
            (order_id,)).fetchone() is not None
    finally:
        conn.close()


def _order_dead(order_id):
    """Round 22: an order is dead when it is tombstoned OR its
    row is gone. Self-contained SQL on purpose: the send
    seams and the bookkeeping guards consult the order
    through this, never through a helper a caller may have
    left holding a stale answer."""
    conn = db_connect()
    try:
        if conn.execute(
                "SELECT 1 FROM deleted_orders WHERE order_id=?",
                (order_id,)).fetchone():
            return True
        return conn.execute(
            "SELECT 1 FROM orders WHERE id=?",
            (order_id,)).fetchone() is None
    finally:
        conn.close()


def _order_alive(order_id):
    return not _order_dead(order_id)


def _send_gate(order_id):
    """Round 22: THE send-seam consult, evaluated under
    _db_lock — the same lock the admin delete transaction
    holds from its tombstone write to its commit. The gate
    therefore runs entirely before or entirely after a
    deletion.

    Round 23 (Codex delta-21 (a)): this consult alone is an
    EARLY-ABORT check only — it releases the lock when it
    returns, so by itself it cannot promise the caller that
    the send it is about to start is atomic with the check.
    Callers use it to drop dead work cheaply before doing
    composition or claim bookkeeping; the atomic seam —
    gate and provider call in ONE acquisition — is
    _gated_send, and every notification send goes through
    it."""
    with _db_lock:
        return not _order_dead(order_id)


def _gated_send(order_id, send_fn, *args, **kwargs):
    """Round 23 (Codex delta-21 (a)): the atomic send seam —
    the aliveness gate and the provider call run inside ONE
    _db_lock acquisition. Round 22's seam consulted the gate
    and then released the lock before the HTTP call, so a
    deletion could complete in between and the send still
    started. Here the delete transaction — which holds
    _db_lock from its tombstone write to its commit — cannot
    interleave with the pair: it runs entirely BEFORE this
    acquisition (the gate then aborts, and no send starts)
    or it waits until the provider call has returned (the
    send was legitimately inside its call when the deletion
    began — the accepted in-flight residual, now the only
    residual). Round 24 (Codex delta-22): that wait is
    bounded BY CONSTRUCTION, not by the wrappers'
    per-operation timeout — _GATED_SEND_DEADLINE (30 s) is
    armed below for the duration of the call and the
    wrappers enforce it on their transport: a call still
    in flight when the deadline passes is cut there, its
    outcome classified "unknown" by the wrappers' own
    machinery, and this section exits — releasing the
    lock, and with it the waiting delete, at the deadline
    at the latest. Round 25 (Codex delta-23): the
    enforcement sits on the exchange's raw socket
    (_DeadlineSocket, beside _MAIL_IDEM), so the cut
    lands in EVERY phase — headers and chunk framing
    included — and a cut inside an HTTPError body read
    also classifies "unknown", never definite. Round
    26 (Codex delta-24): connection ESTABLISHMENT is
    inside the same bound — the deadline classes
    construct safely under the swap (HTTPS included)
    and armed connect is capped attempt by attempt
    (address connects, proxy tunnel, TLS handshake);
    the single getaddrinfo call is the statement's one
    named exception. Round 27 (Codex delta-25): the
    resolver exception is restated — at most one
    getaddrinfo per distinct host WITHIN the exchange
    (per-exchange resolution cache, see
    _SEND_RESOLUTION_CACHE) — and a supplied TLS
    context is used verbatim (see
    _DeadlineHTTPSConnection). Round 28 (Codex
    delta-26): the resolution cache is keyed by host
    alone (a same-host redirect to another port reuses
    the resolution, its own port substituted); the
    round-27 factory-context cache is REMOVED (fresh
    context per context=None construction, stdlib
    semantics); and the global opener is built at
    module import, so a first gated call never builds
    the opener — or its handler's context — inside the
    exchange.
    Returns
    None when the gate aborts; otherwise the send
    function's own result."""
    with _db_lock:
        if _order_dead(order_id):
            return None
        _dl_tok = _SEND_DEADLINE_AT.set(
            time.monotonic() + _GATED_SEND_DEADLINE)
        try:
            return send_fn(*args, **kwargs)
        finally:
            _SEND_DEADLINE_AT.reset(_dl_tok)


def _log_event_alive(order_id, event, detail=""):
    """Round 22: log_event for the recovery paths — an event
    row is a durable write, and a recovery resuming after its
    order was deleted must not recreate one for the dead
    order (delta-20's orphan SIDE_EFFECTS_OK arm). Round 22
    implemented the guard as this function's own alive check
    before delegating; round 23 (Codex delta-21 (b)) moved
    the check INTO log_event's single critical section,
    atomic with the insert — this name remains the recovery
    paths' spelling of the one guarded writer and simply
    delegates (through the module-level name, so the writer
    is a single seam)."""
    return log_event(order_id, event, detail)


def _email_note_unknown(notif_key):
    """Stamp the FIRST unknown outcome's time for a logical
    email notification (round 19). The first stamp wins — the
    post-window clock runs from the first attempt whose
    acceptance could not be ruled out, not from later retries.
    The stamp written is the unknown attempt's own pre-send
    stamp (the row's last_attempt_at, set by
    _email_note_attempt just before this send), never the
    bookkeeping time and never an earlier definite attempt's
    stamp — unless an earlier attempt's outcome was never
    recorded, whose stamp _email_note_attempt has already
    promoted into first_unknown_at (the crash arm; the min
    below keeps it). Round 22: UPDATE-only (delta-20's
    resurrection arm) — if the delete transaction removed
    the row, this write is a no-op and recreates nothing.
    The write is committed under the DB lock like every
    durable record in this file."""
    with _db_lock:
        conn = db_connect()
        try:
            row = conn.execute(
                "SELECT first_unknown_at, last_attempt_at FROM "
                "email_delivery WHERE notif_key=?",
                (notif_key,)).fetchone()
            if row is None:
                return
            cands = [v for v in row if v]
            value = min(cands) if cands else time.time()
            conn.execute(
                "UPDATE email_delivery SET first_unknown_at=?, "
                "last_outcome_at=? WHERE notif_key=?",
                (value, time.time(), notif_key))
            conn.commit()
        finally:
            conn.close()


def _email_mark(notif_key, column):
    """Set one durable flag (post_window_used / settled) on a
    logical email notification's row. Round 22: UPDATE-only
    (delta-20's resurrection arm) — if the delete transaction
    removed the row, the flag write is a no-op and recreates
    nothing. `column` is only ever one of the two literals at
    this function's call sites."""
    with _db_lock:
        conn = db_connect()
        try:
            conn.execute(
                f"UPDATE email_delivery SET {column}=1 "
                "WHERE notif_key=?", (notif_key,))
            conn.commit()
        finally:
            conn.close()


def _ensure_paid_receipt(order, amount_cents):
    """True when the receipt is on record as sent (already, or by
    the resend this call performs). The send is single-fire PER
    ORDER (the completion record is per order — Codex delta-9
    #1): two events of one payment, in any processes, contend on
    the same "receipt:<order_id>" lock. If another holder is
    mid-send, this returns the on-record state and the caller's
    retry logic re-checks.

    Round 16 refines the delta-9 #6 arm: a send that SUCCEEDED
    but whose PAID_EMAIL_SENT record did not persist is not
    treated as unsent — releasing the lock made the next consult
    send a duplicate receipt (2026-11-10 incident). The held
    lock instead becomes the durable 'sent, unconfirmed' record
    (purpose receipt-sent-unconfirmed), and the consult below
    honours it: reconcile the log, never resend.

    Round 18 (delta-17 (a1)/(a2)): the send outcome is tri-state
    now. A DEFINITE failure releases the lock and reports False
    exactly as before. An UNKNOWN outcome (the provider may
    have accepted before its answer was lost) does the same —
    the retry this invites is safe because every attempt
    carries the same Resend idempotency key: the provider
    dedupes an accepted first attempt. A crash between an
    accepted send and this function's bookkeeping leaves the
    lock held; once it goes stale the reclaim resend is
    likewise deduped by the key. The receipt's pending state
    deliberately does NOT live in the lock row: it is the
    absence of PAID_EMAIL_SENT under a live stripe_events link,
    driven by the webhook consults and the boot sweep (both
    status-independent) — and pin A5 fixes the lock lifecycle
    (a failed send leaves no row).

    Round 19 (delta-18 (b)): the idempotency dedupe above holds
    only while Resend retains the key — 24 hours. The first
    UNKNOWN outcome's time is stamped durably (email_delivery,
    NOT the lock row: the stamp must survive the lock release
    the unknown arm performs, and A5 forbids a failed send
    leaving a lock row). Inside 23h of that stamp, retries are
    unrestricted. Past it, exactly ONE further same-key resend
    is permitted — its spent flag is marked durably after the
    send lock is claimed and before the send — and whatever
    its outcome the receipt then settles as sent-unconfirmed
    and is never attempted again. Never zero post-window
    attempts (the one resend always happens), never a second
    one, never an unbounded loop.

    Round 19 (delta-18 (d)): the sent-unconfirmed reconcile
    below is claimed ATOMICALLY before it inserts + emits. The
    claim lives on the lock row's purpose: a takeover swaps
    owner, purpose and claimed_at in one guarded update from
    receipt-sent-unconfirmed to receipt-reconciling; the loser
    observes the claim and no-ops (it reports the on-record
    state). The claim only ever transitions a row that already
    exists in the unconfirmed state — it creates no row, so
    A5's lifecycle is untouched.

    Round 20: the sweep whose event loop drives this function
    now runs on every production scheduler tick as well as at
    boot (see _monitor_tick), so a pending receipt no longer
    waits for a webhook retry, a consult, or a restart.

    Round 21 (Codex delta-19 (a2)/(c)): three hardenings.
    The receipt lock is now claimed BEFORE the durable state
    is read, and the post-window spend is decided by an
    atomic claim on that fresh state (_email_claim_post_
    window) — round 19 computed the spend from a state read
    taken before the claim, so two racing drivers could both
    read the unspent state and both spend. The post-window
    clock runs from the earliest stamp on the row, and the
    first-attempt stamp is written BEFORE every send
    (_email_note_attempt), so an attempt whose outcome
    recording a crash ate is still on the clock. And the
    recovery is existence-guarded: an order deleted before
    or during the pass — checked at entry, again after the
    claim, and again at the send seam — gets no state
    written and no send attempted.

    Round 22 (Codex delta-20): the basis is the first UNKNOWN
    outcome again — the round-21 sentence above ("the clock
    runs from the earliest stamp on the row") is superseded:
    the parent rejected the first-attempt widening as a
    contract change. _email_window_basis implements the three
    arms (recorded unknown starts the window; definite
    failures never do; an unrecorded-outcome attempt counts
    its pre-send stamp). The seam consult is the tombstone
    gate (_send_gate), serialized against the delete
    transaction; the outcome bookkeeping is UPDATE-only, so
    a receipt send that resolves after its order was deleted
    recreates nothing."""
    if _receipt_logged(order["id"]):
        return True
    if not _order_alive(order["id"]):
        return False
    key = f"receipt:{order['id']}"
    lock = _lock_row(key)
    if lock is not None and lock[0] == "receipt-sent-unconfirmed":
        token = _takeover_event_lock(
            key, "receipt-sent-unconfirmed", "receipt-reconciling",
            lock[2])
        if not token:
            return _receipt_logged(order["id"])
        _log_event_alive(order["id"], "PAID_EMAIL_SENT",
                         "reconciled from the durable "
                         "sent-unconfirmed record; the original "
                         "send was delivered")
        if _receipt_logged(order["id"]):
            return True
        # The reconcile's own record did not persist: hand the
        # unconfirmed state back so a later consult can claim
        # it again, and report not-on-record.
        _cas_lock_purpose(key, token, "receipt-reconciling",
                          "receipt-sent-unconfirmed")
        return False
    token = _claim_event_lock(key, "receipt")
    if not token:
        return _receipt_logged(order["id"])
    if not _lock_still_mine(key, token):
        return _receipt_logged(order["id"])
    if _receipt_logged(order["id"]):
        # A racing driver completed the receipt while this one
        # was claiming; nothing is owed, and this claim row —
        # taken for a send that will not happen — is released.
        _release_event_lock(key, token)
        return True
    if not _order_alive(order["id"]):
        # Deleted while this driver claimed: the delete
        # transaction removed the order's bookkeeping; leave
        # nothing behind.
        _release_event_lock(key, token)
        return False
    # The state is read only now, under the claim — the spend
    # decision below is taken from THIS read plus the atomic
    # claim itself, never from a pre-claim snapshot (round 21).
    state = _email_state(key)
    final_attempt = False
    if state is not None and state[2]:
        # Settled by the post-window rule on an earlier pass;
        # the settle's own completion record is this write (if
        # it already persisted, the check at the top returned).
        # Round 22: a dead order gets no completion record
        # recreated for it — the receipt question is moot.
        if not _order_alive(order["id"]):
            _release_event_lock(key, token)
            return False
        log_event(order["id"], "PAID_EMAIL_SENT",
                  "settled as sent-unconfirmed: the Resend "
                  "idempotency window passed and the single "
                  "post-window resend is spent; not attempted "
                  "again")
        _release_event_lock(key, token)
        return True
    # The window basis (round 22): the first UNKNOWN outcome,
    # with the crash arm — see _email_window_basis. Definite
    # failures, however early, never start this clock.
    basis = _email_window_basis(state)
    if basis is not None and \
            time.time() - basis > _RESEND_IDEM_SAFE_AGE:
        if not _email_claim_post_window(key):
            # The one post-window resend OPPORTUNITY is
            # already claimed — its flag was claimed before
            # its send, but the settle never landed (a crash
            # in between — possibly before the HTTP call was
            # ever made), or a racing driver claimed it
            # first. Settle WITHOUT another attempt: a second
            # post-window resend is never permitted.
            if not _order_alive(order["id"]):
                _release_event_lock(key, token)
                return False
            _email_mark(key, "settled")
            log_event(order["id"], "PAID_EMAIL_SENT",
                      "settled as sent-unconfirmed: the single "
                      "post-window resend was spent by an "
                      "interrupted pass; not attempted again")
            _release_event_lock(key, token)
            return True
        # The atomic claim above IS the spent flag, landed
        # durably BEFORE the one permitted post-window send:
        # a crash around the send spends the attempt rather
        # than permitting a second one.
        final_attempt = True
    # The attempt stamp lands BEFORE the send (round 21,
    # kept): an attempt whose outcome recording is lost to a
    # crash is on the post-window clock through the crash arm
    # of the basis above.
    _email_note_attempt(key)
    if not _send_gate(order["id"]):
        # The send seam (round 21's check, round 22's gate):
        # the order was deleted — tombstone written — in the
        # gap before this send: abort it, serialized against
        # the delete transaction by _db_lock. The delete
        # already removed the stamp and this lock row; the
        # release below is then a no-op, and the driver's GC
        # collects anything a wider race leaves.
        _release_event_lock(key, token)
        return False
    status = _send_paid_receipt(order, amount_cents)
    if status == "delivered" and not _receipt_logged(order["id"]):
        if _set_lock_purpose(key, token,
                             "receipt-sent-unconfirmed"):
            _email_note_outcome(key)
            return True
        status = "failed"
    if status != "delivered":
        _release_event_lock(key, token)
        if status == "unknown":
            _email_note_unknown(key)
        else:
            _email_note_outcome(key)
        if final_attempt:
            _email_mark(key, "settled")
            _log_event_alive(order["id"], "PAID_EMAIL_SENT",
                      "settled as sent-unconfirmed: the single "
                      f"post-window resend ended {status}; not "
                      "attempted again")
            return True
        return False
    _email_note_outcome(key)
    return True


def _stripe_signature_ok(raw, header, secret):
    """Verify a Stripe-Signature header against the raw body:
    HMAC-SHA256 of "<t>.<body>" with the endpoint secret, 5-minute
    tolerance, constant-time compare. Any v1 candidate may match
    (Stripe sends two during secret rotation)."""
    try:
        stamps = []
        sigs = []
        for part in header.split(","):
            key, _, value = part.partition("=")
            if key.strip() == "t":
                stamps.append(value.strip())
            elif key.strip() == "v1":
                sigs.append(value.strip())
        if not stamps or not sigs:
            return False
        ts = stamps[0]
        if abs(time.time() - int(ts)) > 300:
            return False
        signed = ts.encode() + b"." + raw
        expect = hmac.new(secret.encode(), signed,
                          _hl.sha256).hexdigest()
        return any(hmac.compare_digest(expect, s) for s in sigs)
    except Exception:
        return False


def _deepscan_queued_logged(order_id):
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT 1 FROM events WHERE order_id=? AND "
            "event='DEEPSCAN_QUEUED'",
            (order_id,)).fetchone() is not None
    finally:
        conn.close()


def _deepscan_notified(order_id):
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT 1 FROM events WHERE order_id=? AND "
            "event='DEEPSCAN_NOTIFIED'",
            (order_id,)).fetchone() is not None
    finally:
        conn.close()


def on_deep_scan_paid(order):
    payload = {"order_id": order["id"], "tier": order["tier"],
               "name": order["name"], "email": order["email"],
               "url": order["url"], "amount": order["amount"],
               "queued_at": utcnow()}
    with _db_lock:
        conn = db_connect()
        try:
            # Round 21 (Codex delta-19 (c)): the insert is
            # existence-guarded IN THE SAME TRANSACTION — a
            # caller resuming with a snapshot of an order the
            # admin deleted in the gap must not recreate the
            # queued request (the delete path removes it, and
            # the engine worker would be offered work for an
            # order that no longer exists), and the
            # notification half below is skipped with it.
            alive = conn.execute(
                "SELECT 1 FROM orders WHERE id=?",
                (order["id"],)).fetchone()
            if alive is None:
                return
            # Round 22: tombstone-guarded in the same
            # transaction too — mid-delete, the row can still
            # exist while its work is already dead.
            if conn.execute(
                    "SELECT 1 FROM deleted_orders WHERE "
                    "order_id=?", (order["id"],)).fetchone():
                return
            conn.execute(
                "INSERT OR IGNORE INTO fulfilment_requests(order_id,kind,"
                "payload,status,created_at) VALUES(?,?,?,?,?)",
                (order["id"], "deep_scan", json.dumps(payload), "queued",
                 utcnow()))
            conn.commit()
        finally:
            conn.close()
    _fire_deep_scan_notification(order)


def _fire_deep_scan_notification(order):
    """The notification half of the Deep Scan hook. Round 16
    made it exactly-once for the outcomes it modelled; round 18
    (Codex delta-17 (a1)/(a2)/(g)) completes the semantics at
    the transport seam and decouples it from the order
    workflow. Telegram has no idempotency key, so the ping is
    AT-MOST-ONCE, intent-first: the durable state lives on the
    "notify:<order_id>" lock row —

      (no row)                       not started; the claim
                                     itself, purpose
                                     deepscan-notify-intent, IS
                                     the intent record, written
                                     before any send.
      deepscan-notify-intent         a fire is in flight, or
                                     its owner died around the
                                     send; a STALE intent is an
                                     unknown outcome and is
                                     honoured as delivered.
      deepscan-notify-pending        the send was DEFINITELY
                                     rejected; retryable — the
                                     boot sweep's driver takes
                                     the row over and re-fires.
      deepscan-notify-pending-unknown  the transport outcome
                                     was UNKNOWN (the answer
                                     was lost after possible
                                     acceptance); reconciled as
                                     delivered, NEVER re-sent.
      deepscan-notified-unconfirmed  the send reported success
                                     but its DEEPSCAN_NOTIFIED
                                     record did not persist
                                     (round 16); reconciled,
                                     never re-sent.

    A failed or unknown ping writes its durable state and
    RETURNS — it never raises out of the hook, so it can no
    longer block SIDE_EFFECTS_OK or wedge the order in PAID;
    the marker now means 'done, or durably queued with a live
    retry path'. Only a state that cannot be established
    durably at all (the database itself failing) still raises.

    Round 21 (Codex delta-19 (c)): existence-guarded like
    the rest of the recovery paths — an order deleted before
    this fire, or in the gap before its send, gets no lock
    claimed and no ping attempted (the send-seam re-check
    below).

    Round 22 (Codex delta-20): the entry check is
    tombstone-aware and the seam consult is the serialized
    gate (_send_gate) — a deletion landing anywhere in the
    check-to-send gap aborts the fire at the gate; the
    outcome/reconcile event writes are guarded the same way
    (no event is recreated for a dead order).
    """
    oid = order["id"]
    if not _order_alive(oid):
        return
    if _deepscan_notified(oid):
        return
    key = f"notify:{oid}"
    token = None
    for _try in range(2):
        row = _lock_row(key)
        purpose = row[0] if row else None
        if purpose == "deepscan-notified-unconfirmed":
            _log_event_alive(
                oid, "DEEPSCAN_NOTIFIED",
                "reconciled from the durable sent-unconfirmed "
                "record; the original ping was delivered")
            return
        if purpose == "deepscan-notify-pending-unknown":
            _log_event_alive(
                oid, "DEEPSCAN_NOTIFIED",
                "the original ping's transport outcome was "
                "unknown; treated as delivered, not re-sent")
            return
        if purpose == "deepscan-notify-intent":
            if row[1] and time.time() - row[1] <= 3600:
                # A fire is in flight in another process. Its
                # intent is durable, so this caller may treat
                # the notification as queued: the state resolves
                # there, or goes stale and is reconciled.
                return
            # A stale intent: the firing process died around
            # its send. The outcome is unknowable; at-most-once
            # honours the intent as delivered.
            if _cas_lock_purpose(
                    key, row[2], "deepscan-notify-intent",
                    "deepscan-notify-pending-unknown"):
                _log_event_alive(
                    oid, "DEEPSCAN_NOTIFIED",
                    "delivery intent on record from an "
                    "interrupted fire; treated as "
                    "delivered, not re-sent")
            return
        if purpose == "deepscan-notify-pending":
            token = _takeover_event_lock(
                key, "deepscan-notify-pending",
                "deepscan-notify-intent", row[2])
            if not token:
                return  # another driver took the retry
            break
        if row is None:
            token = _claim_event_lock(key, "deepscan-notify-intent")
            if token:
                break
            if not _lock_key_alive(key):
                # Round 23: the claim was refused because the
                # order is dead (the round-23 claim guard) —
                # the fire is dropped, not an error: nothing
                # is owed for a deleted order, and raising
                # here would misreport the refusal as a state
                # that could not be established. The guard's
                # own question is re-asked (direct SQL), so
                # the answer cannot be a caller's stale
                # snapshot.
                return
            continue  # lost a claim race; re-dispatch once
        return  # a row in a state this code does not own
    if not token:
        raise RuntimeError(
            "Deep Scan HQ notification state could not be "
            "established")
    if not _lock_still_mine(key, token):
        # The state moved under us (a stale reclaim or a CAS
        # resolution); whatever it is now, it is durable.
        return
    if not _deepscan_queued_logged(oid):
        _log_event_alive(oid, "DEEPSCAN_QUEUED",
                         "fulfilment request recorded for the "
                         "engine worker")
    res = _gated_send(
        oid, send_telegram,
        f"ShipAudit Lab: Deep Scan order #{oid} is PAID — "
        f"fulfilment queued for {order['url']} "
        f"(client {order['email']}).")
    if res is None:
        # The send seam (round 21's check, round 22's gate,
        # round 23's atomic pair): the order was deleted —
        # tombstone written — before this send could start:
        # drop the fire. The delete removed this intent row
        # with the order (the release below is then a no-op);
        # a ping for a deleted order is never attempted.
        _release_event_lock(key, token)
        return
    status = _send_status(res)
    det = res[1]
    if status == "delivered":
        _log_event_alive(oid, "DEEPSCAN_NOTIFIED", det)
        if not _deepscan_notified(oid):
            if _set_lock_purpose(key, token,
                                 "deepscan-notified-unconfirmed"):
                return
            # Neither the record nor the durable fallback could
            # be written. Leave the intent row standing —
            # staleness resolves it as an interrupted fire and
            # at-most-once holds — and raise rather than
            # releasing into a re-fire.
            raise RuntimeError(
                "Deep Scan HQ notification record did not persist")
        return
    if status == "unknown":
        if not _cas_lock_purpose(
                key, token, "deepscan-notify-intent",
                "deepscan-notify-pending-unknown"):
            raise RuntimeError(
                "Deep Scan HQ notification state did not persist")
        _log_event_alive(oid, "DEEPSCAN_NOTIFIED",
                         "transport outcome unknown; treated as "
                         "delivered, not re-sent")
        return
    # Definite rejection: nothing was delivered. Record the
    # durable pending state and return WITHOUT raising (the
    # round-16 raise is what wedged orders in PAID, delta-17
    # (g)); the boot sweep's driver retries from the row.
    if not _cas_lock_purpose(
            key, token, "deepscan-notify-intent",
            "deepscan-notify-pending"):
        raise RuntimeError(
            "Deep Scan HQ notification state did not persist")
    _log_event_alive(
        oid, "DEEPSCAN_NOTIFY_FAILED",
        f"definite rejection; delivery pending retry: {det}")


# ---------------------------------------------------------------------------
# Monitoring — the $79/mo tier's machinery: a weekly rescan per PAID
# Monitoring order, a stored baseline digest, and a client alert when
# the finding set changes. Activation happens in _api_admin_post when a
# Monitoring order reaches PAID. The baseline scan runs on the first
# tick and never emails the client — it is the reference point.
# ---------------------------------------------------------------------------
MONITOR_INTERVAL = 7 * 86400
MONITOR_TICK = int(os.environ.get("VF_MONITOR_TICK", "600"))
_monitor_scan_lock = threading.Lock()


def _monitor_activated_logged(order_id):
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT 1 FROM events WHERE order_id=? AND "
            "event='MONITOR_ACTIVATED'",
            (order_id,)).fetchone() is not None
    finally:
        conn.close()


def activate_monitor(order):
    """Insert the monitor row (INSERT OR IGNORE: unique in every
    interleaving) and fire its MONITOR_ACTIVATED courtesy log
    exactly once (round 17, the out-of-mandate observation round
    16 recorded). The log rides the same single-fire discipline
    as the Deep Scan hook (round 16): the durable
    MONITOR_ACTIVATED record is verified by reading it back; a
    fire whose record did not persist leaves the held lock as
    the durable 'sent, unconfirmed' record (purpose
    monitor-activated-unconfirmed), and re-entry honours it and
    reconciles the log."""
    with _db_lock:
        conn = db_connect()
        try:
            # Round 21 (Codex delta-19 (c)): existence-guarded
            # IN THE SAME TRANSACTION, like the fulfilment
            # insert — a caller resuming with a snapshot of a
            # deleted order must not recreate its monitor row,
            # and the activation log below is skipped with it.
            alive = conn.execute(
                "SELECT 1 FROM orders WHERE id=?",
                (order["id"],)).fetchone()
            if alive is None:
                return
            # Round 22: tombstone-guarded in the same
            # transaction too — mid-delete, the row can still
            # exist while its work is already dead.
            if conn.execute(
                    "SELECT 1 FROM deleted_orders WHERE "
                    "order_id=?", (order["id"],)).fetchone():
                return
            conn.execute(
                "INSERT OR IGNORE INTO monitors(order_id,url,email,name,"
                "created_at,next_run_at) VALUES(?,?,?,?,?,?)",
                (order["id"], order["url"], order["email"],
                 order["name"], utcnow(), time.time()))
            conn.commit()
        finally:
            conn.close()
    oid = order["id"]
    if not _order_alive(oid):
        # Deleted in the gap after the insert (round 21): the
        # delete transaction removed the row just written;
        # claim no activation lock and write no log for it.
        return
    if _monitor_activated_logged(oid):
        return
    key = f"monitor-activate:{oid}"
    mrow = _lock_row(key)
    if mrow is not None and mrow[0] in (
            "monitor-activated-unconfirmed",
            "monitor-activated-reconciling"):
        # Round 19 (Codex delta-18 (d)): the reconcile insert +
        # emit is claimed ATOMICALLY first — a takeover swaps
        # owner, purpose and claimed_at in one guarded update;
        # the loser observes the claim and no-ops. Before, two
        # concurrent re-entries could both observe the
        # unconfirmed state and each insert + emit the line.
        # A claim another reconcile holds and has not finished
        # is honoured while fresh (the reconciler is mid-write);
        # a stale one is taken over like the unconfirmed state.
        if mrow[0] == "monitor-activated-reconciling" and \
                mrow[1] and time.time() - mrow[1] <= 3600:
            return
        token = _takeover_event_lock(
            key, mrow[0], "monitor-activated-reconciling", mrow[2])
        if not token:
            return  # another reconcile claimed it first
        _log_event_alive(
            oid, "MONITOR_ACTIVATED",
            "reconciled from the durable sent-unconfirmed "
            "record; the original log line was written")
        if _monitor_activated_logged(oid):
            return
        # The reconcile's own record did not persist: hand the
        # unconfirmed state back for a later retry.
        _cas_lock_purpose(key, token,
                          "monitor-activated-reconciling",
                          "monitor-activated-unconfirmed")
        raise RuntimeError(
            "MONITOR_ACTIVATED record did not persist")
    token = _claim_event_lock(key, "monitor-activate")
    if not token:
        if not _lock_key_alive(key):
            # Round 23: the claim was refused because the
            # order is dead (the round-23 claim guard) — the
            # activation is moot, not an error. (The guard's
            # own question, re-asked directly — never a
            # caller's stale snapshot.)
            return
        if _monitor_activated_logged(oid) or \
                _lock_purpose(key) == \
                "monitor-activated-unconfirmed":
            return
        raise RuntimeError(
            "monitor activation log in flight in another process")
    if not _lock_still_mine(key, token):
        if _monitor_activated_logged(oid):
            return
        raise RuntimeError(
            "monitor activation log lock lost before firing")
    _log_event_alive(
        oid, "MONITOR_ACTIVATED",
        "weekly rescan scheduled; baseline due on next tick")
    if not _monitor_activated_logged(oid):
        if _set_lock_purpose(key, token,
                             "monitor-activated-unconfirmed"):
            return
        _release_event_lock(key, token)
        raise RuntimeError(
            "MONITOR_ACTIVATED record did not persist")


def _monitor_reschedule(monitor_id, when):
    with _db_lock:
        conn = db_connect()
        conn.execute("UPDATE monitors SET next_run_at=? WHERE id=?",
                     (when, monitor_id))
        conn.commit()
        conn.close()


def _finding_key(f):
    return f"{(f.get('severity') or '').upper()}|{f.get('title') or ''}"


def _fmt_changes(items):
    if not items:
        return "  - none"
    lines = []
    for it in items[:15]:
        sev, _, title = it.partition("|")
        lines.append(f"  - [{sev}] {title}")
    if len(items) > 15:
        lines.append(f"  - ... and {len(items) - 15} more")
    return "\n".join(lines)


def _fmt_changes_html(items):
    """HTML twin of _fmt_changes: same 15-item cap, same content,
    rendered as a severity-chip list."""
    pairs = []
    for it in items[:15]:
        sev, _, title = it.partition("|")
        pairs.append((sev, title))
    out = email_template.severity_list(pairs)
    if len(items) > 15:
        out += email_template.para(
            f"…and {len(items) - 15} more — reply for the full list.")
    return out


def _scan_with_timeout(target, timeout=None):
    """run_surface_scan with a hard wall-clock bound. The scan's own
    per-request timeouts do not cover every socket path (resolver
    stalls, a TLS handshake that never completes); an unbounded call
    would wedge the weekly scheduler thread forever on one bad target.
    A stuck worker leaks one daemon thread; the loop lives."""
    if timeout is None:
        timeout = int(os.environ.get("VF_MONITOR_SCAN_TIMEOUT", "600"))
    box = {}

    def _work():
        try:
            box["r"] = run_surface_scan(target)
        except Exception as e:
            box["e"] = e

    th = threading.Thread(target=_work, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        raise TimeoutError(f"scan of {target} exceeded {timeout}s")
    if "e" in box:
        raise box["e"]
    return box["r"]


def _monitor_alert_parts(mon, host, order_id, d_new, d_gone,
                         d_grade, d_score):
    """Compose the monitoring change-alert (text + HTML)
    for one delivered diff."""
    body = (
        f"Hi {mon['name']},\n\n"
        f"Our weekly rescan of {mon['url']} found changes since the "
        f"previous scan.\n\n"
        f"Current grade: {d_grade} ({d_score}/100)\n\n"
        f"New findings ({len(d_new)}):\n{_fmt_changes(d_new)}\n\n"
        f"Resolved since the last scan ({len(d_gone)}):\n"
        f"{_fmt_changes(d_gone)}\n\n"
        "Reply to this email if you would like the full updated "
        "report.\n\n"
        "- ShipAudit Lab\n"
        "Security for what you shipped.")
    body_html = email_template.render_email(
        eyebrow="Monitoring · Weekly rescan",
        headline=f"Changes detected on {host}",
        body_html=(
            email_template.para(f"Hi {mon['name']},")
            + email_template.para(
                f"Our weekly rescan of {mon['url']} found changes "
                f"since the previous scan.")
            + email_template.grade_block(d_grade, d_score)
            + email_template.details_table([
                ("Target", mon["url"]),
                ("Service", "Monitoring — weekly rescan"),
                ("Reference", f"Order #{order_id}"),
            ])
            + email_template.list_heading(
                f"New findings ({len(d_new)})")
            + _fmt_changes_html(d_new)
            + email_template.list_heading(
                f"Resolved since the last scan ({len(d_gone)})")
            + _fmt_changes_html(d_gone)
            + email_template.para(
                "Reply to this email if you would like the full "
                "updated report.")),
        reason="You received this email because Monitoring is active "
               "for this app on your ShipAudit Lab account.")
    return body, body_html


def _monitor_alert_idem(mon, pending):
    """The stable Resend idempotency key for one logical
    monitoring alert (round 18): derived from the monitor, the
    retained record's creation stamp and its exact diff, so
    every retry of THIS alert carries the same key (the same
    alert retried keeps the key) and a genuinely new alert —
    a different diff, or the same diff in a later week under a
    new record — gets a new one."""
    raw = json.dumps(
        [mon["id"], pending.get("since"), pending.get("new"),
         pending.get("gone"), pending.get("digest_after")],
        sort_keys=True)
    return "monitor-alert:" + _hl.sha256(raw.encode()).hexdigest()[:32]


def _alert_final_attempt(pending):
    """Round 19 (Codex delta-18 (b)): True when this send is
    the ONE post-window resend the rule permits — the alert's
    first unknown outcome is past the safe side of Resend's
    24h idempotency window and the resend has not been spent.
    The caller marks post_window_used durably WITH the intent
    write, before the send, and settles the alert as
    sent-unconfirmed whatever the send's outcome."""
    first = pending.get("first_unknown_at")
    return bool(first) and not pending.get("post_window_used") \
        and (time.time() - first) > _RESEND_IDEM_SAFE_AGE


def _alert_window_spent(pending):
    """Round 19: True when the alert's single post-window
    resend has been spent (marked before its send) and the
    window has passed — the alert is settled WITHOUT another
    attempt (a crash between the spent mark and the settle
    lands here on the next run)."""
    first = pending.get("first_unknown_at")
    return bool(first) and bool(pending.get("post_window_used")) \
        and (time.time() - first) > _RESEND_IDEM_SAFE_AGE


def _send_monitor_alert(mon, host, order_id, pending):
    """One monitoring change-alert send, under the alert's
    idempotency key (round 18). Returns the wrapper's
    tri-state-carrying result.

    Round 22: the FINAL monitor seam is inside this function,
    after composition — a tombstone written while the alert
    was being composed aborts the send before any HTTP call.
    Round 23 (Codex delta-21 (a)): the seam is _gated_send —
    gate and HTTP call in one critical section, not a consult
    followed by a send. The abort returns a plain (False, ...)
    tuple, which _send_status classifies as a definite
    outcome: the callers' retry bookkeeping runs, its UPDATEs
    no-op on the removed monitor row, and its event writes are
    guarded."""
    body, body_html = _monitor_alert_parts(
        mon, host, order_id, pending["new"], pending["gone"],
        pending["grade"], pending["score"])
    _idem_tok = _MAIL_IDEM.set(
        pending.get("idem")
        or _monitor_alert_idem(mon, pending))
    try:
        res = _gated_send(
            order_id, send_resend,
            mon["email"],
            f"Monitoring: changes detected on {host}",
            body, html=body_html)
        if res is None:
            return (False, "aborted before send: the order "
                           "was deleted")
        return res
    finally:
        _MAIL_IDEM.reset(_idem_tok)


def _run_monitor(mon, scheduled=False):
    # One run per monitor across processes (Codex delta-13 #2):
    # two interleaved runs read the same baseline, and the later
    # unconditional save can erase the earlier run's retained
    # alert. The event-lock table is the mutex; a foreign holder
    # means this monitor is already being worked — skip the cycle.
    key = f"monitor:{mon['id']}"
    token = _claim_event_lock(key, "monitor")
    if not token:
        log(f"monitor {mon['id']}: run already in progress "
            "elsewhere; skipped")
        return
    try:
        # The caller's row is a snapshot taken BEFORE the mutex:
        # another run may have completed since (retained alert
        # saved, digest advanced). Re-read under the mutex and
        # work only on the fresh row (Codex delta-14 #1).
        conn = db_connect()
        conn.row_factory = sqlite3.Row
        try:
            fresh = conn.execute(
                "SELECT * FROM monitors WHERE id=?",
                (mon["id"],)).fetchone()
        finally:
            conn.close()
        if fresh is None or not fresh["active"]:
            return
        if scheduled and fresh["next_run_at"] > time.time() + 5:
            # Another run already completed and rescheduled
            # (Codex delta-15): the scheduler's snapshot was
            # due, the fresh row is not. Direct calls are a
            # deliberate force-run and skip this revalidation.
            return
        _run_monitor_locked(dict(fresh))
    finally:
        _release_event_lock(key, token)


def _run_monitor_locked(mon):
    # Round 21 (Codex delta-19 (c)): the caller re-read this
    # row under the run mutex, but a deletion can still land
    # between that read and this run — and again before each
    # send below. The send seams re-read existence (the
    # _monitor_alive checks at the two _send_monitor_alert
    # calls); this entry check drops a run whose row is
    # already gone before it writes or sends anything.
    if not _monitor_alive(mon["id"]):
        return
    order_id = mon["order_id"]
    host = urllib.parse.urlparse(mon["url"]).hostname or ""
    # A retained alert from an earlier failed send is delivered
    # BEFORE any scanning: it needs nothing from a new scan, and a
    # target that no longer scans must not starve it (Codex delta-3).
    _pending = None
    if mon.get("pending_alert"):
        try:
            _pending = json.loads(mon["pending_alert"])
        except Exception:
            _pending = None
    if _pending:
        # Reconcile interrupted deliveries BEFORE anything is
        # re-sent (round 16): a BARE intent field on record means
        # a previous run persisted its intent and died before the
        # outcome was persisted — the send may already have been
        # accepted remotely, and re-sending would duplicate a
        # delivered message. (The residual ambiguity — a crash
        # between the intent write and the send itself — is the
        # transport case of the 2026-11-10 incident record;
        # exactly-once over that channel cannot be had from this
        # side.) The escalation intent is only ever written
        # together with the persisted attempt bookkeeping, after
        # the delivery intent was already cleared, so the two
        # reconciliations never compete.
        #
        # Round 18 adds the recorded-outcome arm: an intent
        # whose last_outcome is "unknown" is NOT an interrupted
        # run — the previous run SAW the transport fail
        # ambiguously and persisted that fact. For email that is
        # retryable safely under the alert's idempotency key
        # (Resend dedupes an accepted first attempt), so the
        # record falls through to the send step below instead of
        # being reconciled as delivered.
        _unknown_retry = bool(_pending.get("send_intent")) and \
            _pending.get("last_outcome") == "unknown" and \
            not _alert_window_spent(_pending)
        if _pending.get("send_intent") and \
                _pending.get("last_outcome") == "unknown" and \
                _alert_window_spent(_pending):
            # Round 19 (Codex delta-18 (b)): the single
            # post-window resend was spent (its flag is marked
            # before the send) but the settle never landed — a
            # crash in between. Settle as sent-unconfirmed NOW,
            # without another attempt: past Resend's retention
            # window a further same-key resend could deliver a
            # second copy, and the rule permits exactly one.
            _log_event_alive(
                order_id, "MONITOR_ALERT_SENT",
                "retained alert settled as sent-unconfirmed: "
                "the Resend idempotency window passed and "
                "the single post-window resend is spent; "
                "not attempted again")
            _gated_send(
                order_id, send_telegram,
                f"ShipAudit Lab: retained monitoring alert "
                f"for {mon['url']} settled as "
                f"sent-unconfirmed "
                f"({len(_pending['new'])} new, "
                f"{len(_pending['gone'])} resolved).")
            with _db_lock:
                conn = db_connect()
                conn.execute(
                    "UPDATE monitors SET pending_alert=NULL, "
                    "last_digest=? WHERE id=?",
                    (json.dumps(_pending["digest_after"]),
                     mon["id"]))
                conn.commit()
                conn.close()
            mon["pending_alert"] = None
            mon["last_digest"] = json.dumps(_pending["digest_after"])
            _pending = None
        if _pending and _pending.get("escalation_intent") and \
                not _pending.get("escalated"):
            _pending["escalated"] = True
            del _pending["escalation_intent"]
            _log_event_alive(
                order_id, "MONITOR_ALERT_ESCALATED",
                "escalation intent on record from an "
                "interrupted run; treated as delivered, "
                "not re-sent")
        if _pending and _pending.get("send_intent") and \
                not _unknown_retry:
            _log_event_alive(
                order_id, "MONITOR_ALERT_SENT",
                "retained alert treated as delivered: "
                "delivery intent on record from an "
                "interrupted run; not re-sent")
            _gated_send(
                order_id, send_telegram,
                f"ShipAudit Lab: retained monitoring alert "
                f"for {mon['url']} delivered "
                f"({len(_pending['new'])} new, "
                f"{len(_pending['gone'])} resolved).")
            with _db_lock:
                conn = db_connect()
                conn.execute(
                    "UPDATE monitors SET pending_alert=NULL, "
                    "last_digest=? WHERE id=?",
                    (json.dumps(_pending["digest_after"]),
                     mon["id"]))
                conn.commit()
                conn.close()
            mon["pending_alert"] = None
            mon["last_digest"] = json.dumps(_pending["digest_after"])
            _pending = None
    if _pending and _alert_window_spent(_pending):
        # Round 19 (delta-18 (b)): the post-window resend is
        # spent and this record reached the send step anyway
        # (its intent was cleared by a later definite failure,
        # so the settle arm above did not claim it). Settle
        # WITHOUT sending: no further attempt is permitted.
        _log_event_alive(
            order_id, "MONITOR_ALERT_SENT",
            "retained alert settled as sent-unconfirmed: "
            "the Resend idempotency window passed and "
            "the single post-window resend is spent; "
            "not attempted again")
        with _db_lock:
            conn = db_connect()
            conn.execute(
                "UPDATE monitors SET pending_alert=NULL, "
                "last_digest=? WHERE id=?",
                (json.dumps(_pending["digest_after"]), mon["id"]))
            conn.commit()
            conn.close()
        mon["pending_alert"] = None
        mon["last_digest"] = json.dumps(_pending["digest_after"])
        _pending = None
    if _pending:
        # Durable delivery intent BEFORE the send (round 16):
        # what a crash can leave behind is the intent, never a
        # silent second delivery. The intent now also carries
        # the alert's idempotency key (round 18), persisted with
        # it, so any retry of this alert re-presents the key.
        # Round 19: when this send is the ONE post-window resend,
        # its spent flag is persisted in the same write, before
        # the send — a crash around the send spends the attempt
        # rather than permitting a second one.
        _final19 = _alert_final_attempt(_pending)
        _pending["send_intent"] = utcnow()
        # Round 21 (Codex delta-19 (a2)): the alert's window
        # stamp is written in THIS pre-send write, first-stamp-
        # wins — round 19 stamped first_unknown_at only when
        # the unknown outcome was recorded, after the send, so
        # a crash between an accepted send and that write left
        # the attempt unstamped (the receipt path's twin fix
        # is _email_note_attempt).
        # Round 22: the stamp is PROVISIONAL for this attempt.
        # The basis is the first UNKNOWN outcome again (the
        # parent rejected the first-attempt widening): if this
        # attempt ends DEFINITELY and the stamp was set by
        # this attempt, the outcome write below removes it
        # again — a definite failure never starts the window.
        # A stamp locked by an earlier unknown is never
        # removed; an attempt whose outcome is never recorded
        # keeps it (the crash arm).
        _fua_pre22 = _pending.get("first_unknown_at")
        if not _pending.get("first_unknown_at"):
            _pending["first_unknown_at"] = time.time()
        if _final19:
            _pending["post_window_used"] = 1
        if not _pending.get("idem"):
            _pending["idem"] = _monitor_alert_idem(mon, _pending)
        with _db_lock:
            conn = db_connect()
            conn.execute(
                "UPDATE monitors SET pending_alert=? WHERE id=?",
                (json.dumps(_pending), mon["id"]))
            conn.commit()
            conn.close()
        if not _monitor_alive(mon["id"]):
            # The send seam (round 21): the monitor (and its
            # order) was deleted mid-run — drop the work; no
            # alert send is attempted and no state is written
            # for a monitor that no longer exists.
            return
        _pres = _send_monitor_alert(mon, host, order_id, _pending)
        _pstatus = _send_status(_pres)
        _pdet = _pres[1]
        if _pstatus != "delivered" and _final19:
            # Round 19: the post-window resend settles the
            # alert WHATEVER its outcome — no retry bookkeeping,
            # no escalation, no further attempt. The digest
            # advances exactly as for a reconciled delivery.
            _log_event_alive(
                order_id, "MONITOR_ALERT_SENT",
                "retained alert settled as sent-unconfirmed: "
                f"the single post-window resend ended "
                f"{_pstatus} ({_pdet}); not attempted again")
            with _db_lock:
                conn = db_connect()
                conn.execute(
                    "UPDATE monitors SET pending_alert=NULL, "
                    "last_digest=? WHERE id=?",
                    (json.dumps(_pending["digest_after"]),
                     mon["id"]))
                conn.commit()
                conn.close()
            mon["pending_alert"] = None
            mon["last_digest"] = json.dumps(_pending["digest_after"])
            return
        if _pstatus != "delivered":
            _attempts = int(_pending.get("attempts", 1)) + 1
            _pending["attempts"] = _attempts
            if _pstatus == "unknown":
                # Round 18: the outcome is recorded AS unknown —
                # the intent stays on record together with it,
                # and the next run retries under the same
                # idempotency key instead of reconciling the
                # alert as delivered. Round 19: the FIRST unknown
                # outcome also starts the post-window clock
                # (first_unknown_at, stamped once).
                _pending["last_outcome"] = "unknown"
                if not _pending.get("first_unknown_at"):
                    _pending["first_unknown_at"] = time.time()
            else:
                _pending.pop("send_intent", None)
                _pending.pop("last_outcome", None)
                # Round 22: a definite outcome also removes
                # the provisional stamp THIS attempt set (see
                # the pre-send write) — definite failures never
                # start the window. A stamp locked by an
                # earlier unknown outcome stays.
                if not _fua_pre22:
                    _pending.pop("first_unknown_at", None)
            # The outcome is known: persist it FIRST, so a crash
            # from here on cannot be misread by the
            # reconciliation above as an interrupted delivery.
            with _db_lock:
                conn = db_connect()
                conn.execute(
                    "UPDATE monitors SET pending_alert=? "
                    "WHERE id=?",
                    (json.dumps(_pending), mon["id"]))
                conn.commit()
                conn.close()
            _log_event_alive(
                order_id, "MONITOR_ALERT_FAILED",
                f"retained alert attempt {_attempts} "
                f"({_pstatus}): {_pdet}")
            if _attempts >= 3 and not _pending.get("escalated"):
                # Durable escalation intent, persisted with the
                # attempt bookkeeping, BEFORE the send (round
                # 16): a crash after delivery must not
                # re-escalate.
                _pending["escalation_intent"] = True
                with _db_lock:
                    conn = db_connect()
                    conn.execute(
                        "UPDATE monitors SET pending_alert=?, "
                        "next_run_at=? WHERE id=?",
                        (json.dumps(_pending),
                         time.time() + 3600, mon["id"]))
                    conn.commit()
                    conn.close()
                # Round 22 (Codex delta-20): this escalation
                # send had NO existence check at all in round
                # 21 — round 22 put it behind the tombstone
                # gate. Round 23: it goes through the ATOMIC
                # seam like every other send — gate and HTTP
                # call in one critical section; an abort
                # (None) means the order was deleted after
                # the failed attempt: no escalation starts,
                # and the escalated bookkeeping below is
                # skipped with it (the persists that follow
                # write to a monitor row the delete
                # transaction already removed).
                _eres = _gated_send(
                    order_id, send_telegram,
                    f"ShipAudit Lab: monitoring alert for "
                    f"{mon['url']} UNDELIVERED after 3 "
                    f"attempts ({_pdet}); digest held, "
                    f"weekly retries continue. Check the "
                    f"mail pipeline.")
                if _eres is not None:
                    _estatus = _send_status(_eres)
                    if _estatus == "delivered":
                        _pending["escalated"] = True
                        _log_event_alive(
                            order_id, "MONITOR_ALERT_ESCALATED",
                            "retained alert undelivered after 3 "
                            "attempts; hourly retries stop, "
                            "weekly retries continue")
                    elif _estatus == "unknown":
                        # Telegram is at-most-once (round 18):
                        # an ambiguous outcome counts as
                        # delivered and is never re-escalated.
                        _pending["escalated"] = True
                        _log_event_alive(
                            order_id, "MONITOR_ALERT_ESCALATED",
                            "escalation transport outcome "
                            "unknown; treated as delivered, not "
                            "re-sent")
                del _pending["escalation_intent"]
            with _db_lock:
                conn = db_connect()
                conn.execute(
                    "UPDATE monitors SET pending_alert=?, "
                    "next_run_at=? WHERE id=?",
                    (json.dumps(_pending),
                     time.time() + (3600
                                    if _attempts < 3
                                    or not _pending.get("escalated")
                                    else MONITOR_INTERVAL),
                     mon["id"]))
                conn.commit()
                conn.close()
            _log_event_alive(order_id, "MONITOR_ALERT_RETRY",
                             f"attempt {_attempts}; digest held")
            return
        _log_event_alive(order_id, "MONITOR_ALERT_SENT",
                         f"retained alert delivered: {_pdet}")
        _gated_send(
            order_id, send_telegram,
            f"ShipAudit Lab: retained monitoring alert for "
            f"{mon['url']} delivered ({len(_pending['new'])} new, "
            f"{len(_pending['gone'])} resolved).")
        with _db_lock:
            conn = db_connect()
            conn.execute(
                "UPDATE monitors SET pending_alert=NULL, "
                "last_digest=? WHERE id=?",
                (json.dumps(_pending["digest_after"]), mon["id"]))
            conn.commit()
            conn.close()
        mon["pending_alert"] = None
        mon["last_digest"] = json.dumps(_pending["digest_after"])
    guard = _guard_public_target(host)
    if guard:
        log_event(order_id, "MONITOR_ERROR", f"target refused: {guard}")
        _gated_send(
            order_id, send_telegram,
            f"ShipAudit Lab: monitoring rescan of {mon['url']} "
            f"refused by the SSRF guard ({guard}); retry in 24h.")
        _monitor_reschedule(mon["id"], time.time() + 86400)
        return
    try:
        with _monitor_scan_lock:
            findings, meta = _scan_with_timeout("https://" + host)
    except Exception as e:
        log_event(order_id, "MONITOR_ERROR", f"scan crashed: {e!r}")
        _gated_send(
            order_id, send_telegram,
            f"ShipAudit Lab: monitoring rescan of {mon['url']} "
            f"CRASHED ({e!r}); retry in 24h.")
        _monitor_reschedule(mon["id"], time.time() + 86400)
        return
    if meta.get("errors") and not findings:
        log_event(order_id, "MONITOR_ERROR",
                  f"scan returned errors only: {meta.get('errors')}")
        _monitor_reschedule(mon["id"], time.time() + 86400)
        return
    findings.sort(key=lambda x: SEV_ORDER.get(x["severity"], 9))
    grade, score = score_findings(findings)
    results = {
        "tool": "widecheck 1.1 (shipauditlab server port)",
        "generated_at": utcnow(),
        "note": "Monitoring rescan - surface evidence.",
        "targets": [meta],
        "findings": findings,
    }
    with _db_lock:
        conn = db_connect()
        cur = conn.execute(
            "INSERT INTO scans(created_at,url,email,grade,score,"
            "results_json) VALUES(?,?,?,?,?,?)",
            (utcnow(), mon["url"], mon["email"], grade, score,
             json.dumps(results)))
        scan_id = cur.lastrowid
        conn.commit()
        conn.close()
    digest = sorted({_finding_key(f) for f in findings})
    prev = None
    if mon.get("last_digest"):
        try:
            prev = json.loads(mon["last_digest"])
        except Exception:
            prev = None
    pending = None
    if mon.get("pending_alert"):
        try:
            pending = json.loads(mon["pending_alert"])
        except Exception:
            pending = None
    def _save_mon(digest_json, next_run, pending_json):
        with _db_lock:
            conn = db_connect()
            conn.execute(
                "UPDATE monitors SET last_run_at=?, last_scan_id=?, "
                "last_digest=?, next_run_at=?, pending_alert=? "
                "WHERE id=?",
                (time.time(), scan_id, digest_json, next_run,
                 pending_json, mon["id"]))
            conn.commit()
            conn.close()

    now = time.time()
    # This scan's own diff, against what the client was last told.
    # (A retained alert, if any, was already delivered at the top of
    # this run and last_digest advanced to its digest_after there.)
    if prev is None:
        _save_mon(json.dumps(digest), now + MONITOR_INTERVAL, None)
        log_event(order_id, "MONITOR_BASELINE",
                  f"grade={grade} score={score} findings={len(digest)}")
        _gated_send(
            order_id, send_telegram,
            f"ShipAudit Lab: monitoring baseline set for {mon['url']} - "
            f"grade {grade} ({score}), {len(digest)} findings. "
            "Weekly rescans from here.")
        return
    new = [d for d in digest if d not in prev]
    gone = [d for d in prev if d not in digest]
    if not new and not gone:
        _save_mon(json.dumps(digest), now + MONITOR_INTERVAL, None)
        log_event(order_id, "MONITOR_RESCAN",
                  f"no changes; grade={grade} score={score}")
        return
    log_event(order_id, "MONITOR_CHANGED",
              f"new={len(new)} resolved={len(gone)} "
              f"grade={grade} score={score}")
    # Durable intent BEFORE the send (round 16): the retained
    # record — with its delivery intent — is persisted first, so
    # a crash after delivery leaves the evidence the retained
    # path at the top of the next run reconciles, instead of a
    # second delivery. The outcome is persisted the moment the
    # send returns, before any other post-send work. Round 18:
    # the record also carries the alert's idempotency key, and
    # an UNKNOWN outcome keeps the intent with the outcome
    # recorded — the retained path then retries under the same
    # key rather than reconciling the alert as delivered.
    retained = {"new": new, "gone": gone, "grade": grade,
                "score": score, "digest_after": digest,
                "attempts": 1, "since": utcnow(),
                "send_intent": utcnow(),
                # Round 21 (Codex delta-19 (a2)): the window
                # stamp rides the pre-send record itself (see
                # the retained path) — a crash after an accepted
                # send can no longer leave the attempt unstamped.
                "first_unknown_at": time.time()}
    retained["idem"] = _monitor_alert_idem(mon, retained)
    _save_mon(json.dumps(prev), now + 3600, json.dumps(retained))
    if not _monitor_alive(mon["id"]):
        # The send seam (round 21): the monitor (and its
        # order) was deleted while this run scanned — drop
        # the work; no alert send is attempted.
        return
    res = _send_monitor_alert(mon, host, order_id, retained)
    status = _send_status(res)
    detail = res[1]
    if status == "delivered":
        _save_mon(json.dumps(digest), now + MONITOR_INTERVAL, None)
    elif status == "unknown":
        retained["last_outcome"] = "unknown"
        # Round 19: the first unknown outcome starts the
        # post-window clock for this alert. Round 21: the
        # stamp was already written with the pre-send record
        # above (first-stamp-wins); this arm only backstops a
        # record that somehow reaches here without one.
        if not retained.get("first_unknown_at"):
            retained["first_unknown_at"] = time.time()
        _save_mon(json.dumps(prev), now + 3600, json.dumps(retained))
    else:
        del retained["send_intent"]
        # Round 22: the record is new and its stamp was this
        # attempt's — a definite outcome removes it with the
        # intent (definite failures never start the window;
        # see the retained path's twin arm).
        retained.pop("first_unknown_at", None)
        _save_mon(json.dumps(prev), now + 3600, json.dumps(retained))
    _log_event_alive(
        order_id,
        "MONITOR_ALERT_SENT" if status == "delivered"
        else "MONITOR_ALERT_FAILED",
        detail if status != "unknown"
        else f"transport outcome unknown: {detail}")
    _gated_send(
        order_id, send_telegram,
        f"ShipAudit Lab: monitoring changes on {mon['url']} - "
        f"{len(new)} new, {len(gone)} resolved; grade {grade} "
        f"({score}). Client alert: "
        f"{'SENT' if status == 'delivered' else 'FAILED - ' + detail}")
    if status != "delivered":
        _log_event_alive(order_id, "MONITOR_ALERT_RETRY",
                         "attempt 1; alert retained, digest held")


def _monitor_tick():
    """One production scheduler pass (round 19): the due
    monitor runs, THEN the pending-notification driver — each
    in its own exception isolation, so a failure in either can
    neither kill the scheduler nor starve the other. Before
    round 19 the driver ran only inside the startup sweep, so
    a notification that went pending while the process lived
    (a definite Telegram rejection, healed minutes later)
    could wait for a restart that might never come (Codex
    delta-18 (c1)). The tick is separately callable so the
    wiring itself is pinnable in the catalog.

    Round 20: the tick ALSO runs the paid-side-effects sweep
    (sweep_paid_side_effects — the same function main() runs
    at startup, unmodified) in its own isolation leg between
    the monitor runs and the driver. Round 19 wired only the
    notification driver in here; pending RECEIPTS were still
    driven solely by webhook consults and the startup sweep,
    so a receipt whose outcome went unknown could sit dormant
    once Stripe's webhook retries were exhausted — its
    bounded post-window attempt (round 19) never made until
    someone opened the order or the process restarted. The
    sweep's own tail already drives pending notifications, so
    the driver leg below remains as the final resolver; both
    are idempotent."""
    try:
        with _db_lock:
            conn = db_connect()
            conn.row_factory = sqlite3.Row
            due = conn.execute(
                "SELECT * FROM monitors WHERE active=1 "
                "AND next_run_at<=? ORDER BY next_run_at",
                (time.time(),)).fetchall()
            conn.close()
        for mon in due:
            # Round 21 (Codex delta-19 (a3)): each monitor run
            # is isolated — before, the loop shared the leg's
            # one exception handler, so an exception in one
            # monitor's run skipped every later monitor of the
            # tick. The leg's handler below now covers only
            # the due-snapshot query.
            try:
                _run_monitor(dict(mon), scheduled=True)
            except Exception as e:
                log(f"monitor loop: monitor {mon['id']} run "
                    f"failed: {e!r}")
    except Exception as e:
        log(f"monitor loop error: {e!r}")
    try:
        sweep_paid_side_effects()
    except Exception as e:
        log(f"paid side-effects sweep error: {e!r}")
    try:
        _drive_pending_notifications()
    except Exception as e:
        log(f"pending-notification driver error: {e!r}")


def _monitor_loop():
    while True:
        _monitor_tick()
        time.sleep(MONITOR_TICK)


def main():
    # Warm the DB so a bad path fails loudly at boot, not on first order.
    conn = db_connect()
    conn.close()
    try:
        sweep_paid_side_effects()
    except Exception as e:
        log(f"boot sweep failed: {e!r}")
    if os.environ.get("VF_MONITORING", "1") != "0":
        threading.Thread(target=_monitor_loop, daemon=True,
                         name="monitor-loop").start()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    sys.stderr.write(f"vibefort server listening on :{PORT}, db={DB_PATH}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
