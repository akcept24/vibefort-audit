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

import datetime
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
_db_lock = threading.Lock()
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
    try:
        with _db_lock:
            conn = db_connect()
            conn.execute(
                "INSERT INTO events(created_at,order_id,event,detail)"
                " VALUES(?,?,?,?)", (utcnow(), order_id, event, detail))
            conn.commit()
            conn.close()
    except Exception as e:
        log(f"event-log write failed: {e!r}")
    log(f"order={order_id} event={event} {detail}")


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Outbound notifications
# ---------------------------------------------------------------------------
def send_resend(to, subject, text, html=None):
    """Returns (ok, detail). Never raises. When html is given the
    mail goes out multipart: the plain-text body is preserved
    byte-for-byte and the branded HTML renders alongside it."""
    if not RESEND_API_KEY:
        return False, "RESEND_API_KEY not configured"
    body = {"from": MAIL_FROM, "to": [to],
            "subject": subject, "text": text}
    if html:
        body["html"] = html
    payload = json.dumps(body).encode()
    req = urllib.request.Request(
        "https://api.resend.com/emails", data=payload, method="POST",
        headers={"Authorization": f"Bearer {RESEND_API_KEY}",
                 "Content-Type": "application/json",
                 "User-Agent": "vibefort-server/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read().decode("utf-8", "replace"))
            return True, str(body.get("id", "sent"))
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            detail = ""
        return False, f"HTTP {e.code}: {detail}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def send_telegram(text):
    """Known-working pattern on this machine: urllib POST (curl hangs)."""
    if not TELEGRAM_BOT_TOKEN:
        return False, "TELEGRAM_BOT_TOKEN not configured"
    data = urllib.parse.urlencode(
        {"chat_id": TELEGRAM_CHAT_ID, "text": text}).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read().decode("utf-8", "replace"))
            return bool(body.get("ok")), str(body.get("ok"))
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


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
                                "order_id=NULL WHERE event_id=?",
                                (eid,))
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
                    # unlinks after a successful alert.
                    lost_claim = True
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
                send_telegram(
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
            # link come off (delta-10 #2).
            with _db_lock:
                conn = db_connect()
                conn.execute(
                    "UPDATE stripe_events SET order_id=NULL "
                    "WHERE event_id=?", (eid,))
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
        with _db_lock:
            conn = db_connect()
            try:
                if kind == "orders":
                    cur = conn.execute("DELETE FROM orders WHERE id=?",
                                       (oid,))
                    if cur.rowcount:
                        conn.execute(
                            "DELETE FROM events WHERE order_id=?", (oid,))
                        conn.execute(
                            "DELETE FROM monitors WHERE order_id=?", (oid,))
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
        alert_ok, alert_detail = send_resend(
            ALERT_EMAIL,
            f"New brief: {clean['tier']} ({amount_label}) — {clean['url']}",
            alert_text)
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
        confirm_ok, confirm_detail = send_resend(
            clean["email"],
            f"We received your brief — {clean['tier']}", confirm_text,
            html=confirm_html)
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
        tg_ok, tg_detail = send_telegram(tg_text)
        log_event(order_id, "TELEGRAM_SENT" if tg_ok else "TELEGRAM_FAILED",
                  tg_detail)

        if not tg_ok:
            # Last-resort loud channel: email HQ about the Telegram failure
            # (and restate the email results, in case those failed too).
            fb_ok, fb_detail = send_resend(
                ALERT_EMAIL,
                f"DELIVERY PROBLEM: Telegram alert failed for brief #{order_id}",
                f"The Telegram alert for brief #{order_id} "
                f"({clean['tier']}, {clean['url']}) FAILED: {tg_detail}\n"
                f"Alert email: {'SENT' if alert_ok else 'FAILED — ' + alert_detail}\n"
                f"Client confirmation: {'SENT' if confirm_ok else 'FAILED — ' + confirm_detail}\n"
                f"The order IS stored in the register (id {order_id}).")
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
        # order (Codex delta-5 finding 2).
        ensure_paid_side_effects(row)
    with _db_lock:
        conn = db_connect()
        try:
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
    (Codex delta-6 finding 2)."""
    log_event(order_id, "SIDE_EFFECTS_OK",
              f"tier={tier}" + (f" {note}" if note else ""))
    if not _paid_effects_done(order_id):
        raise RuntimeError(
            "SIDE_EFFECTS_OK marker did not persist; the paid "
            "side effects are not treated as complete")


def ensure_paid_side_effects(order):
    """Re-fire a PAID order's side effects when their completion was
    never recorded. No-op when SIDE_EFFECTS_OK is already logged."""
    if _paid_effects_done(order["id"]):
        return
    if order["tier"] == "Monitoring":
        activate_monitor(order)
    if order["tier"] == "Deep Scan":
        on_deep_scan_paid(order)
    _record_effects_ok(order["id"], order["tier"], "(recovered)")


def sweep_paid_side_effects():
    """Boot sweep: every PAID order gets its side-effect completion
    verified (and re-fired if missing), and
    every matched Stripe event gets its receipt email verified (and
    resent if it never landed). Idempotent; runs once at startup."""
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
                        "WHERE event_id=?", (row["ev_id"],))
                    conn.commit()
                    conn.close()
            except Exception as e:
                log(f"boot sweep: settle for pi-less event "
                    f"{row['ev_id']} deferred: {e!r}")
            continue
        try:
            transition_order_status(
                dict(row), "PAID", paid_event_id=row["ev_id"],
                paid_pi=row["ev_pi"])
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
            # Never tell a payer the audit is queued while the
            # queueing itself failed (Codex delta-5 finding 3):
            # the receipt goes only once the effects are on record.
            if not _paid_effects_done(ev["order_id"]):
                continue
            conn = db_connect()
            conn.row_factory = sqlite3.Row
            orow = conn.execute("SELECT * FROM orders WHERE id=?",
                                (ev["order_id"],)).fetchone()
            conn.close()
            if orow is None:
                continue
            order_d = dict(orow)
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
                # for the next sweep (delta-8 #4).
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
                        "WHERE event_id=?", (ev["event_id"],))
                    conn.commit()
                    conn.close()
                continue
            _ensure_paid_receipt(order_d, ev["amount"])
        except Exception as e:
            log(f"boot sweep: receipt for event {ev['event_id']} "
                f"failed: {e!r}")


def _send_paid_receipt(order, amount_cents):
    """The payment-received email. Logged either way; a failure is
    recoverable — while no PAID_EMAIL_SENT is on record, the boot
    sweep and the webhook recovery consult resend it."""
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
    eok, edet = send_resend(
        order["email"], f"Payment received — {tier}",
        rcpt_text, html=rcpt_html)
    log_event(order["id"],
              "PAID_EMAIL_SENT" if eok else "PAID_EMAIL_FAILED",
              edet)
    return eok


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


def _ensure_paid_receipt(order, amount_cents):
    """True when the receipt is on record as sent (already, or by
    the resend this call performs). The send is single-fire PER
    ORDER (the completion record is per order — Codex delta-9
    #1): two events of one payment, in any processes, contend on
    the same "receipt:<order_id>" lock. A send whose PAID_EMAIL_
    SENT record does not persist counts as not sent (delta-9
    #6). If another holder is mid-send, this returns the
    on-record state and the caller's retry logic re-checks."""
    if _receipt_logged(order["id"]):
        return True
    key = f"receipt:{order['id']}"
    token = _claim_event_lock(key, "receipt")
    if not token:
        return _receipt_logged(order["id"])
    if not _lock_still_mine(key, token):
        return _receipt_logged(order["id"])
    ok = _send_paid_receipt(order, amount_cents)
    if ok and not _receipt_logged(order["id"]):
        ok = False
    if not ok:
        _release_event_lock(key, token)
    return ok


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


def on_deep_scan_paid(order):
    payload = {"order_id": order["id"], "tier": order["tier"],
               "name": order["name"], "email": order["email"],
               "url": order["url"], "amount": order["amount"],
               "queued_at": utcnow()}
    with _db_lock:
        conn = db_connect()
        conn.execute(
            "INSERT OR IGNORE INTO fulfilment_requests(order_id,kind,"
            "payload,status,created_at) VALUES(?,?,?,?,?)",
            (order["id"], "deep_scan", json.dumps(payload), "queued",
             utcnow()))
        conn.commit()
        conn.close()
    log_event(order["id"], "DEEPSCAN_QUEUED",
              "fulfilment request recorded for the engine worker")
    send_telegram(
        f"ShipAudit Lab: Deep Scan order #{order['id']} is PAID — "
        f"fulfilment queued for {order['url']} "
        f"(client {order['email']}).")


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


def activate_monitor(order):
    with _db_lock:
        conn = db_connect()
        conn.execute(
            "INSERT OR IGNORE INTO monitors(order_id,url,email,name,"
            "created_at,next_run_at) VALUES(?,?,?,?,?,?)",
            (order["id"], order["url"], order["email"], order["name"],
             utcnow(), time.time()))
        conn.commit()
        conn.close()
    log_event(order["id"], "MONITOR_ACTIVATED",
              "weekly rescan scheduled; baseline due on next tick")


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


def _run_monitor(mon):
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
        _pbody, _phtml = _monitor_alert_parts(
            mon, host, order_id, _pending["new"], _pending["gone"],
            _pending["grade"], _pending["score"])
        _pok, _pdet = send_resend(
            mon["email"], f"Monitoring: changes detected on {host}",
            _pbody, html=_phtml)
        if not _pok:
            _attempts = int(_pending.get("attempts", 1)) + 1
            _pending["attempts"] = _attempts
            log_event(order_id, "MONITOR_ALERT_FAILED",
                      f"retained alert attempt {_attempts}: {_pdet}")
            if _attempts >= 3 and not _pending.get("escalated"):
                _tok, _ = send_telegram(
                    f"ShipAudit Lab: monitoring alert for "
                    f"{mon['url']} UNDELIVERED after 3 attempts "
                    f"({_pdet}); digest held, weekly retries "
                    f"continue. Check the mail pipeline.")
                if _tok:
                    _pending["escalated"] = True
                    log_event(order_id, "MONITOR_ALERT_ESCALATED",
                              "retained alert undelivered after 3 "
                              "attempts; hourly retries stop, weekly "
                              "retries continue")
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
            log_event(order_id, "MONITOR_ALERT_RETRY",
                      f"attempt {_attempts}; digest held")
            return
        log_event(order_id, "MONITOR_ALERT_SENT",
                  f"retained alert delivered: {_pdet}")
        send_telegram(
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
        send_telegram(f"ShipAudit Lab: monitoring rescan of {mon['url']} "
                      f"refused by the SSRF guard ({guard}); retry in 24h.")
        _monitor_reschedule(mon["id"], time.time() + 86400)
        return
    try:
        with _monitor_scan_lock:
            findings, meta = _scan_with_timeout("https://" + host)
    except Exception as e:
        log_event(order_id, "MONITOR_ERROR", f"scan crashed: {e!r}")
        send_telegram(f"ShipAudit Lab: monitoring rescan of {mon['url']} "
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

    def _attempt(d_new, d_gone, d_grade, d_score):
        body, body_html = _monitor_alert_parts(
            mon, host, order_id, d_new, d_gone, d_grade, d_score)
        return send_resend(
            mon["email"], f"Monitoring: changes detected on {host}",
            body, html=body_html)

    now = time.time()
    # This scan's own diff, against what the client was last told.
    # (A retained alert, if any, was already delivered at the top of
    # this run and last_digest advanced to its digest_after there.)
    if prev is None:
        _save_mon(json.dumps(digest), now + MONITOR_INTERVAL, None)
        log_event(order_id, "MONITOR_BASELINE",
                  f"grade={grade} score={score} findings={len(digest)}")
        send_telegram(
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
    ok, detail = _attempt(new, gone, grade, score)
    log_event(order_id,
              "MONITOR_ALERT_SENT" if ok else "MONITOR_ALERT_FAILED",
              detail)
    send_telegram(
        f"ShipAudit Lab: monitoring changes on {mon['url']} - "
        f"{len(new)} new, {len(gone)} resolved; grade {grade} "
        f"({score}). Client alert: "
        f"{'SENT' if ok else 'FAILED - ' + detail}")
    if ok:
        _save_mon(json.dumps(digest), now + MONITOR_INTERVAL, None)
    else:
        retained = {"new": new, "gone": gone, "grade": grade,
                    "score": score, "digest_after": digest,
                    "attempts": 1, "since": utcnow()}
        _save_mon(json.dumps(prev), now + 3600, json.dumps(retained))
        log_event(order_id, "MONITOR_ALERT_RETRY",
                  "attempt 1; alert retained, digest held")


def _monitor_loop():
    while True:
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
                _run_monitor(dict(mon))
        except Exception as e:
            log(f"monitor loop error: {e!r}")
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
