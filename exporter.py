#!/usr/bin/env python3
"""ShipAudit Lab — fulfilment bridge exporter (sidecar).

Reads Deep Scan fulfilment rows that the site's certified paid hook
writes into the `fulfilment_requests` table (status 'queued') and
drops each payload, verbatim, as a JSON file into the engine robot's
inbox directory. The engine polls that directory; nothing else
connects the two halves.

Hard rules this module lives by:
  * The site DB is opened READ-ONLY (SQLite URI mode=ro). The
    exporter never writes the site's certified tables — it has no
    code path that could.
  * Its only durable state is its OWN ledger file (order_id ->
    payload sha256 + export timestamp), stored outside the site DB.
    Startup CONFIG GUARD: if the ledger path resolves (realpath)
    to the DB path, that is a misconfiguration — the exporter
    writes NOTHING and idles in the retry loop, logging loudly.
  * The output filename comes from the ROW's order_id column (the
    DB's UNIQUE integer), never from the payload. The payload must
    parse and carry an order_id that is a strict int (no bool, no
    float) EQUAL to the row's — any mismatch skips the row.
  * File first, ledger second: write the inbox file atomically
    (temp file in the same directory + fsync + os.replace +
    directory fsync), then record the ledger. Any fsync failure —
    file or directory — FAILS that export (no ledger entry); the
    row is retried on a later pass. A crash between the two
    re-exports on the next pass, which is harmless — the file
    name is deterministic per order and the engine's delivery
    machinery is idempotent by order.
  * Never fatal, never in the way: every error is logged and the
    loop carries on with capped backoff (the exponent is capped
    BEFORE exponentiation, and the poll interval is sanitized at
    startup, so no failure count or bad config can kill the loop).
    The exporter never signals, blocks, or shares fate with
    server.py.

Env contract:
  SITE_DB_PATH        site SQLite DB (default: $VF_DB_PATH or
                      /data/vibefort.db — the image's own default)
  EXPORTER_INBOX_DIR  engine inbox directory (default /data/inbox).
                      Must be a mounted directory in production;
                      the exporter NEVER creates it (a missing
                      mount must stay visible as a logged retry).
  EXPORTER_LEDGER_PATH  exporter ledger file (default
                      /data/exporter-ledger.json, on the site volume)
  EXPORTER_POLL_SEC   poll interval seconds (default 15)
"""

import hashlib
import json
import math
import os
import sqlite3
import sys
import time

BACKOFF_CAP_SEC = 60
DEFAULT_POLL_SEC = 15.0
BACKOFF_MAX_EXPONENT = 10


def log(msg):
    print(f"[exporter] {msg}", file=sys.stderr, flush=True)


def _env(name, default):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def sanitize_poll_sec(raw):
    """Poll interval from config: unparseable, non-finite, or
    <= 0 values fall back to DEFAULT_POLL_SEC (logged). A bad
    value must never be able to kill or spin the loop."""
    try:
        value = float(raw)
    except (TypeError, ValueError):
        log(f"EXPORTER_POLL_SEC {raw!r} is not a number; "
            f"using default {DEFAULT_POLL_SEC:g}s")
        return DEFAULT_POLL_SEC
    if not math.isfinite(value) or value <= 0:
        log(f"EXPORTER_POLL_SEC {raw!r} is not a positive finite "
            f"interval; using default {DEFAULT_POLL_SEC:g}s")
        return DEFAULT_POLL_SEC
    return value


def backoff_delay(poll_sec, failures):
    """Delay after `failures` consecutive failed passes. The
    exponent is capped BEFORE exponentiation, so no failure
    count, however large, can raise OverflowError; the result
    is always within (0, BACKOFF_CAP_SEC]."""
    exponent = min(max(int(failures) - 1, 0), BACKOFF_MAX_EXPONENT)
    return min(BACKOFF_CAP_SEC, poll_sec * (2 ** exponent))


def config_problem(cfg):
    """Returns a description of a fatal misconfiguration, or
    None. The one certified case: the ledger path resolving to
    the DB path — save_ledger would replace the site DB itself
    with ledger JSON, so the exporter must write NOTHING and
    idle instead."""
    ledger_real = os.path.realpath(cfg["ledger_path"])
    db_real = os.path.realpath(cfg["db_path"])
    if ledger_real == db_real:
        return (f"ledger path {cfg['ledger_path']!r} resolves to "
                f"the site DB path {cfg['db_path']!r}")
    return None


def config_from_env():
    return {
        "db_path": _env("SITE_DB_PATH",
                        _env("VF_DB_PATH", "/data/vibefort.db")),
        "inbox_dir": _env("EXPORTER_INBOX_DIR", "/data/inbox"),
        "ledger_path": _env("EXPORTER_LEDGER_PATH",
                            "/data/exporter-ledger.json"),
        "poll_sec": sanitize_poll_sec(_env("EXPORTER_POLL_SEC",
                                           "15")),
    }


# ---------------------------------------------------------------- ledger

def load_ledger(path):
    """Ledger: {str(order_id): {"sha256": ..., "exported_at": ...}}.
    A missing or corrupt ledger is an empty ledger (everything is
    simply re-exported, which is harmless)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except FileNotFoundError:
        return {}
    except Exception as e:
        log(f"ledger unreadable ({e!r}); starting from an empty ledger")
    return {}


def save_ledger(path, ledger):
    # The temp file always lives in the ledger's OWN directory,
    # and the ledger is fsynced (file, then directory) before it
    # counts as recorded. Any fsync failure raises: the caller
    # treats the pass as failed and retries later.
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    tmp = os.path.join(
        parent, f".{os.path.basename(path)}.tmp-{os.getpid()}")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(ledger, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(parent)


# ---------------------------------------------------------------- files

def _fsync_dir(path):
    """fsync a directory, RAISING on any failure. Durability is
    never claimed silently: if the directory entry cannot be
    forced to disk, the export that depended on it has failed
    and must be retried, not recorded."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_atomic(inbox_dir, filename, data):
    """Write `data` to inbox_dir/filename atomically: temp file in
    the SAME directory, fsync, os.replace onto the final name, then
    a directory fsync. The final path is never opened for writing.
    Any fsync failure raises — the export has failed and the
    caller must not record it in the ledger."""
    final_path = os.path.join(inbox_dir, filename)
    tmp_path = os.path.join(
        inbox_dir, f".{filename}.tmp-{os.getpid()}")
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, final_path)
    _fsync_dir(inbox_dir)


# ---------------------------------------------------------------- export

def export_once(db_path, inbox_dir, ledger_path):
    """One pass. Returns {"exported": n, "skipped": n, "errors": n}.
    Raises only for pass-level failures (misconfiguration, DB
    unreadable, inbox missing); per-row failures are counted and
    logged, never raised."""
    problem = config_problem({"db_path": db_path,
                              "ledger_path": ledger_path})
    if problem is not None:
        # Config guard, checked before ANY read or write: with
        # the ledger aimed at the DB itself, proceeding could
        # replace the site DB with ledger JSON. Refuse loudly;
        # the caller (run_loop) backs off and retries forever,
        # so the exporter idles until the config is fixed.
        log(f"MISCONFIGURATION: {problem}; refusing to export — "
            f"nothing will be written")
        raise ValueError(f"misconfiguration: {problem}")
    if not os.path.isdir(inbox_dir):
        raise FileNotFoundError(f"inbox directory missing: {inbox_dir}")
    ledger = load_ledger(ledger_path)
    uri = "file:" + db_path.replace("?", "%3f") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        rows = conn.execute(
            "SELECT order_id, payload FROM fulfilment_requests "
            "WHERE status='queued' ORDER BY id").fetchall()
    finally:
        conn.close()
    stats = {"exported": 0, "skipped": 0, "errors": 0}
    dirty = False
    for row_order_id, payload in rows:
        try:
            # The filename and the ledger key come from the ROW's
            # order_id column (UNIQUE in the schema) — never from
            # the payload, so one row can never name, collide
            # with, or overwrite another order's file.
            if type(row_order_id) is not int:
                raise ValueError(
                    f"row order_id is not an int: {row_order_id!r}")
            data = payload.encode("utf-8") \
                if isinstance(payload, str) else bytes(payload)
            parsed = json.loads(data.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("payload is not a JSON object")
            payload_order_id = parsed.get("order_id")
            # Strict: type(...) is int excludes bool (a subclass)
            # and float; no coercion. The payload must agree with
            # the row it rides on, exactly.
            if type(payload_order_id) is not int \
                    or payload_order_id != row_order_id:
                raise ValueError(
                    f"payload order_id {payload_order_id!r} does "
                    f"not strictly equal row order_id "
                    f"{row_order_id!r}; row skipped")
            digest = hashlib.sha256(data).hexdigest()
            rec = ledger.get(str(row_order_id))
            if rec is not None and rec.get("sha256") == digest:
                stats["skipped"] += 1
                continue
            write_atomic(inbox_dir,
                         f"fulfilment-{row_order_id}.json", data)
            ledger[str(row_order_id)] = {
                "sha256": digest,
                "exported_at": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "row_order_id": row_order_id,
            }
            dirty = True
            stats["exported"] += 1
            log(f"exported order {row_order_id} "
                f"(sha256 {digest[:12]}…)")
        except Exception as e:
            stats["errors"] += 1
            log(f"row order_id={row_order_id!r} skipped: {e!r}")
    if dirty:
        save_ledger(ledger_path, ledger)
    return stats


def run_loop(cfg, stop_event=None):
    """Poll forever (or until stop_event is set). No exception
    terminates the loop: pass failures back off via
    backoff_delay (exponent capped before exponentiation), and
    an outermost guard catches anything else, logs it, sleeps,
    and continues. KeyboardInterrupt / SystemExit still exit —
    they are BaseExceptions, not caught here."""
    failures = 0
    poll_sec = sanitize_poll_sec(cfg.get("poll_sec",
                                         DEFAULT_POLL_SEC))
    while stop_event is None or not stop_event.is_set():
        try:
            try:
                stats = export_once(cfg["db_path"],
                                    cfg["inbox_dir"],
                                    cfg["ledger_path"])
                if stats["exported"] or stats["errors"]:
                    log(f"pass: {stats}")
                failures = 0
                wait = poll_sec
            except Exception as e:
                failures += 1
                wait = backoff_delay(poll_sec, failures)
                log(f"pass failed ({e!r}); retrying in {wait:.1f}s")
            if stop_event is not None:
                stop_event.wait(wait)
            else:
                time.sleep(wait)
        except Exception as e:
            log(f"unexpected loop error ({e!r}); continuing")
            try:
                if stop_event is not None:
                    stop_event.wait(poll_sec)
                else:
                    time.sleep(poll_sec)
            except Exception:
                pass


def main():
    cfg = config_from_env()
    problem = config_problem(cfg)
    if problem is not None:
        log(f"MISCONFIGURATION: {problem}; the exporter will "
            f"write NOTHING and idle in the retry loop until "
            f"the configuration is fixed")
    log(f"starting: db={cfg['db_path']} inbox={cfg['inbox_dir']} "
        f"ledger={cfg['ledger_path']} poll={cfg['poll_sec']}s")
    run_loop(cfg)


if __name__ == "__main__":
    main()
