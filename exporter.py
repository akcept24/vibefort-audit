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
  * File first, ledger second: write the inbox file atomically
    (temp file in the same directory + fsync + os.replace +
    directory fsync), then record the ledger. A crash between the
    two re-exports on the next pass, which is harmless — the file
    name is deterministic per order and the engine's delivery
    machinery is idempotent by order.
  * Never fatal, never in the way: every error is logged and the
    loop carries on with backoff. The exporter never signals,
    blocks, or shares fate with server.py.

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
import os
import sqlite3
import sys
import time

BACKOFF_CAP_SEC = 60


def log(msg):
    print(f"[exporter] {msg}", file=sys.stderr, flush=True)


def _env(name, default):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def config_from_env():
    return {
        "db_path": _env("SITE_DB_PATH",
                        _env("VF_DB_PATH", "/data/vibefort.db")),
        "inbox_dir": _env("EXPORTER_INBOX_DIR", "/data/inbox"),
        "ledger_path": _env("EXPORTER_LEDGER_PATH",
                            "/data/exporter-ledger.json"),
        "poll_sec": float(_env("EXPORTER_POLL_SEC", "15")),
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
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(ledger, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(parent or ".")


# ---------------------------------------------------------------- files

def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_atomic(inbox_dir, filename, data):
    """Write `data` to inbox_dir/filename atomically: temp file in
    the SAME directory, fsync, os.replace onto the final name, then
    a directory fsync. The final path is never opened for writing."""
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
    Raises only for pass-level failures (DB unreadable, inbox
    missing); per-row failures are counted and logged, never raised."""
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
            data = payload.encode("utf-8") \
                if isinstance(payload, str) else bytes(payload)
            parsed = json.loads(data.decode("utf-8"))
            order_id = parsed["order_id"]
            if not isinstance(order_id, int):
                order_id = int(order_id)
            digest = hashlib.sha256(data).hexdigest()
            rec = ledger.get(str(order_id))
            if rec is not None and rec.get("sha256") == digest:
                stats["skipped"] += 1
                continue
            write_atomic(inbox_dir, f"fulfilment-{order_id}.json", data)
            ledger[str(order_id)] = {
                "sha256": digest,
                "exported_at": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "row_order_id": row_order_id,
            }
            dirty = True
            stats["exported"] += 1
            log(f"exported order {order_id} "
                f"(sha256 {digest[:12]}…)")
        except Exception as e:
            stats["errors"] += 1
            log(f"row order_id={row_order_id!r} skipped: {e!r}")
    if dirty:
        save_ledger(ledger_path, ledger)
    return stats


def run_loop(cfg, stop_event=None):
    """Poll forever (or until stop_event is set). Never raises.
    Successful passes wait poll_sec; failures back off
    exponentially (poll_sec, x2, x4, …) up to BACKOFF_CAP_SEC."""
    failures = 0
    while stop_event is None or not stop_event.is_set():
        try:
            stats = export_once(cfg["db_path"], cfg["inbox_dir"],
                                cfg["ledger_path"])
            if stats["exported"] or stats["errors"]:
                log(f"pass: {stats}")
            failures = 0
            wait = cfg["poll_sec"]
        except Exception as e:
            failures += 1
            wait = min(BACKOFF_CAP_SEC,
                       cfg["poll_sec"] * (2 ** (failures - 1)))
            log(f"pass failed ({e!r}); retrying in {wait:.1f}s")
        if stop_event is not None:
            stop_event.wait(wait)
        else:
            time.sleep(wait)


def main():
    cfg = config_from_env()
    log(f"starting: db={cfg['db_path']} inbox={cfg['inbox_dir']} "
        f"ledger={cfg['ledger_path']} poll={cfg['poll_sec']}s")
    run_loop(cfg)


if __name__ == "__main__":
    main()
