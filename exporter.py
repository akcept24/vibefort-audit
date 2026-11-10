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
    Startup CONFIG GUARD: if the DB path resolves (realpath) to
    the ledger path OR to the ledger's temp path (the name
    save_ledger writes through), that is a misconfiguration —
    the exporter writes NOTHING and idles in the retry loop,
    logging loudly.
  * The output filename comes from the ROW's order_id column (the
    DB's UNIQUE integer), never from the payload. The payload must
    parse and carry an order_id that is a strict int (no bool, no
    float) EQUAL to the row's — any mismatch skips the row.
  * File first, ledger second: write the inbox file atomically
    (temp file in the same directory + fsync + os.replace +
    directory fsync), then record the ledger. An inbox-side
    fsync failure FAILS that export (no ledger entry); the row
    is retried on a later pass. A LEDGER directory fsync failure
    is subtler: it happens after os.replace, so the new entry
    is already VISIBLE but its durability was never established
    — the export still counts as FAILED, and the entry is held
    in an in-memory SUSPECT set: it is trusted (skipped) only
    after the inbox file is seen to exist with a matching
    sha256, and re-exported otherwise. A crash between the file
    and the ledger re-exports on the next pass, which is
    harmless — the file name is deterministic per order and
    the engine's delivery machinery is idempotent by order.
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
MAX_POLL_SEC = 3600.0
RECOVERY_SLEEP_SEC = 1.0
BACKOFF_MAX_EXPONENT = 10


def log(msg):
    print(f"[exporter] {msg}", file=sys.stderr, flush=True)


def _env(name, default):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def sanitize_poll_sec(raw):
    """Poll interval from config: unparseable, non-finite, or
    <= 0 values fall back to DEFAULT_POLL_SEC (logged); values
    above MAX_POLL_SEC are clamped to it (logged) — a huge but
    finite value (e.g. 1e308) must never reach time.sleep,
    which would raise OverflowError. A bad value must never be
    able to kill or spin the loop."""
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
    if value > MAX_POLL_SEC:
        log(f"EXPORTER_POLL_SEC {raw!r} exceeds the maximum "
            f"{MAX_POLL_SEC:g}s; clamping to {MAX_POLL_SEC:g}s")
        return MAX_POLL_SEC
    return value


def backoff_delay(poll_sec, failures):
    """Delay after `failures` consecutive failed passes. The
    exponent is capped BEFORE exponentiation, so no failure
    count, however large, can raise OverflowError; the result
    is always within (0, BACKOFF_CAP_SEC]."""
    exponent = min(max(int(failures) - 1, 0), BACKOFF_MAX_EXPONENT)
    return min(BACKOFF_CAP_SEC, poll_sec * (2 ** exponent))


def ledger_tmp_path(path):
    """The temp path save_ledger writes through before the
    atomic replace: a dot-file next to the ledger, named from
    the ledger's basename and this process's pid. Computed in
    ONE place so the config guard checks exactly the name the
    writer will use."""
    parent = os.path.dirname(os.path.abspath(path))
    return os.path.join(
        parent, f".{os.path.basename(path)}.tmp-{os.getpid()}")


def config_problem(cfg):
    """Returns a description of a fatal misconfiguration, or
    None. The certified cases: the DB path resolving to the
    ledger path (save_ledger would replace the site DB itself
    with ledger JSON) OR to the ledger's TEMP path (save_ledger
    opens that name with "w" before the replace, truncating
    the DB). Either way the exporter must write NOTHING and
    idle instead."""
    ledger_real = os.path.realpath(cfg["ledger_path"])
    tmp_real = os.path.realpath(ledger_tmp_path(cfg["ledger_path"]))
    db_real = os.path.realpath(cfg["db_path"])
    if ledger_real == db_real:
        return (f"ledger path {cfg['ledger_path']!r} resolves to "
                f"the site DB path {cfg['db_path']!r}")
    if tmp_real == db_real:
        return (f"ledger temp path "
                f"{ledger_tmp_path(cfg['ledger_path'])!r} resolves "
                f"to the site DB path {cfg['db_path']!r}")
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

class LedgerNotDurableError(Exception):
    """The ledger file was replaced, but the directory fsync
    after the replace failed: the new entries are VISIBLE in
    the ledger file, yet their durability was never
    established. Callers must treat those exports as FAILED
    and hold the entries as suspect until the inbox files
    themselves confirm them."""


# In-memory SUSPECT set: (ledger realpath, str(order_id)) for
# entries whose ledger save replaced the file but failed its
# directory fsync. Held across passes for the life of the
# process. A suspect entry is trusted only when the skip
# decision sees the inbox file present with a matching
# sha256; otherwise the row is re-exported.
_SUSPECTS = set()


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
    # The temp file always lives in the ledger's OWN directory
    # (its name comes from ledger_tmp_path — the same helper
    # the config guard checks), and the ledger is fsynced
    # (file, then directory) before it counts as recorded.
    # A failure BEFORE the replace raises as-is: no new entry
    # became visible. A DIRECTORY fsync failure AFTER the
    # replace is different — the entries are already visible
    # but not durable — and raises LedgerNotDurableError so
    # the caller can hold exactly those entries as suspect.
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    tmp = ledger_tmp_path(path)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(ledger, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
        _fsync_dir(parent)
    except Exception as e:
        raise LedgerNotDurableError(
            f"ledger replaced at {path!r} but its directory "
            f"fsync failed: {e!r}") from e


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
    written_keys = []
    ledger_key = os.path.realpath(ledger_path)
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
            skip = False
            if rec is not None and rec.get("sha256") == digest:
                skey = (ledger_key, str(row_order_id))
                if skey not in _SUSPECTS:
                    skip = True
                else:
                    # The entry is visible but its durability
                    # was never established (its save's directory
                    # fsync failed). Trust it only if the inbox
                    # file itself is present with exactly the
                    # recorded hash; then it leaves the suspect
                    # set. Missing or mismatched -> re-export.
                    fpath = os.path.join(
                        inbox_dir, f"fulfilment-{row_order_id}.json")
                    confirmed = False
                    try:
                        with open(fpath, "rb") as fh:
                            confirmed = hashlib.sha256(
                                fh.read()).hexdigest() == digest
                    except OSError:
                        confirmed = False
                    if confirmed:
                        _SUSPECTS.discard(skey)
                        skip = True
                    else:
                        log(f"order {row_order_id}: ledger entry "
                            f"is suspect and the inbox file is "
                            f"missing or mismatched; re-exporting")
            if skip:
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
            written_keys.append(str(row_order_id))
            stats["exported"] += 1
            log(f"exported order {row_order_id} "
                f"(sha256 {digest[:12]}…)")
        except Exception as e:
            stats["errors"] += 1
            log(f"row order_id={row_order_id!r} skipped: {e!r}")
    if dirty:
        try:
            save_ledger(ledger_path, ledger)
        except LedgerNotDurableError as e:
            # The replace already happened, so the new entries
            # are VISIBLE in the ledger file — but the directory
            # fsync failed, so their durability was never
            # established. Those exports count as FAILED here,
            # and the entries join the suspect set: later passes
            # trust them only when the inbox file itself is
            # present with a matching hash, and re-export
            # otherwise.
            for key in written_keys:
                _SUSPECTS.add((ledger_key, key))
                stats["exported"] -= 1
                stats["errors"] += 1
            log(f"ledger save not durable ({e!r}); "
                f"{len(written_keys)} new entries held as "
                f"suspect until the inbox files confirm them")
        else:
            # A fully durable save confirms any of this pass's
            # entries that were suspect (e.g. re-exports).
            for key in written_keys:
                _SUSPECTS.discard((ledger_key, key))
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
            # The handler itself is guarded: its log call may
            # fail (that may be WHY we are here — a failing log
            # inside the pass), and its recovery sleep uses a
            # small constant that cannot overflow. Whatever the
            # handler's own failures, the loop still sleeps and
            # continues — it never spins and never dies here.
            try:
                log(f"unexpected loop error ({e!r}); continuing")
            except Exception:
                pass
            try:
                if stop_event is not None:
                    stop_event.wait(RECOVERY_SLEEP_SEC)
                else:
                    time.sleep(RECOVERY_SLEEP_SEC)
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
