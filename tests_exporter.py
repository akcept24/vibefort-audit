#!/usr/bin/env python3
"""Catalog for the fulfilment bridge exporter (exporter.py).

Standalone: python3 tests_exporter.py — prints one line per check
and exits non-zero if any check fails. Uses throwaway temp dirs and
a throwaway SQLite DB built with the site's REAL fulfilment_requests
schema (copied from server.py, frozen tree 3e5d1f0).
"""

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exporter  # noqa: E402

PASS = []


def check(name, ok):
    PASS.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name)


SCHEMA = """CREATE TABLE fulfilment_requests(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER UNIQUE NOT NULL,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    created_at TEXT NOT NULL)"""


def make_db(path, rows):
    conn = sqlite3.connect(path)
    conn.execute(SCHEMA)
    for order_id, payload, status in rows:
        conn.execute(
            "INSERT INTO fulfilment_requests(order_id,kind,payload,"
            "status,created_at) VALUES(?,?,?,?,?)",
            (order_id, "deep_scan", payload, status,
             "2026-11-10T00:00:00Z"))
    conn.commit()
    conn.close()


def payload_for(order_id, **over):
    p = {"order_id": order_id, "tier": "Deep Scan", "name": "T",
         "email": "t@example.com", "url": "https://example.com",
         "amount": 29, "queued_at": "2026-11-10T00:00:00Z"}
    p.update(over)
    return json.dumps(p)


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    tmp = tempfile.mkdtemp(prefix="exporter-test-")
    db = os.path.join(tmp, "site.db")
    inbox = os.path.join(tmp, "inbox")
    ledger = os.path.join(tmp, "ledger.json")
    os.makedirs(inbox)

    # ---- (a) queued row -> inbox file, exact bytes, order_id name
    p62 = payload_for(62)
    make_db(db, [(62, p62, "queued")])
    stats = exporter.export_once(db, inbox, ledger)
    f62 = os.path.join(inbox, "fulfilment-62.json")
    check("(a) queued row produces fulfilment-<order_id>.json",
          stats["exported"] == 1 and os.path.isfile(f62))
    with open(f62, "rb") as f:
        check("(a) file bytes are the payload bytes verbatim",
              f.read() == p62.encode("utf-8"))

    # ---- (b) second pass does not rewrite (content + mtime)
    before = (sha256_file(f62), os.stat(f62).st_mtime_ns)
    time.sleep(0.02)
    stats = exporter.export_once(db, inbox, ledger)
    after = (sha256_file(f62), os.stat(f62).st_mtime_ns)
    check("(b) second pass skips via ledger (no rewrite)",
          stats["exported"] == 0 and stats["skipped"] == 1
          and before == after)

    # ---- (b2) payload change in the DB -> re-export with new bytes
    p62b = payload_for(62, amount=30)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE fulfilment_requests SET payload=? "
                 "WHERE order_id=62", (p62b,))
    conn.commit()
    conn.close()
    stats = exporter.export_once(db, inbox, ledger)
    with open(f62, "rb") as f:
        body = f.read()
    check("(b2) hash change re-exports the new payload",
          stats["exported"] == 1 and body == p62b.encode("utf-8"))

    # ---- (c) other statuses ignored
    make_db(os.path.join(tmp, "site2.db"),
            [(71, payload_for(71), "done"),
             (72, payload_for(72), "cancelled"),
             (73, payload_for(73), "exported")])
    inbox2 = os.path.join(tmp, "inbox2")
    os.makedirs(inbox2)
    stats = exporter.export_once(os.path.join(tmp, "site2.db"),
                                 inbox2, os.path.join(tmp, "l2.json"))
    check("(c) non-queued rows are ignored",
          stats["exported"] == 0 and os.listdir(inbox2) == [])

    # ---- (d) malformed rows skipped, later rows still exported
    db3 = os.path.join(tmp, "site3.db")
    make_db(db3, [(81, "{not json", "queued"),
                  (82, json.dumps({"tier": "Deep Scan"}), "queued"),
                  (83, payload_for(83), "queued")])
    inbox3 = os.path.join(tmp, "inbox3")
    os.makedirs(inbox3)
    stats = exporter.export_once(db3, inbox3,
                                 os.path.join(tmp, "l3.json"))
    check("(d) malformed rows skipped, loop continues to later rows",
          stats["errors"] == 2 and stats["exported"] == 1
          and os.path.isfile(os.path.join(inbox3,
                                          "fulfilment-83.json")))

    # ---- (e) site DB byte-identical after exporter runs
    db4 = os.path.join(tmp, "site4.db")
    make_db(db4, [(91, payload_for(91), "queued")])
    inbox4 = os.path.join(tmp, "inbox4")
    os.makedirs(inbox4)
    h_before = sha256_file(db4)
    exporter.export_once(db4, inbox4, os.path.join(tmp, "l4.json"))
    exporter.export_once(db4, inbox4, os.path.join(tmp, "l4.json"))
    check("(e) site DB file byte-identical after runs (read-only)",
          sha256_file(db4) == h_before)

    # ---- (f) atomic write path: os.replace onto the final name,
    #           the final path is never opened for writing
    src = open(os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "exporter.py"),
        encoding="utf-8").read()
    check("(f) writes go through os.replace onto the final name",
          "os.replace(tmp_path, final_path)" in src
          and 'open(final_path' not in src
          and "open(tmp_path" in src)

    # ---- (g) inbox missing at start: log, retry, export when it
    #           appears (live loop in a thread)
    db5 = os.path.join(tmp, "site5.db")
    make_db(db5, [(95, payload_for(95), "queued")])
    inbox5 = os.path.join(tmp, "inbox5")  # deliberately NOT created
    cfg = {"db_path": db5, "inbox_dir": inbox5,
           "ledger_path": os.path.join(tmp, "l5.json"),
           "poll_sec": 0.2}
    stop = threading.Event()
    t = threading.Thread(target=exporter.run_loop, args=(cfg, stop),
                         daemon=True)
    t.start()
    time.sleep(0.7)
    alive_blocked = t.is_alive() and not os.path.exists(inbox5)
    os.makedirs(inbox5)
    deadline = time.time() + 4
    f95 = os.path.join(inbox5, "fulfilment-95.json")
    while time.time() < deadline and not os.path.isfile(f95):
        time.sleep(0.1)
    stop.set()
    t.join(timeout=3)
    check("(g) missing inbox: exporter survives, retries, exports "
          "once the directory appears",
          alive_blocked and os.path.isfile(f95))

    failed = [n for n, ok in PASS if not ok]
    print(f"\n{len(PASS) - len(failed)}/{len(PASS)} exporter checks pass")
    if failed:
        print("FAILED:", failed)
        sys.exit(1)


if __name__ == "__main__":
    main()
