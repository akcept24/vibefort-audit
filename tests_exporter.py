#!/usr/bin/env python3
"""Catalog for the fulfilment bridge exporter (exporter.py).

Standalone: python3 tests_exporter.py — prints one line per check
and exits non-zero if any check fails. Uses throwaway temp dirs and
a throwaway SQLite DB built with the site's REAL fulfilment_requests
schema (copied from server.py, frozen tree 3e5d1f0).
"""

import builtins
import hashlib
import io
import json
import os
import sqlite3
import stat
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

    # ---- (f) atomic write path — BEHAVIORAL. This REPLACES the
    #           round-1 source-string check, which asserted
    #           nothing behavioural (it searched exporter.py's
    #           text; it never exercised a write). Now: patch
    #           os.replace to raise after the temp file is
    #           written -> the final name must NOT appear; a
    #           pre-existing final file keeps its old bytes; and
    #           opens are recorded to prove the final path is
    #           never opened in a write mode during an export.
    dirF = os.path.join(tmp, "caseF")
    os.makedirs(dirF)
    dbF = os.path.join(dirF, "site.db")
    inboxF = os.path.join(dirF, "inbox")
    os.makedirs(inboxF)
    ledgerF = os.path.join(dirF, "ledger.json")
    make_db(dbF, [(111, payload_for(111), "queued")])
    finalF = os.path.join(inboxF, "fulfilment-111.json")
    opened = []
    real_open = builtins.open

    def recording_open(file, mode="r", *a, **kw):
        opened.append((os.fspath(file), mode))
        return real_open(file, mode, *a, **kw)

    real_replace = os.replace

    def failing_replace(src_p, dst_p):
        raise OSError("simulated replace failure")

    ok_f1 = ok_f2 = False
    builtins.open = recording_open
    os.replace = failing_replace
    try:
        exporter.export_once(dbF, inboxF, ledgerF)
        ok_f1 = not os.path.exists(finalF)
        with real_open(finalF, "wb") as fh:
            fh.write(b"OLD BYTES")
        exporter.export_once(dbF, inboxF, ledgerF)
        with real_open(finalF, "rb") as fh:
            ok_f2 = fh.read() == b"OLD BYTES"
    finally:
        builtins.open = real_open
        os.replace = real_replace
    ok_f3 = all(not (p == finalF and any(c in m for c in "wax+"))
                for p, m in opened)
    check("(f1) replace fails after temp write: the final name "
          "does not appear", ok_f1)
    check("(f2) replace fails: a pre-existing final file keeps "
          "its old bytes", ok_f2)
    check("(f3) the final path is never opened in a write mode "
          "during an export", ok_f3)

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

    # ---- (h) config guard: ledger path == DB path -> refusal.
    #           The exporter must write NOTHING (in particular it
    #           must never let save_ledger replace the site DB
    #           with ledger JSON), log the misconfiguration, and
    #           export nothing.
    dirH = os.path.join(tmp, "caseH")
    os.makedirs(dirH)
    dbH = os.path.join(dirH, "site.db")
    inboxH = os.path.join(dirH, "inbox")
    os.makedirs(inboxH)
    make_db(dbH, [(121, payload_for(121), "queued")])
    with real_open(dbH, "rb") as fh:
        dbH_bytes = fh.read()
    refused = False
    err_buf = io.StringIO()
    old_stderr = sys.stderr
    sys.stderr = err_buf
    try:
        try:
            exporter.export_once(dbH, inboxH, dbH)  # ledger == DB
        except ValueError:
            refused = True
    finally:
        sys.stderr = old_stderr
    with real_open(dbH, "rb") as fh:
        dbH_bytes_after = fh.read()
    check("(h) ledger path == DB path: refusal logged, DB bytes "
          "unchanged, nothing exported, no stray files",
          refused
          and dbH_bytes_after == dbH_bytes
          and os.listdir(inboxH) == []
          and sorted(os.listdir(dirH)) == ["inbox", "site.db"]
          and "MISCONFIGURATION" in err_buf.getvalue())

    # ---- (i) filename comes from the ROW: the payload's
    #           order_id must be a strict int (no bool, no float)
    #           EQUAL to the row's, else the row is skipped with
    #           no file and no ledger entry.
    dirI = os.path.join(tmp, "caseI")
    os.makedirs(dirI)
    dbI = os.path.join(dirI, "site.db")
    inboxI = os.path.join(dirI, "inbox")
    os.makedirs(inboxI)
    ledgerI = os.path.join(dirI, "ledger.json")
    def payload_with(row_id, payload_order_id):
        p = json.loads(payload_for(row_id))
        p["order_id"] = payload_order_id
        return json.dumps(p)

    p135 = json.loads(payload_for(135))
    del p135["order_id"]
    make_db(dbI, [(131, payload_with(131, 132), "queued"),
                  (133, payload_with(133, 133.0), "queued"),
                  (134, payload_with(134, True), "queued"),
                  (135, json.dumps(p135), "queued"),
                  (136, payload_for(136), "queued")])
    stats = exporter.export_once(dbI, inboxI, ledgerI)
    ledI = exporter.load_ledger(ledgerI)
    bad_files = [n for n in ("fulfilment-131.json",
                             "fulfilment-132.json",
                             "fulfilment-133.json",
                             "fulfilment-134.json",
                             "fulfilment-135.json",
                             "fulfilment-1.json")
                 if os.path.exists(os.path.join(inboxI, n))]
    check("(i) mismatched / float / bool / missing payload "
          "order_id skipped (no file, no ledger entry); the "
          "matching row exports under the row's id",
          stats["exported"] == 1 and stats["errors"] == 4
          and bad_files == []
          and os.path.isfile(os.path.join(inboxI,
                                          "fulfilment-136.json"))
          and set(ledI.keys()) == {"136"})

    # ---- (j) directory fsync failure FAILS the export: no
    #           ledger entry for the row; a later pass with
    #           fsync healthy exports it.
    dirJ = os.path.join(tmp, "caseJ")
    os.makedirs(dirJ)
    dbJ = os.path.join(dirJ, "site.db")
    inboxJ = os.path.join(dirJ, "inbox")
    os.makedirs(inboxJ)
    ledgerJ = os.path.join(dirJ, "ledger.json")
    p141 = payload_for(141)
    make_db(dbJ, [(141, p141, "queued")])
    real_fsync = os.fsync

    def dir_failing_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("simulated directory fsync failure")
        return real_fsync(fd)

    os.fsync = dir_failing_fsync
    try:
        statsJ1 = exporter.export_once(dbJ, inboxJ, ledgerJ)
    finally:
        os.fsync = real_fsync
    ledJ1 = exporter.load_ledger(ledgerJ)
    statsJ2 = exporter.export_once(dbJ, inboxJ, ledgerJ)
    ledJ2 = exporter.load_ledger(ledgerJ)
    check("(j) directory fsync failure: export fails with no "
          "ledger entry; a later healthy pass exports the row",
          statsJ1["exported"] == 0 and "141" not in ledJ1
          and statsJ2["exported"] == 1
          and ledJ2.get("141", {}).get("sha256")
          == hashlib.sha256(p141.encode("utf-8")).hexdigest())

    # ---- (k) the loop cannot be killed by arithmetic or config:
    #           backoff_delay caps the exponent BEFORE
    #           exponentiation (no OverflowError at any failure
    #           count, result always within the cap), and an
    #           invalid EXPORTER_POLL_SEC is sanitized to the
    #           default at startup.
    ok_k1 = False
    try:
        delays = [exporter.backoff_delay(15.0, n)
                  for n in (0, 10, 1000, 10 ** 6)]
        ok_k1 = all(0 < d <= exporter.BACKOFF_CAP_SEC
                    for d in delays)
    except Exception:
        ok_k1 = False
    check("(k1) backoff_delay stays within the cap at failure "
          "counts 0 / 10 / 1000 / 10**6 and never raises", ok_k1)
    ok_k2 = False
    saved_poll = os.environ.get("EXPORTER_POLL_SEC")
    try:
        os.environ["EXPORTER_POLL_SEC"] = "not-a-number"
        bad1 = exporter.config_from_env()["poll_sec"]
        os.environ["EXPORTER_POLL_SEC"] = "-5"
        bad2 = exporter.config_from_env()["poll_sec"]
        os.environ["EXPORTER_POLL_SEC"] = "0"
        bad3 = exporter.config_from_env()["poll_sec"]
        os.environ["EXPORTER_POLL_SEC"] = "2.5"
        good = exporter.config_from_env()["poll_sec"]
        ok_k2 = (bad1 == 15 and bad2 == 15 and bad3 == 15
                 and good == 2.5)
    except Exception:
        ok_k2 = False
    finally:
        if saved_poll is None:
            os.environ.pop("EXPORTER_POLL_SEC", None)
        else:
            os.environ["EXPORTER_POLL_SEC"] = saved_poll
    check("(k2) invalid EXPORTER_POLL_SEC (text / negative / "
          "zero) sanitized to the 15s default; a valid value "
          "passes through", ok_k2)

    # ---- (l) config guard, second name: (h) covers ledger ==
    #           DB; a DB sitting at the ledger's TEMP path must
    #           also be refused — save_ledger opens that name
    #           with "w" before the replace and would truncate
    #           the DB. The temp name is built here by hand
    #           (.<ledger basename>.tmp-<pid>, in the ledger's
    #           own directory — the documented naming) so the
    #           specimen exercises the behaviour on any tree,
    #           not a helper's existence.
    dirL = os.path.join(tmp, "caseL")
    os.makedirs(dirL)
    inboxL = os.path.join(dirL, "inbox")
    os.makedirs(inboxL)
    ledgerL = os.path.join(dirL, "ledger.json")
    dbL = os.path.join(
        dirL, f".{os.path.basename(ledgerL)}.tmp-{os.getpid()}")
    make_db(dbL, [(161, payload_for(161), "queued")])
    with real_open(dbL, "rb") as fh:
        dbL_bytes = fh.read()
    refusedL = False
    err_buf = io.StringIO()
    old_stderr = sys.stderr
    sys.stderr = err_buf
    try:
        try:
            exporter.export_once(dbL, inboxL, ledgerL)
        except ValueError:
            refusedL = True
    finally:
        sys.stderr = old_stderr
    dbL_intact = os.path.isfile(dbL)
    if dbL_intact:
        with real_open(dbL, "rb") as fh:
            dbL_intact = fh.read() == dbL_bytes
    check("(l) DB path == ledger TEMP path: refusal logged, "
          "DB bytes unchanged, nothing exported, no ledger "
          "written",
          refusedL and dbL_intact
          and os.listdir(inboxL) == []
          and not os.path.exists(ledgerL)
          and "MISCONFIGURATION" in err_buf.getvalue())

    # ---- (m) ledger DIRECTORY fsync failure AFTER the
    #           replace: the new entry is VISIBLE in the ledger
    #           file, but its durability was never established.
    #           The export counts as FAILED and the entry is
    #           suspect: a later pass re-exports when the inbox
    #           file is missing (arm A) and confirms/skips when
    #           the file is present with a matching hash
    #           (arm B). os.fsync is patched to fail ONLY for
    #           the ledger directory's fd (matched by inode);
    #           the inbox directory and the ledger file fsync
    #           normally.
    def ledger_dir_fsync_case(case_dir, order_id):
        os.makedirs(case_dir)
        dbM = os.path.join(case_dir, "site.db")
        inboxM = os.path.join(case_dir, "inbox")
        os.makedirs(inboxM)
        ledgerM = os.path.join(case_dir, "ledger.json")
        pM = payload_for(order_id)
        make_db(dbM, [(order_id, pM, "queued")])
        ledger_dir_ino = os.stat(case_dir).st_ino
        real_f = os.fsync

        def picky_fsync(fd):
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode) \
                    and st.st_ino == ledger_dir_ino:
                raise OSError(
                    "simulated ledger-dir fsync failure")
            return real_f(fd)

        os.fsync = picky_fsync
        statsM = None
        try:
            statsM = exporter.export_once(dbM, inboxM, ledgerM)
        except Exception:
            statsM = None
        finally:
            os.fsync = real_f
        return statsM, dbM, inboxM, ledgerM, pM

    dirMA = os.path.join(tmp, "caseMA")
    statsMA1, dbMA, inboxMA, ledgerMA, p171 = \
        ledger_dir_fsync_case(dirMA, 171)
    ledMA1 = exporter.load_ledger(ledgerMA)
    f171 = os.path.join(inboxMA, "fulfilment-171.json")
    check("(m1) ledger dir-fsync failure after replace: the "
          "export counts as failed (stats returned, not "
          "raised) although the entry is visible in the "
          "ledger",
          statsMA1 is not None and statsMA1["exported"] == 0
          and statsMA1["errors"] == 1
          and ledMA1.get("171", {}).get("sha256")
          == hashlib.sha256(p171.encode("utf-8")).hexdigest()
          and os.path.isfile(f171))
    os.remove(f171)  # the unconfirmed file is lost
    statsMA2 = exporter.export_once(dbMA, inboxMA, ledgerMA)
    bodyMA = None
    if os.path.isfile(f171):
        with real_open(f171, "rb") as fh:
            bodyMA = fh.read()
    check("(m2) suspect entry + missing inbox file: the row "
          "is RE-EXPORTED despite the visible ledger entry",
          statsMA2["exported"] == 1
          and bodyMA == p171.encode("utf-8"))

    dirMB = os.path.join(tmp, "caseMB")
    statsMB1, dbMB, inboxMB, ledgerMB, p172 = \
        ledger_dir_fsync_case(dirMB, 172)
    f172 = os.path.join(inboxMB, "fulfilment-172.json")
    beforeMB = (sha256_file(f172), os.stat(f172).st_mtime_ns)
    time.sleep(0.02)
    statsMB2 = exporter.export_once(dbMB, inboxMB, ledgerMB)
    afterMB = (sha256_file(f172), os.stat(f172).st_mtime_ns)
    check("(m3) suspect entry + present, hash-matching inbox "
          "file: confirmed and skipped (file untouched)",
          statsMB1 is not None and statsMB1["errors"] == 1
          and statsMB2["skipped"] == 1
          and statsMB2["exported"] == 0 and beforeMB == afterMB)
    os.remove(f172)
    statsMB3 = exporter.export_once(dbMB, inboxMB, ledgerMB)
    check("(m4) once confirmed, the entry has left the "
          "suspect set: a later deletion is the accepted "
          "residual (still skipped, no re-export)",
          statsMB3["skipped"] == 1 and not os.path.exists(f172))

    # ---- (n) sleep overflow + handler fragility: huge finite
    #           poll values are clamped before they can reach
    #           time.sleep (which would raise OverflowError),
    #           and the loop survives a log function that
    #           raises on every call — the outer guard's own
    #           log and recovery sleep are themselves guarded.
    ok_n1 = False
    try:
        ok_n1 = (exporter.sanitize_poll_sec(1e6) == 3600
                 and exporter.sanitize_poll_sec(1e308) == 3600
                 and exporter.sanitize_poll_sec(3600) == 3600
                 and exporter.sanitize_poll_sec(2.5) == 2.5)
    except Exception:
        ok_n1 = False
    check("(n1) sanitize_poll_sec clamps huge finite values "
          "(1e6, 1e308) to the 3600s maximum without raising; "
          "ordinary values pass through", ok_n1)

    dirN = os.path.join(tmp, "caseN")
    os.makedirs(dirN)
    cfgN = {"db_path": os.path.join(dirN, "site.db"),
            "inbox_dir": os.path.join(dirN, "missing-inbox"),
            "ledger_path": os.path.join(dirN, "ledger.json"),
            "poll_sec": 5}
    real_log = exporter.log
    real_sleep = time.sleep
    sleep_calls = {"n": 0}

    def raising_log(msg):
        raise RuntimeError("simulated logging failure")

    def counting_sleep(sec):
        sleep_calls["n"] += 1
        if sleep_calls["n"] >= 4:
            raise KeyboardInterrupt

    exporter.log = raising_log
    time.sleep = counting_sleep
    ki_raised = False
    try:
        exporter.run_loop(cfgN)
    except KeyboardInterrupt:
        ki_raised = True
    except Exception:
        ki_raised = False
    finally:
        exporter.log = real_log
        time.sleep = real_sleep
    check("(n2) run_loop survives a log that raises on every "
          "call: iterations continue (the counting recovery "
          "sleep is reached repeatedly) and the loop exits "
          "only via KeyboardInterrupt",
          ki_raised and sleep_calls["n"] >= 4)

    failed = [n for n, ok in PASS if not ok]
    print(f"\n{len(PASS) - len(failed)}/{len(PASS)} exporter checks pass")
    if failed:
        print("FAILED:", failed)
        sys.exit(1)


if __name__ == "__main__":
    main()
