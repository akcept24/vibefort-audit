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

    # ---- (o) the recovery wait cannot be bypassed: if the
    #           sleep primitive raises IMMEDIATELY on every
    #           call, a failed iteration must still consume
    #           its wall-clock recovery delay (the recovery
    #           wait is a monotonic-deadline wait that keeps
    #           attempting small sleeps, swallowing their
    #           failures, until the deadline passes) — never
    #           a busy spin. export_once raises on every pass;
    #           over a ~2.2s window the number of passes must
    #           stay small. (On the pre-round-4 loop the same
    #           setup spins through thousands of passes.)
    dirO = os.path.join(tmp, "caseO")
    os.makedirs(dirO)
    cfgO = {"db_path": os.path.join(dirO, "site.db"),
            "inbox_dir": os.path.join(dirO, "inbox"),
            "ledger_path": os.path.join(dirO, "ledger.json"),
            "poll_sec": 5}
    real_export_once = exporter.export_once
    real_sleep_o = time.sleep
    pass_calls = {"n": 0}
    stop_now_o = threading.Event()
    loop_end_o = {}

    def failing_pass(db_path, inbox_dir, ledger_path):
        pass_calls["n"] += 1
        raise RuntimeError("simulated pass failure")

    def raising_sleep_o(sec):
        if stop_now_o.is_set():
            raise KeyboardInterrupt
        raise RuntimeError("simulated sleep failure")

    def loop_thread_o():
        try:
            exporter.run_loop(cfgO)
            loop_end_o["how"] = "returned"
        except KeyboardInterrupt:
            loop_end_o["how"] = "KeyboardInterrupt"
        except BaseException as e:  # noqa: BLE001
            loop_end_o["how"] = f"other:{e!r}"

    exporter.export_once = failing_pass
    time.sleep = raising_sleep_o
    th_o = threading.Thread(target=loop_thread_o, daemon=True)
    try:
        th_o.start()
        real_sleep_o(2.2)
        passes_in_window = pass_calls["n"]
    finally:
        stop_now_o.set()
        th_o.join(timeout=5)
        exporter.export_once = real_export_once
        time.sleep = real_sleep_o
    check("(o) a recovery/interval sleep that raises "
          "immediately on every call cannot spin the loop: "
          "over a 2.2s window of always-failing passes the "
          "pass count stays <= 5 (each failed iteration waits "
          "out its monotonic recovery deadline), and the loop "
          "still exits via KeyboardInterrupt",
          passes_in_window <= 5
          and loop_end_o.get("how") == "KeyboardInterrupt"
          and not th_o.is_alive())

    # ---- (p) setup is inside the guard: a logger that raises
    #           on EVERY call, combined with an invalid poll
    #           config (so startup sanitization itself wants
    #           to log), cannot prevent run_loop from entering
    #           its loop — sanitization runs inside the
    #           protected structure and every log call in
    #           run_loop's own machinery goes through a
    #           never-raising wrapper. Exit is via a patched
    #           sleep raising KeyboardInterrupt after a few
    #           iterations. (On the pre-round-4 loop,
    #           run_loop died during setup sanitization.)
    dirP = os.path.join(tmp, "caseP")
    os.makedirs(dirP)
    cfgP = {"db_path": os.path.join(dirP, "site.db"),
            "inbox_dir": os.path.join(dirP, "missing-inbox"),
            "ledger_path": os.path.join(dirP, "ledger.json"),
            "poll_sec": "not-a-number"}
    real_log_p = exporter.log
    real_sleep_p = time.sleep
    sleep_calls_p = {"n": 0}

    def raising_log_p(msg):
        raise RuntimeError("simulated logging failure")

    def counting_sleep_p(sec):
        sleep_calls_p["n"] += 1
        if sleep_calls_p["n"] >= 4:
            raise KeyboardInterrupt

    exporter.log = raising_log_p
    time.sleep = counting_sleep_p
    ki_p = False
    other_p = False
    try:
        exporter.run_loop(cfgP)
    except KeyboardInterrupt:
        ki_p = True
    except Exception:
        other_p = True
    finally:
        exporter.log = real_log_p
        time.sleep = real_sleep_p
    check("(p) run_loop enters and completes iterations even "
          "when the logger raises on every call AND the poll "
          "config is invalid (startup sanitization logs): no "
          "exception escapes setup, iterations proceed, and "
          "the loop exits only via KeyboardInterrupt",
          ki_p and not other_p and sleep_calls_p["n"] >= 4)

    # ---- (q) the recovery wait survives a BROKEN monotonic
    #           clock: time.monotonic raises on EVERY call.
    #           The recovery wait is a DUAL-clock wait — a
    #           clock that raises reports no new elapsed for
    #           that slice and the other clock governs — so
    #           the failed iteration still waits out its
    #           recovery delay by the wall clock (~1s between
    #           the first and second pass) and run_loop
    #           carries on. (On the round-4 loop, the
    #           monotonic exception escaped _recovery_wait —
    #           its clock calls sat outside the slice guard —
    #           and killed run_loop outright: no second pass.)
    #           The handler is driven by a flaky stop event
    #           whose FIRST wait() raises (the interval wait
    #           failing is what lands an iteration in the
    #           recovery handler at all).
    dirQ = os.path.join(tmp, "caseQ")
    os.makedirs(dirQ)
    cfgQ = {"db_path": os.path.join(dirQ, "site.db"),
            "inbox_dir": os.path.join(dirQ, "inbox"),
            "ledger_path": os.path.join(dirQ, "ledger.json"),
            "poll_sec": 0.05}
    real_export_once_q = exporter.export_once
    real_monotonic_q = time.monotonic
    pass_times_q = []
    loop_end_q = {}

    class FlakyEventQ:
        """A stop event whose first wait() raises; later
        waits are real short waits on an inner event."""

        def __init__(self):
            self._inner = threading.Event()
            self.wait_calls = 0

        def is_set(self):
            return self._inner.is_set()

        def set(self):
            self._inner.set()

        def wait(self, timeout=None):
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise RuntimeError("simulated interval-wait "
                                   "failure")
            return self._inner.wait(
                min(timeout if timeout is not None else 0.05,
                    0.05))

    stop_q = FlakyEventQ()

    def flaky_pass_q(db_path, inbox_dir, ledger_path):
        pass_times_q.append(time.time())
        if len(pass_times_q) == 1:
            raise RuntimeError("simulated first-pass failure")
        return {"exported": 0, "errors": 0}

    def raising_monotonic_q():
        raise RuntimeError("simulated monotonic failure")

    def loop_thread_q():
        try:
            exporter.run_loop(cfgQ, stop_q)
            loop_end_q["how"] = "returned"
        except BaseException as e:  # noqa: BLE001
            loop_end_q["how"] = f"other:{type(e).__name__}"

    exporter.export_once = flaky_pass_q
    time.monotonic = raising_monotonic_q
    th_q = threading.Thread(target=loop_thread_q, daemon=True)
    try:
        th_q.start()
        deadline_q = time.time() + 6
        while len(pass_times_q) < 2 and time.time() < deadline_q:
            time.sleep(0.02)
        gap_q = (pass_times_q[1] - pass_times_q[0]
                 if len(pass_times_q) >= 2 else 0.0)
    finally:
        stop_q.set()
        th_q.join(timeout=5)
        exporter.export_once = real_export_once_q
        time.monotonic = real_monotonic_q
    check("(q) a time.monotonic that raises on every call "
          "cannot kill the loop: the dual-clock recovery wait "
          "is governed by the wall clock, the gap between the "
          "failed first pass and the second pass is >= 0.8x "
          "the recovery interval, and run_loop returns "
          "cleanly on stop",
          loop_end_q.get("how") == "returned"
          and gap_q >= 0.8 * exporter.RECOVERY_SLEEP_SEC
          and not th_q.is_alive())

    # ---- (r) the recovery wait survives a LYING monotonic
    #           clock: the first read returns the start, every
    #           later read jumps forward by 10**6 seconds.
    #           A dual-clock wait ends only when BOTH clocks
    #           have accumulated the interval, so one clock's
    #           forward jump cannot end it early: the gap
    #           between the failed first pass and the second
    #           pass stays >= 0.8x the recovery interval by
    #           the (honest) wall clock. (On the round-4 loop
    #           the deadline was computed from the jumped
    #           clock alone and the wait ended almost
    #           immediately.) The interval wait is broken via
    #           a size-discriminating fake sleep (waits above
    #           0.2s raise; recovery slices are <= 0.1s and
    #           really sleep) so every iteration lands in the
    #           recovery handler.
    dirR = os.path.join(tmp, "caseR")
    os.makedirs(dirR)
    cfgR = {"db_path": os.path.join(dirR, "site.db"),
            "inbox_dir": os.path.join(dirR, "inbox"),
            "ledger_path": os.path.join(dirR, "ledger.json"),
            "poll_sec": 5}
    real_export_once_r = exporter.export_once
    real_monotonic_r = time.monotonic
    real_sleep_r = time.sleep
    pass_times_r = []
    loop_end_r = {}
    stop_flag_r = threading.Event()
    mono_base_r = real_monotonic_r()
    mono_calls_r = {"n": 0}

    def jumping_monotonic_r():
        mono_calls_r["n"] += 1
        if mono_calls_r["n"] == 1:
            return mono_base_r
        return mono_base_r + 10 ** 6

    def failing_pass_r(db_path, inbox_dir, ledger_path):
        pass_times_r.append(time.time())
        raise RuntimeError("simulated pass failure")

    def fake_sleep_r(sec):
        if stop_flag_r.is_set():
            raise KeyboardInterrupt
        if sec > 0.2:
            raise RuntimeError("simulated interval-wait "
                               "failure")
        real_sleep_r(sec)

    def loop_thread_r():
        try:
            exporter.run_loop(cfgR)
            loop_end_r["how"] = "returned"
        except KeyboardInterrupt:
            loop_end_r["how"] = "KeyboardInterrupt"
        except BaseException as e:  # noqa: BLE001
            loop_end_r["how"] = f"other:{type(e).__name__}"

    exporter.export_once = failing_pass_r
    time.monotonic = jumping_monotonic_r
    time.sleep = fake_sleep_r
    th_r = threading.Thread(target=loop_thread_r, daemon=True)
    try:
        th_r.start()
        real_sleep_r(1.6)
        gap_r = (pass_times_r[1] - pass_times_r[0]
                 if len(pass_times_r) >= 2 else 0.0)
    finally:
        stop_flag_r.set()
        th_r.join(timeout=5)
        exporter.export_once = real_export_once_r
        time.monotonic = real_monotonic_r
        time.sleep = real_sleep_r
    check("(r) a time.monotonic that jumps forward by 10**6s "
          "on its second read cannot end the recovery wait "
          "early: the gap between the failed first pass and "
          "the second pass is >= 0.8x the recovery interval "
          "by the wall clock, and the loop exits only via "
          "KeyboardInterrupt",
          gap_r >= 0.8 * exporter.RECOVERY_SLEEP_SEC
          and loop_end_r.get("how") == "KeyboardInterrupt"
          and not th_r.is_alive())

    # ---- (s) the handler never formats the exception it
    #           caught: an exception whose __repr__ AND
    #           __str__ both raise is raised by the interval
    #           wait (a size-discriminating fake sleep). The
    #           handler's log line must carry only the
    #           exception's TYPE name, obtained defensively —
    #           formatting the instance would raise a second
    #           time INSIDE the handler and escape it without
    #           recovery. Proof of survival: the loop
    #           completes a SECOND pass and exits only via
    #           KeyboardInterrupt. (On the round-4 loop the
    #           handler's f-string formatted {e!r} before the
    #           never-raising log wrapper was reached, and
    #           run_loop died on the first bad wait.)
    dirS = os.path.join(tmp, "caseS")
    os.makedirs(dirS)
    cfgS = {"db_path": os.path.join(dirS, "site.db"),
            "inbox_dir": os.path.join(dirS, "inbox"),
            "ledger_path": os.path.join(dirS, "ledger.json"),
            "poll_sec": 5}
    real_export_once_s = exporter.export_once
    real_sleep_s = time.sleep
    pass_calls_s = {"n": 0}
    loop_end_s = {}

    class BadReprError(Exception):
        def __repr__(self):
            raise RuntimeError("repr is broken")

        def __str__(self):
            raise RuntimeError("str is broken")

    def ok_pass_s(db_path, inbox_dir, ledger_path):
        pass_calls_s["n"] += 1
        return {"exported": 0, "errors": 0}

    def fake_sleep_s(sec):
        if sec > 0.2:
            if pass_calls_s["n"] >= 2:
                raise KeyboardInterrupt
            raise BadReprError()
        real_sleep_s(sec)

    def loop_thread_s():
        try:
            exporter.run_loop(cfgS)
            loop_end_s["how"] = "returned"
        except KeyboardInterrupt:
            loop_end_s["how"] = "KeyboardInterrupt"
        except BaseException as e:  # noqa: BLE001
            loop_end_s["how"] = f"other:{type(e).__name__}"

    exporter.export_once = ok_pass_s
    time.sleep = fake_sleep_s
    th_s = threading.Thread(target=loop_thread_s, daemon=True)
    try:
        th_s.start()
        th_s.join(timeout=8)
    finally:
        exporter.export_once = real_export_once_s
        time.sleep = real_sleep_s
    check("(s) an interval-wait exception whose __repr__ and "
          "__str__ both raise cannot escape the handler: the "
          "handler logs only its type name, the loop "
          "completes a second pass, and exits only via "
          "KeyboardInterrupt",
          pass_calls_s["n"] >= 2
          and loop_end_s.get("how") == "KeyboardInterrupt"
          and not th_s.is_alive())

    # ---- (t) GOVERNING, not vetoing: a clock that read
    #           successfully and then DIES drops out of the
    #           exit set — the other clock governs and the
    #           wait ENDS on its accumulation. Monotonic
    #           reads successfully twice (small elapsed),
    #           then raises forever; the wall clock is
    #           healthy, so the recovery wait must end after
    #           ~the recovery interval by the wall clock and
    #           a second pass must run. (On the round-5 loop
    #           a once-live clock belonged to the exit set
    #           FOREVER: its frozen elapsed vetoed exit and
    #           the wait hung until the stop event — no
    #           second pass inside the window. The window is
    #           bounded and the stop event is set for
    #           cleanup, so the prefix failure is a clean
    #           FAIL, not a hung catalog.) The handler is
    #           driven by a flaky stop event whose FIRST
    #           wait() raises, as in (q).
    dirT = os.path.join(tmp, "caseT")
    os.makedirs(dirT)
    cfgT = {"db_path": os.path.join(dirT, "site.db"),
            "inbox_dir": os.path.join(dirT, "inbox"),
            "ledger_path": os.path.join(dirT, "ledger.json"),
            "poll_sec": 0.05}
    real_export_once_t = exporter.export_once
    real_monotonic_t = time.monotonic
    pass_times_t = []
    loop_end_t = {}

    class FlakyEventT:
        """A stop event whose first wait() raises; later
        waits are real short waits on an inner event."""

        def __init__(self):
            self._inner = threading.Event()
            self.wait_calls = 0

        def is_set(self):
            return self._inner.is_set()

        def set(self):
            self._inner.set()

        def wait(self, timeout=None):
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise RuntimeError("simulated interval-wait "
                                   "failure")
            return self._inner.wait(
                min(timeout if timeout is not None else 0.05,
                    0.05))

    stop_t = FlakyEventT()
    mono_calls_t = {"n": 0}

    def dying_monotonic_t():
        mono_calls_t["n"] += 1
        if mono_calls_t["n"] <= 2:
            return real_monotonic_t()
        raise RuntimeError("simulated monotonic death")

    def flaky_pass_t(db_path, inbox_dir, ledger_path):
        pass_times_t.append(time.time())
        if len(pass_times_t) == 1:
            raise RuntimeError("simulated first-pass failure")
        return {"exported": 0, "errors": 0}

    def loop_thread_t():
        try:
            exporter.run_loop(cfgT, stop_t)
            loop_end_t["how"] = "returned"
        except BaseException as e:  # noqa: BLE001
            loop_end_t["how"] = f"other:{type(e).__name__}"

    exporter.export_once = flaky_pass_t
    time.monotonic = dying_monotonic_t
    th_t = threading.Thread(target=loop_thread_t, daemon=True)
    try:
        th_t.start()
        deadline_t = time.time() + 4
        while len(pass_times_t) < 2 and time.time() < deadline_t:
            time.sleep(0.02)
        gap_t = (pass_times_t[1] - pass_times_t[0]
                 if len(pass_times_t) >= 2 else 0.0)
    finally:
        stop_t.set()
        th_t.join(timeout=5)
        exporter.export_once = real_export_once_t
        time.monotonic = real_monotonic_t
    check("(t) a clock that reads successfully twice and "
          "then dies drops out of the exit set (governing, "
          "not vetoing): the recovery wait ends on the wall "
          "clock's accumulation, a second pass runs with a "
          "gap >= 0.8x the recovery interval, and run_loop "
          "returns cleanly on stop",
          len(pass_times_t) >= 2
          and gap_t >= 0.8 * exporter.RECOVERY_SLEEP_SEC
          and loop_end_t.get("how") == "returned"
          and not th_t.is_alive())

    # ---- (u) READING VALIDATION: a clock reading that is
    #           not a number at all — monotonic returns a
    #           STRING on its first read, valid values
    #           afterwards — is treated as NO reading: it
    #           cannot become a baseline and no arithmetic
    #           is ever attempted on it. The wait completes
    #           by the valid readings and the loop carries
    #           on. (On the round-5 loop the string became
    #           the clock's baseline and the NEXT read's
    #           subtraction raised TypeError, escaping the
    #           recovery handler and killing run_loop.)
    dirU = os.path.join(tmp, "caseU")
    os.makedirs(dirU)
    cfgU = {"db_path": os.path.join(dirU, "site.db"),
            "inbox_dir": os.path.join(dirU, "inbox"),
            "ledger_path": os.path.join(dirU, "ledger.json"),
            "poll_sec": 0.05}
    real_export_once_u = exporter.export_once
    real_monotonic_u = time.monotonic
    pass_times_u = []
    loop_end_u = {}

    class FlakyEventU:
        """A stop event whose first wait() raises; later
        waits are real short waits on an inner event."""

        def __init__(self):
            self._inner = threading.Event()
            self.wait_calls = 0

        def is_set(self):
            return self._inner.is_set()

        def set(self):
            self._inner.set()

        def wait(self, timeout=None):
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise RuntimeError("simulated interval-wait "
                                   "failure")
            return self._inner.wait(
                min(timeout if timeout is not None else 0.05,
                    0.05))

    stop_u = FlakyEventU()
    mono_calls_u = {"n": 0}

    def stringy_monotonic_u():
        mono_calls_u["n"] += 1
        if mono_calls_u["n"] == 1:
            return "not-a-number"
        return real_monotonic_u()

    def flaky_pass_u(db_path, inbox_dir, ledger_path):
        pass_times_u.append(time.time())
        if len(pass_times_u) == 1:
            raise RuntimeError("simulated first-pass failure")
        return {"exported": 0, "errors": 0}

    def loop_thread_u():
        try:
            exporter.run_loop(cfgU, stop_u)
            loop_end_u["how"] = "returned"
        except BaseException as e:  # noqa: BLE001
            loop_end_u["how"] = f"other:{type(e).__name__}"

    exporter.export_once = flaky_pass_u
    time.monotonic = stringy_monotonic_u
    th_u = threading.Thread(target=loop_thread_u, daemon=True)
    try:
        th_u.start()
        deadline_u = time.time() + 6
        while len(pass_times_u) < 2 and time.time() < deadline_u:
            time.sleep(0.02)
        gap_u = (pass_times_u[1] - pass_times_u[0]
                 if len(pass_times_u) >= 2 else 0.0)
    finally:
        stop_u.set()
        th_u.join(timeout=5)
        exporter.export_once = real_export_once_u
        time.monotonic = real_monotonic_u
    check("(u) a non-numeric clock reading (a string) is "
          "no reading at all: it never becomes a baseline, "
          "no subtraction is attempted on it, the recovery "
          "wait completes by the valid readings (gap >= "
          "0.8x the recovery interval), and run_loop "
          "returns cleanly on stop",
          len(pass_times_u) >= 2
          and gap_u >= 0.8 * exporter.RECOVERY_SLEEP_SEC
          and loop_end_u.get("how") == "returned"
          and not th_u.is_alive())

    # ---- (v) the handler embeds only SANITIZED type
    #           names: _describe must return an exact plain
    #           str even when the exception's type name is a
    #           hostile str SUBCLASS whose __format__ raises
    #           (supplied by a hostile metaclass as the
    #           class's __name__), and the loop must survive
    #           such an exception raised by the interval
    #           wait. (On the round-5 loop, _describe
    #           returned the hostile subclass object itself
    #           — isinstance passed — and the handler's
    #           f-string raised on __format__ BEFORE the
    #           never-raising log wrapper was reached,
    #           killing run_loop on the first bad wait.)
    class TrapNameV(str):
        def __format__(self, format_spec=""):
            raise RuntimeError("trapped __format__")

    class TrapMetaV(type):
        @property
        def __name__(cls):
            return TrapNameV("TrapErrorV")

    class TrapErrorV(Exception, metaclass=TrapMetaV):
        pass

    # Unit arm: the label is an exact plain str and a
    # handler-style log line builds without raising.
    describe_ok_v = False
    try:
        label_v = exporter._describe(TrapErrorV())
        line_v = (f"unexpected loop error ({label_v}); "
                  f"continuing")
        describe_ok_v = (type(label_v) is str
                         and "TrapErrorV" in line_v)
    except Exception:
        describe_ok_v = False

    dirV = os.path.join(tmp, "caseV")
    os.makedirs(dirV)
    cfgV = {"db_path": os.path.join(dirV, "site.db"),
            "inbox_dir": os.path.join(dirV, "inbox"),
            "ledger_path": os.path.join(dirV, "ledger.json"),
            "poll_sec": 5}
    real_export_once_v = exporter.export_once
    real_sleep_v = time.sleep
    pass_calls_v = {"n": 0}
    loop_end_v = {}

    def ok_pass_v(db_path, inbox_dir, ledger_path):
        pass_calls_v["n"] += 1
        return {"exported": 0, "errors": 0}

    def fake_sleep_v(sec):
        if sec > 0.2:
            if pass_calls_v["n"] >= 2:
                raise KeyboardInterrupt
            raise TrapErrorV()
        real_sleep_v(sec)

    def loop_thread_v():
        try:
            exporter.run_loop(cfgV)
            loop_end_v["how"] = "returned"
        except KeyboardInterrupt:
            loop_end_v["how"] = "KeyboardInterrupt"
        except BaseException as e:  # noqa: BLE001
            loop_end_v["how"] = f"other:{type(e).__name__}"

    exporter.export_once = ok_pass_v
    time.sleep = fake_sleep_v
    th_v = threading.Thread(target=loop_thread_v, daemon=True)
    try:
        th_v.start()
        th_v.join(timeout=8)
    finally:
        exporter.export_once = real_export_once_v
        time.sleep = real_sleep_v
    check("(v) an exception whose type name is a hostile "
          "str subclass with a trapped __format__ cannot "
          "escape the handler: _describe returns an exact "
          "plain str, the handler log line builds, the loop "
          "completes a second pass, and exits only via "
          "KeyboardInterrupt",
          describe_ok_v
          and pass_calls_v["n"] >= 2
          and loop_end_v.get("how") == "KeyboardInterrupt"
          and not th_v.is_alive())

    # ---- (w) EXACT-FLOAT BOUNDARY: a clock reading that is
    #           a float SUBCLASS whose __sub__ raises must be
    #           disarmed at the read boundary — the accepted
    #           reading is converted to an exact plain float
    #           inside the guard, so no downstream operation
    #           can ever invoke the reading's own operators.
    #           (On the round-6 loop the subclass passed
    #           validation untouched; its trapped __sub__
    #           then raised in the wait's displacement
    #           arithmetic, escaped the recovery handler and
    #           killed run_loop.) Driven like (q)/(t): a
    #           flaky stop event whose first wait() raises
    #           lands the failed first pass in the handler.
    class HostileFloatW(float):
        def __sub__(self, other):
            raise RuntimeError("trapped __sub__")

        def __rsub__(self, other):
            raise RuntimeError("trapped __rsub__")

    converted_w = exporter._read_clock(
        lambda: HostileFloatW(1.5))
    unit_w = type(converted_w) is float and converted_w == 1.5

    dirW = os.path.join(tmp, "caseW")
    os.makedirs(dirW)
    cfgW = {"db_path": os.path.join(dirW, "site.db"),
            "inbox_dir": os.path.join(dirW, "inbox"),
            "ledger_path": os.path.join(dirW, "ledger.json"),
            "poll_sec": 0.05}
    real_export_once_w = exporter.export_once
    real_monotonic_w = time.monotonic
    pass_times_w = []
    loop_end_w = {}

    class FlakyEventW:
        """A stop event whose first wait() raises; later
        waits are real short waits on an inner event."""

        def __init__(self):
            self._inner = threading.Event()
            self.wait_calls = 0

        def is_set(self):
            return self._inner.is_set()

        def set(self):
            self._inner.set()

        def wait(self, timeout=None):
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise RuntimeError("simulated interval-wait "
                                   "failure")
            return self._inner.wait(
                min(timeout if timeout is not None else 0.05,
                    0.05))

    stop_w = FlakyEventW()

    def hostile_monotonic_w():
        return HostileFloatW(real_monotonic_w())

    def flaky_pass_w(db_path, inbox_dir, ledger_path):
        pass_times_w.append(time.time())
        if len(pass_times_w) == 1:
            raise RuntimeError("simulated first-pass failure")
        return {"exported": 0, "errors": 0}

    def loop_thread_w():
        try:
            exporter.run_loop(cfgW, stop_w)
            loop_end_w["how"] = "returned"
        except BaseException as e:  # noqa: BLE001
            loop_end_w["how"] = f"other:{type(e).__name__}"

    exporter.export_once = flaky_pass_w
    time.monotonic = hostile_monotonic_w
    th_w = threading.Thread(target=loop_thread_w, daemon=True)
    try:
        th_w.start()
        deadline_w = time.time() + 6
        while len(pass_times_w) < 2 and time.time() < deadline_w:
            time.sleep(0.02)
        gap_w = (pass_times_w[1] - pass_times_w[0]
                 if len(pass_times_w) >= 2 else 0.0)
    finally:
        stop_w.set()
        th_w.join(timeout=5)
        exporter.export_once = real_export_once_w
        time.monotonic = real_monotonic_w
    check("(w) a float-subclass clock reading whose __sub__ "
          "raises is converted to an exact plain float at "
          "the read boundary: _read_clock returns an exact "
          "float, no subtraction can invoke the trapped "
          "operator, the recovery wait completes (gap >= "
          "0.8x the recovery interval), and run_loop returns "
          "cleanly on stop",
          unit_w
          and len(pass_times_w) >= 2
          and gap_w >= 0.8 * exporter.RECOVERY_SLEEP_SEC
          and loop_end_w.get("how") == "returned"
          and not th_w.is_alive())

    # ---- (x) ZERO-PROGRESS DROP: a FROZEN clock — readings
    #           succeed but the value never advances — is
    #           excluded the moment the other clock reaches
    #           the interval, so the wait ENDS on the
    #           reaching clock instead of spinning in the
    #           window forever. Driven at the wait itself,
    #           with every sleep primitive failing (a busy
    #           window) and a healthy wall clock. (On the
    #           round-6 loop the frozen clock stayed in the
    #           exit set with a stale zero accumulation and
    #           vetoed exit indefinitely.) The frozen fake
    #           is stateful: cleanup unfreezes it with a
    #           large forward offset (so a still-waiting
    #           old-tree thread can exit), which keeps the
    #           prefix failure a clean FAIL, not a hang.
    real_monotonic_x = time.monotonic
    real_sleep_x = time.sleep
    frozen_x = {"on": True}

    def frozen_monotonic_x():
        if frozen_x["on"]:
            return 424242.0
        return real_monotonic_x() + 500000.0

    def raising_sleep_x(sec):
        raise RuntimeError("simulated sleep failure")

    wait_end_x = {}

    def wait_thread_x():
        t0 = time.time()
        exporter._recovery_wait(None)
        wait_end_x["elapsed"] = time.time() - t0

    time.monotonic = frozen_monotonic_x
    time.sleep = raising_sleep_x
    th_x = threading.Thread(target=wait_thread_x, daemon=True)
    elapsed_x = None
    returned_x = False
    try:
        th_x.start()
        th_x.join(timeout=3.0)
        elapsed_x = wait_end_x.get("elapsed")
        returned_x = elapsed_x is not None and not th_x.is_alive()
    finally:
        frozen_x["on"] = False
        th_x.join(timeout=5)
        time.monotonic = real_monotonic_x
        time.sleep = real_sleep_x
    check("(x) a frozen clock (readings succeed, value "
          "never advances) is dropped once the other clock "
          "reaches the interval: with all sleep primitives "
          "failing, the recovery wait still ENDS at ~the "
          "wall duration (0.8x-3x the recovery interval) "
          "instead of spinning in the window forever",
          returned_x
          and elapsed_x >= 0.8 * exporter.RECOVERY_SLEEP_SEC
          and elapsed_x <= 3.0
          and not th_x.is_alive())

    # ---- (y) PARTIAL-PROGRESS VETO (semantics pin, NOT a
    #           defect specimen): a SLOW clock advancing at
    #           1/4 rate has progressed but not reached the
    #           interval when the wall clock reaches it, so
    #           it KEEPS its veto — the wait trusts the
    #           slowest progressing clock and ends only
    #           when the slow clock reaches the interval
    #           (~4x the wall duration). This pins the
    #           semantics disclosed in BRIDGE.md; the
    #           round-6 loop already behaved this way, so
    #           (y) is expected to pass on BOTH trees.
    real_time_y = time.time
    real_monotonic_y = time.monotonic
    y_t0 = real_time_y()
    y_mono0 = real_monotonic_y()

    def slow_monotonic_y():
        return y_mono0 + (real_time_y() - y_t0) / 4.0

    wait_end_y = {}

    def wait_thread_y():
        t0 = real_time_y()
        exporter._recovery_wait(None)
        wait_end_y["elapsed"] = real_time_y() - t0

    time.monotonic = slow_monotonic_y
    th_y = threading.Thread(target=wait_thread_y, daemon=True)
    vetoed_y = False
    elapsed_y = None
    try:
        th_y.start()
        time.sleep(2.0)
        vetoed_y = "elapsed" not in wait_end_y and th_y.is_alive()
        th_y.join(timeout=4.0)
        elapsed_y = wait_end_y.get("elapsed")
    finally:
        th_y.join(timeout=5)
        time.monotonic = real_monotonic_y
    check("(y) a slow clock at 1/4 rate keeps its "
          "partial-progress veto: the recovery wait has NOT "
          "ended at 2s (past the wall duration) and ends "
          "only at ~the slow clock's duration (elapsed "
          ">= 3s, generous bounds) — the disclosed "
          "slowest-progressing-clock semantics",
          vetoed_y
          and elapsed_y is not None
          and elapsed_y >= 3.0
          and not th_y.is_alive())

    failed = [n for n, ok in PASS if not ok]
    print(f"\n{len(PASS) - len(failed)}/{len(PASS)} exporter checks pass")
    if failed:
        print("FAILED:", failed)
        sys.exit(1)


if __name__ == "__main__":
    main()
