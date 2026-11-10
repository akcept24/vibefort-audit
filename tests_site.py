"""Invariant catalog for the ShipAudit Lab site (server.py).

Every closed hole and confirmed behavior is pinned here forever
(Vitaliy's "don't break what works" rule, 2026-11-09): tests are
only ever ADDED; changing an existing assertion requires an
explicit contract-change decision. Run: python3 tests_site.py
(in-process, throwaway DB, mail/telegram stubbed).
"""
import json
import os
import sqlite3
import sys
import time

os.environ["VF_DB_PATH"] = "/tmp/vf-catalog.db"
os.environ["STRIPE_WEBHOOK_SECRET"] = "whsec_catalog"
if os.path.exists("/tmp/vf-catalog.db"):
    os.unlink("/tmp/vf-catalog.db")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server as S  # noqa: E402

STATE = {"resend_ok": True, "telegram_ok": True, "sent": []}
S.send_telegram = lambda text: (STATE["telegram_ok"], "stub")


def _resend(to, subject, text, html=None):
    if STATE["resend_ok"]:
        STATE["sent"].append((to, subject))
    return STATE["resend_ok"], "stub-detail"


S.send_resend = _resend

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def db():
    c = sqlite3.connect("/tmp/vf-catalog.db")
    c.row_factory = sqlite3.Row
    return c


def mk_order(email, tier, amount, status="NEW"):
    c = S.db_connect()
    cur = c.execute(
        "INSERT INTO orders(created_at,name,email,url,tier,notes,"
        "amount,status) VALUES(?,?,?,?,?,?,?,?)",
        (S.utcnow(), "Cat T", email, "https://example.com", tier, "",
         amount, status))
    oid = cur.lastrowid
    c.commit()
    c.close()
    return oid


def order_status(oid):
    c = db()
    r = c.execute("SELECT status FROM orders WHERE id=?",
                  (oid,)).fetchone()["status"]
    c.close()
    return r


def count(table, where, args):
    c = db()
    n = c.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}",
                  args).fetchone()[0]
    c.close()
    return n


import hashlib
import hmac as _hmac


class FakeSelf(S.Handler):
    """The real webhook entry point (_api_stripe_webhook) with a
    captured reply: signature verification and the crash-rollback
    wrapper are part of the catalog contract, not just the inner
    processing."""

    def __init__(self, raw):
        self.replies = []
        self._raw_body = raw
        ts = str(int(time.time()))
        sig = _hmac.new(b"whsec_catalog", ts.encode() + b"." + raw,
                        hashlib.sha256).hexdigest()
        self.headers = {"Stripe-Signature": f"t={ts},v1={sig}"}

    def _send_json(self, code, payload):
        self.replies.append((code, payload))


def stripe_call(event, session):
    body = dict(event)
    body["data"] = {"object": session}
    fs = FakeSelf(json.dumps(body).encode())
    S.Handler._api_stripe_webhook(fs)
    return fs.replies[-1]


def sess(amount, email, currency="usd", pi="pi_1", plink=None):
    o = {"payment_status": "paid", "amount_total": amount,
         "currency": currency, "payment_intent": pi,
         "customer_details": {"email": email}}
    if plink:
        o["payment_link"] = plink
    return o


def evt(eid, etype="checkout.session.completed"):
    return {"id": eid, "type": etype}


PLINK_DS = "plink_1Ua3hOL0Rfi91QqAUpx9XrMR"

# W1: plain amount match pays, fulfils once, records completion,
#     sends the receipt.
o1 = mk_order("w1@test.dev", "Deep Scan", 29)
r = stripe_call(evt("evt_w1"), sess(2900, "w1@test.dev", pi="pi_w1"))
check("W1 match pays", r == (200, {"ok": True, "order_id": o1})
      and order_status(o1) == "PAID")
check("W1 fulfilment once",
      count("fulfilment_requests", "order_id=?", (o1,)) == 1)
check("W1 effects recorded",
      count("events", "order_id=? AND event='SIDE_EFFECTS_OK'",
            (o1,)) == 1)
check("W1 receipt sent",
      count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
            (o1,)) == 1)

# W2: foreign currency never matches.
o2 = mk_order("w2@test.dev", "Deep Scan", 29)
r = stripe_call(evt("evt_w2"), sess(2900, "w2@test.dev",
                                    currency="eur", pi="pi_w2"))
check("W2 EUR unmatched", r[1].get("matched") is False
      and order_status(o2) == "NEW")

# W3/W4: payment-link binding — wrong amount on a real link fails,
#        the link's own amount pays.
o3 = mk_order("w3@test.dev", "Deep Scan", 29)
r = stripe_call(evt("evt_w3"), sess(29900, "w3@test.dev", pi="pi_w3",
                                    plink=PLINK_DS))
check("W3 plink wrong amount", r[1].get("matched") is False
      and order_status(o3) == "NEW")
r = stripe_call(evt("evt_w4"), sess(2900, "w3@test.dev", pi="pi_w4",
                                    plink=PLINK_DS))
check("W4 plink match pays", r == (200, {"ok": True, "order_id": o3})
      and order_status(o3) == "PAID")

# W5: the async second event for the same payment is a quiet
#     duplicate — no second fulfilment, no unmatched alert.
r = stripe_call(evt("evt_w5", "checkout.session.async_payment_succeeded"),
                sess(2900, "w3@test.dev", pi="pi_w4", plink=PLINK_DS))
check("W5 pi duplicate quiet", r[1].get("duplicate") is True
      and count("fulfilment_requests", "order_id=?", (o3,)) == 1)

# W6: a dedupe row left by a crash (no order link, no terminal log)
#     reprocesses instead of acking as a duplicate.
o6 = mk_order("w6@test.dev", "Deep Scan", 29)
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w6','checkout.session.completed',NULL,?,?,2900)",
          (S.utcnow(), None))
c.commit()
c.close()
r = stripe_call(evt("evt_w6"), sess(2900, "w6@test.dev", pi="pi_w6"))
check("W6 incomplete dedupe reprocesses",
      r == (200, {"ok": True, "order_id": o6})
      and order_status(o6) == "PAID")

# W7: a crash between linking and the transition — the replay's
#     recovery consult finishes the transition itself.
o7 = mk_order("w7@test.dev", "Deep Scan", 29)
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w7','checkout.session.completed',?,?,?,2900)",
          (o7, S.utcnow(), "pi_w7"))
c.commit()
c.close()
r = stripe_call(evt("evt_w7"), sess(2900, "w7@test.dev", pi="pi_w7"))
check("W7 consult transitions linked NEW order",
      r[1].get("duplicate") is True and order_status(o7) == "PAID"
      and count("fulfilment_requests", "order_id=?", (o7,)) == 1)

# W8: a failed receipt raises (Stripe will retry) — but the order
#     still lands PAID and fulfilled; the retry's consult resends
#     the receipt and acks.
o8 = mk_order("w8@test.dev", "Deep Scan", 29)
STATE["resend_ok"] = False
r = stripe_call(evt("evt_w8"), sess(2900, "w8@test.dev", pi="pi_w8"))
check("W8 receipt failure -> 500 for Stripe retry", r[0] == 500
      and order_status(o8) == "PAID"
      and count("fulfilment_requests", "order_id=?", (o8,)) == 1)
STATE["resend_ok"] = True
r = stripe_call(evt("evt_w8"), sess(2900, "w8@test.dev", pi="pi_w8"))
check("W8 consult resends receipt",
      r[1].get("duplicate") is True
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o8,)) == 1)

# W9: transition race — first wins, second loses, effects fire once.
o9 = mk_order("w9@test.dev", "Deep Scan", 29)
c = db()
row = dict(c.execute("SELECT * FROM orders WHERE id=?",
                     (o9,)).fetchone())
c.close()
w1 = S.transition_order_status(dict(row), "PAID")
w2 = S.transition_order_status(dict(row), "PAID")
check("W9 race single winner", w1 is True and w2 is False
      and count("fulfilment_requests", "order_id=?", (o9,)) == 1)

# W10: an unmatched payment whose HQ alert cannot be delivered
#      raises and leaves NO dedupe row (Stripe retry reprocesses).
STATE["telegram_ok"] = False
o10 = mk_order("w10@test.dev", "Deep Scan", 29)
r = stripe_call(evt("evt_w10"), sess(200, "w10@test.dev", pi="pi_w10"))
STATE["telegram_ok"] = True
check("W10 unmatched alert failure rolls back",
      r[0] == 500
      and count("stripe_events", "event_id='evt_w10'", ()) == 0
      and order_status(o10) == "NEW")

# W10b: after the rollback, the same event redelivers cleanly —
#       one alert, one terminal log; a third delivery is a quiet
#       duplicate (the alert never repeats).
r = stripe_call(evt("evt_w10"), sess(200, "w10@test.dev", pi="pi_w10"))
r3 = stripe_call(evt("evt_w10"), sess(200, "w10@test.dev", pi="pi_w10"))
check("W10b redelivery after rollback is clean",
      r[1].get("matched") is False and r3[1].get("duplicate") is True
      and count("events",
                "event='STRIPE_UNMATCHED' AND detail LIKE '%evt_w10%'",
                ()) == 1)

# ---- Monitoring catalog ----
F1 = [{"severity": "low", "title": "Missing header A"}]
F2 = [{"severity": "low", "title": "Missing header A"},
      {"severity": "medium", "title": "New hole B"}]
MON = {"findings": F1, "ok": True, "sent": []}
S._guard_public_target = lambda host: None
S._scan_with_timeout = lambda url: (
    list(MON["findings"]), {"host": "example.com", "errors": []})


def mon_resend(to, subject, text, html=None):
    if MON["ok"]:
        MON["sent"].append(text)
    return MON["ok"], "stub-detail"


S.send_resend = mon_resend
om = mk_order("mon@test.dev", "Monitoring", 79, status="PAID")
c = S.db_connect()
c.execute("INSERT INTO monitors(order_id,url,email,name,created_at,"
          "next_run_at) VALUES(?,?,?,?,?,?)",
          (om, "example.com", "mon@test.dev", "Mon T", S.utcnow(),
           time.time()))
c.commit()
c.close()


def mon_row():
    c = db()
    m = dict(c.execute("SELECT * FROM monitors WHERE order_id=?",
                       (om,)).fetchone())
    c.close()
    return m


S._run_monitor(mon_row())
m = mon_row()
check("M1 baseline silent + digest set",
      json.loads(m["last_digest"]) == ["LOW|Missing header A"]
      and m["pending_alert"] is None and not MON["sent"])

MON["findings"] = F2
MON["ok"] = False
S._run_monitor(mon_row())
m = mon_row()
p = json.loads(m["pending_alert"]) if m["pending_alert"] else None
check("M2 failed alert retained, digest held",
      bool(p) and p["attempts"] == 1
      and json.loads(m["last_digest"]) == ["LOW|Missing header A"]
      and abs(m["next_run_at"] - time.time() - 3600) < 120)

S._run_monitor(mon_row())
check("M3 retry attempt counted",
      json.loads(mon_row()["pending_alert"])["attempts"] == 2)

# M3b: at attempt 3 with the escalation channel DOWN, the cadence
#      stays hourly and 'escalated' stays unset.
S.send_telegram = lambda text: (False, "down")
S._run_monitor(mon_row())
m = mon_row()
p = json.loads(m["pending_alert"])
check("M3b unescalated failure stays hourly",
      p["attempts"] == 3 and not p.get("escalated")
      and abs(m["next_run_at"] - time.time() - 3600) < 120)
S.send_telegram = lambda text: (STATE["telegram_ok"], "stub")
S._run_monitor(mon_row())
m = mon_row()
p = json.loads(m["pending_alert"])
check("M3c escalation lands -> weekly",
      p.get("escalated") is True
      and abs(m["next_run_at"] - time.time() - 7 * 86400) < 120)

# M4: findings revert while retained; delivery still happens with
#     the retained diff, then state settles.
MON["findings"] = F1
MON["ok"] = True
MON["sent"] = []
S._run_monitor(mon_row())
m = mon_row()
check("M4 retained alert delivered after revert",
      any("New hole B" in t for t in MON["sent"])
      and m["pending_alert"] is None
      and json.loads(m["last_digest"]) == ["LOW|Missing header A"])

# M5: a retained alert delivers even when the target refuses to
#     scan (delivery precedes the guard/scan in _run_monitor).
c = S.db_connect()
pend = {"new": ["MEDIUM|New hole B"], "gone": [], "grade": "B",
        "score": 89,
        "digest_after": ["LOW|Missing header A", "MEDIUM|New hole B"],
        "attempts": 1, "since": S.utcnow()}
c.execute("UPDATE monitors SET pending_alert=?, last_digest=? "
          "WHERE order_id=?",
          (json.dumps(pend), json.dumps(["LOW|Missing header A"]), om))
c.commit()
c.close()
S._guard_public_target = lambda host: "refused: test"
MON["sent"] = []
S._run_monitor(mon_row())
m = mon_row()
check("M5 retained delivery precedes scan guard",
      any("New hole B" in t for t in MON["sent"])
      and m["pending_alert"] is None)
S._guard_public_target = lambda host: None

# ---- Boot sweep catalog ----
# S1: a marker-less PAID order gets its effects re-fired once.
os1 = mk_order("s1@test.dev", "Deep Scan", 29, status="PAID")
S.sweep_paid_side_effects()
check("S1 sweep re-fires effects",
      count("fulfilment_requests", "order_id=?", (os1,)) == 1
      and count("events", "order_id=? AND event='SIDE_EFFECTS_OK'",
                (os1,)) >= 1)
# S2: a verified payment linked to a still-NEW order transitions it.
os2 = mk_order("s2@test.dev", "Deep Scan", 29)
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_s2','checkout.session.completed',?,?,?,2900)",
          (os2, S.utcnow(), "pi_s2"))
c.commit()
c.close()
S.sweep_paid_side_effects()
check("S2 sweep transitions linked NEW order",
      order_status(os2) == "PAID"
      and count("fulfilment_requests", "order_id=?", (os2,)) == 1)

# ---- Delta-5 catalog (added 2026-11-09, round 5) ----
import threading  # noqa: E402

# W11: two DIFFERENT payments delivered concurrently for one NEW
#      order — exactly one claims it; the other is unmatched, not
#      silently acked as a second match.
o11 = mk_order("w11@test.dev", "Deep Scan", 29)
res11 = []


def _w11(tag):
    res11.append(stripe_call(
        evt(f"evt_w11_{tag}"),
        sess(2900, "w11@test.dev", pi=f"pi_w11_{tag}")))


ts = [threading.Thread(target=_w11, args=(t,)) for t in ("a", "b")]
[t.start() for t in ts]
[t.join() for t in ts]
matched11 = [r for r in res11 if r[1].get("order_id") == o11]
unmatched11 = [r for r in res11 if r[1].get("matched") is False]
check("W11 concurrent payments: single claim",
      len(matched11) == 1 and len(unmatched11) == 1
      and count("fulfilment_requests", "order_id=?", (o11,)) == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o11,)) == 1)

# W12: the SAME payment delivered concurrently as two events —
#      one match, one quiet duplicate, one receipt (W5 under race).
o12 = mk_order("w12@test.dev", "Deep Scan", 29)
res12 = []


def _w12(tag, etype):
    res12.append(stripe_call(
        evt(f"evt_w12_{tag}", etype),
        sess(2900, "w12@test.dev", pi="pi_w12")))


ts = [threading.Thread(target=_w12, args=("a", "checkout.session.completed")),
      threading.Thread(target=_w12,
                       args=("b", "checkout.session.async_payment_succeeded"))]
[t.start() for t in ts]
[t.join() for t in ts]
check("W12 concurrent same-payment duplicate",
      len([r for r in res12 if r[1].get("order_id") == o12]) == 1
      and len([r for r in res12 if r[1].get("duplicate")]) == 1
      and count("fulfilment_requests", "order_id=?", (o12,)) == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o12,)) == 1)

# A1: an admin move may not skip PAID — the side effects live there.
oa1 = mk_order("a1@test.dev", "Deep Scan", 29)
c = db()
row_a1 = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (oa1,)).fetchone())
c.close()
refused = False
try:
    S.transition_order_status(row_a1, "IN_PROGRESS")
except ValueError:
    refused = True
check("A1 skipping PAID refused", refused
      and order_status(oa1) == "NEW")

# A2: leaving PAID re-fires missing side effects first.
oa2 = mk_order("a2@test.dev", "Deep Scan", 29)
c = db()
row_a2 = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (oa2,)).fetchone())
c.close()
S.transition_order_status(row_a2, "PAID")
c = S.db_connect()
c.execute("DELETE FROM fulfilment_requests WHERE order_id=?", (oa2,))
c.execute("DELETE FROM events WHERE order_id=? AND "
          "event='SIDE_EFFECTS_OK'", (oa2,))
c.commit()
c.close()
row_a2["status"] = "PAID"
won = S.transition_order_status(row_a2, "IN_PROGRESS")
check("A2 leaving PAID ensures effects first", won is True
      and count("fulfilment_requests", "order_id=?", (oa2,)) == 1)

# A2b: leaving PAID with broken effects is refused; the order
#      stays PAID where the recovery paths can see it.
oa3 = mk_order("a3@test.dev", "Deep Scan", 29, status="PAID")
real_hook = S.on_deep_scan_paid
S.on_deep_scan_paid = lambda row: (_ for _ in ()).throw(
    RuntimeError("boom"))
c = db()
row_a3 = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (oa3,)).fetchone())
c.close()
refused = False
try:
    S.transition_order_status(row_a3, "IN_PROGRESS")
except RuntimeError:
    refused = True
S.on_deep_scan_paid = real_hook
check("A2b broken effects block leaving PAID", refused
      and order_status(oa3) == "PAID")

# S3: sweep ordering — a linked NEW order whose transition effects
#     fail once is recovered within the SAME sweep (snapshot after
#     transitions), and its receipt follows the recovered effects.
os3 = mk_order("s3@test.dev", "Deep Scan", 29)
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_s3','checkout.session.completed',?,?,?,2900)",
          (os3, S.utcnow(), "pi_s3"))
c.commit()
c.close()
calls = {"n": 0}


def flaky_hook(row):
    calls["n"] += 1
    if calls["n"] == 1:
        raise RuntimeError("first attempt fails")
    return real_hook(row)


S.on_deep_scan_paid = flaky_hook
S.sweep_paid_side_effects()
S.on_deep_scan_paid = real_hook
check("S3 sweep recovers flaky transition in one run",
      order_status(os3) == "PAID"
      and count("fulfilment_requests", "order_id=?", (os3,)) == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (os3,)) == 1)

# S3b: with effects permanently broken, the sweep sends NO receipt
#      (never tell a payer "queued" while the queueing failed).
os4 = mk_order("s4@test.dev", "Deep Scan", 29)
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_s4','checkout.session.completed',?,?,?,2900)",
          (os4, S.utcnow(), "pi_s4"))
c.commit()
c.close()
S.on_deep_scan_paid = lambda row: (_ for _ in ()).throw(
    RuntimeError("always broken"))
S.sweep_paid_side_effects()
S.on_deep_scan_paid = real_hook
check("S3b no receipt while effects broken",
      order_status(os4) == "PAID"
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (os4,)) == 0
      and count("fulfilment_requests", "order_id=?", (os4,)) == 0)

# ---- Delta-6 catalog (added 2026-11-09, round 6) ----
# W13: cross-process claim loss — another payment's transition
#      lands between this delivery's selection and its own
#      transition. This payment must end UNMATCHED (HQ alerted),
#      never acked as matched to an order it did not pay for.
o13 = mk_order("w13@test.dev", "Deep Scan", 29)
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w13_win','checkout.session.completed',?,?,?,2900)",
          (o13, S.utcnow(), "pi_w13_win"))
c.commit()
c.close()
real_t = S.transition_order_status
race = {"fired": False}


def racing_t(row, new_status, **kw):
    # CONTRACT CHANGE (round 7, flagged): the winning transition
    # now records the winning payment's identity on the order, so
    # the simulated winner passes its event/pi explicitly. The
    # invariant asserted below is unchanged.
    if not race["fired"] and row["id"] == o13:
        race["fired"] = True
        real_t(row, new_status, paid_event_id="evt_w13_win",
               paid_pi="pi_w13_win")  # the winner's transition lands
    return real_t(row, new_status, **kw)


S.transition_order_status = racing_t
r = stripe_call(evt("evt_w13_lose"),
                sess(2900, "w13@test.dev", pi="pi_w13_lose"))
S.transition_order_status = real_t
c = db()
loser_link = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w13_lose'").fetchone()[0]
c.close()
check("W13 cross-process loser ends unmatched",
      r[1].get("matched") is False and order_status(o13) == "PAID"
      and loser_link is None
      and count("fulfilment_requests", "order_id=?", (o13,)) == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o13,)) == 0
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w13_lose%'", ()) == 1)

# A3: the completion marker is verified, not assumed — if the
#     SIDE_EFFECTS_OK write cannot persist, leaving PAID is
#     refused (log_event swallows write errors by design).
oa4 = mk_order("a4@test.dev", "Deep Scan", 29, status="PAID")
real_done = S._paid_effects_done
S._paid_effects_done = lambda oid: False
c = db()
row_a4 = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (oa4,)).fetchone())
c.close()
refused = False
try:
    S.transition_order_status(row_a4, "IN_PROGRESS")
except RuntimeError:
    refused = True
S._paid_effects_done = real_done
check("A3 unpersisted marker blocks leaving PAID", refused
      and order_status(oa4) == "PAID")

# A3b: the same failure inside a fresh transition raises, but
#      leaves the recoverable state — PAID, effects applied, the
#      consult/sweep can finish the marker once writes heal.
oa5 = mk_order("a5@test.dev", "Deep Scan", 29)
S._paid_effects_done = lambda oid: False
c = db()
row_a5 = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (oa5,)).fetchone())
c.close()
refused = False
try:
    S.transition_order_status(row_a5, "PAID")
except RuntimeError:
    refused = True
S._paid_effects_done = real_done
check("A3b marker failure leaves recoverable PAID", refused
      and order_status(oa5) == "PAID"
      and count("fulfilment_requests", "order_id=?", (oa5,)) == 1)

# ---- Delta-7 catalog (added 2026-11-09, round 7) ----
# W14: a provisional link is not a match. The order was won by
#      another payment (paid_pi on the order is the authority);
#      the loser's retry settles it as unmatched — no receipt, no
#      duplicate ack, HQ alerted exactly once.
o14 = mk_order("w14@test.dev", "Deep Scan", 29)
c = db()
row_14 = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (o14,)).fetchone())
c.close()
S.transition_order_status(row_14, "PAID",
                          paid_event_id="evt_w14_win",
                          paid_pi="pi_w14_win")
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w14_lose','checkout.session.completed',?,?,?,2900)",
          (o14, S.utcnow(), "pi_w14_lose"))
c.commit()
c.close()
r = stripe_call(evt("evt_w14_lose"),
                sess(2900, "w14@test.dev", pi="pi_w14_lose"))
c = db()
loser14 = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w14_lose'").fetchone()[0]
c.close()
check("W14 provisional loser settled as unmatched",
      r[1].get("matched") is False and loser14 is None
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w14_lose%'", ()) == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o14,)) == 0
      and count("fulfilment_requests", "order_id=?", (o14,)) == 1)

# W15: claim ownership — a live claim held by another process
#      makes this delivery step aside (500, row untouched); once
#      the claim is stale, the next delivery steals it and the
#      event completes exactly once.
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount,claim,claimed_at) "
          "VALUES('evt_w15','checkout.session.completed',NULL,?,?,"
          "200,'otherproc',?)",
          (S.utcnow(), "pi_w15", time.time()))
c.commit()
c.close()
r = stripe_call(evt("evt_w15"), sess(200, "w15@test.dev",
                                     pi="pi_w15"))
c = db()
claim15 = c.execute(
    "SELECT claim FROM stripe_events WHERE "
    "event_id='evt_w15'").fetchone()[0]
c.close()
check("W15 live foreign claim: step aside, row untouched",
      r[0] == 500 and claim15 == "otherproc"
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w15%'", ()) == 0)
c = S.db_connect()
c.execute("UPDATE stripe_events SET claimed_at=? WHERE "
          "event_id='evt_w15'", (time.time() - 300,))
c.commit()
c.close()
r = stripe_call(evt("evt_w15"), sess(200, "w15@test.dev",
                                     pi="pi_w15"))
r3 = stripe_call(evt("evt_w15"), sess(200, "w15@test.dev",
                                      pi="pi_w15"))
check("W15 stale claim stolen, event completes once",
      r[1].get("matched") is False and r3[1].get("duplicate") is True
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w15%'", ()) == 1)

# ---- Delta-8 catalog (added 2026-11-09, round 8) ----
# W16: the unmatched alert is single-fire across processes. A
#      foreign event-lock makes the delivery step aside (500, no
#      alert); once released, exactly one alert fires; a third
#      delivery is a quiet duplicate.
tg16 = {"n": 0}
real_tg = S.send_telegram
S.send_telegram = lambda text: (tg16.__setitem__("n", tg16["n"] + 1),
                                (True, "ok"))[1]
c = S.db_connect()
# MECHANISM NOTE (round 9): lock keys are namespaced since
# delta-9 ("alert:<event_id>", "receipt:<order_id>"); the W16
# invariant — a foreign alert lock silences the delivery — is
# unchanged.
c.execute("INSERT INTO event_locks(event_id,purpose,claimed_at) "
          "VALUES('alert:evt_w16','unmatched-alert',?)",
          (time.time(),))
c.commit()
c.close()
r = stripe_call(evt("evt_w16"), sess(200, "w16@test.dev",
                                     pi="pi_w16"))
check("W16 foreign alert lock: step aside silently",
      r[0] == 500 and tg16["n"] == 0)
c = S.db_connect()
c.execute("DELETE FROM event_locks WHERE "
          "event_id='alert:evt_w16'")
c.commit()
c.close()
r = stripe_call(evt("evt_w16"), sess(200, "w16@test.dev",
                                     pi="pi_w16"))
r3 = stripe_call(evt("evt_w16"), sess(200, "w16@test.dev",
                                      pi="pi_w16"))
S.send_telegram = real_tg
check("W16 alert fires exactly once",
      r[1].get("matched") is False and r3[1].get("duplicate") is True
      and tg16["n"] == 1)

# W17: the payment-intent duplicate shortcut requires the order's
#      recorded winner to BE this payment. A provisional link to
#      an order won by another payment does not dup-ack — the new
#      event settles as unmatched.
o17 = mk_order("w17@test.dev", "Deep Scan", 29)
c = db()
row_17 = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (o17,)).fetchone())
c.close()
S.transition_order_status(row_17, "PAID",
                          paid_event_id="evt_w17_win",
                          paid_pi="pi_w17_b")
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w17_a1','checkout.session.completed',?,?,?,2900)",
          (o17, S.utcnow(), "pi_w17_a"))
c.commit()
c.close()
r = stripe_call(evt("evt_w17_a2",
                    "checkout.session.async_payment_succeeded"),
                sess(2900, "w17@test.dev", pi="pi_w17_a"))
check("W17 dup shortcut requires a proven win",
      r[1].get("matched") is False
      and count("events", "event='STRIPE_DUP_EVENT' AND "
                "detail LIKE '%evt_w17_a2%'", ()) == 0
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w17_a2%'", ()) == 1)

# W18: the consult checks its transition result. Losing the race
#      to a different payment re-judges on the real winner and
#      settles the provisional event as unmatched.
o18 = mk_order("w18@test.dev", "Deep Scan", 29)
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w18_lose','checkout.session.completed',?,?,?,2900)",
          (o18, S.utcnow(), "pi_w18_lose"))
c.commit()
c.close()
race18 = {"fired": False}


def racing_t18(row, new_status, **kw):
    if not race18["fired"] and row["id"] == o18:
        race18["fired"] = True
        real_t(row, new_status, paid_event_id="evt_w18_win",
               paid_pi="pi_w18_win")
    return real_t(row, new_status, **kw)


S.transition_order_status = racing_t18
r = stripe_call(evt("evt_w18_lose"),
                sess(2900, "w18@test.dev", pi="pi_w18_lose"))
S.transition_order_status = real_t
c = db()
link18 = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w18_lose'").fetchone()[0]
c.close()
check("W18 consult re-judges a lost transition",
      r[1].get("matched") is False and link18 is None
      and order_status(o18) == "PAID"
      and count("fulfilment_requests", "order_id=?", (o18,)) == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o18,)) == 0
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w18_lose%'", ()) == 1)

# W19: NULL authority — an order with NO recorded winning payment
#      (admin-paid) never validates a linked payment as matched;
#      the payment surfaces as unmatched for a manual decision.
o19 = mk_order("w19@test.dev", "Deep Scan", 29)
c = db()
row_19 = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (o19,)).fetchone())
c.close()
S.transition_order_status(row_19, "PAID")
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w19','checkout.session.completed',?,?,?,2900)",
          (o19, S.utcnow(), "pi_w19"))
c.commit()
c.close()
r = stripe_call(evt("evt_w19"), sess(2900, "w19@test.dev",
                                     pi="pi_w19"))
check("W19 unrecorded winner never validates a match",
      r[1].get("matched") is False
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o19,)) == 0
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w19%'", ()) == 1)


# ---- Delta-9 catalog (added 2026-11-09, round 9) ----
# W20: a paid session with NO payment_intent never matches, even
#      with a perfect amount+email candidate waiting.
o20 = mk_order("w20@test.dev", "Deep Scan", 29)
sess20 = sess(2900, "w20@test.dev")
sess20["payment_intent"] = None
r = stripe_call(evt("evt_w20"), sess20)
check("W20 pi-less session never matches",
      r[1].get("matched") is False and order_status(o20) == "NEW"
      and count("fulfilment_requests", "order_id=?", (o20,)) == 0
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w20%'", ()) == 1)

# W21: the duplicate lookup must find the PROVEN winner even when
#      a provisional row for the same payment sits on a lost
#      order. A third event for the winning payment dup-acks.
o21a = mk_order("w21a@test.dev", "Deep Scan", 29)
o21b = mk_order("w21b@test.dev", "Deep Scan", 29)
c = db()
ra = dict(c.execute("SELECT * FROM orders WHERE id=?",
                    (o21a,)).fetchone())
rb = dict(c.execute("SELECT * FROM orders WHERE id=?",
                    (o21b,)).fetchone())
c.close()
S.transition_order_status(ra, "PAID", paid_event_id="evt_w21_a",
                          paid_pi="pi_w21_other")
S.transition_order_status(rb, "PAID", paid_event_id="evt_w21_b",
                          paid_pi="pi_w21_z")
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w21_z1','checkout.session.completed',?,?,?,2900)",
          (o21a, S.utcnow(), "pi_w21_z"))
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w21_z2','checkout.session.completed',?,?,?,2900)",
          (o21b, S.utcnow(), "pi_w21_z"))
c.commit()
c.close()
r = stripe_call(evt("evt_w21_z3",
                    "checkout.session.async_payment_succeeded"),
                sess(2900, "w21b@test.dev", pi="pi_w21_z"))
check("W21 dup lookup finds the proven winner",
      r[1].get("duplicate") is True
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w21_z3%'", ()) == 0)

# W22: a consult whose unmatched alert FAILS keeps the link — the
#      boot sweep remains able to settle the event afterwards.
o22 = mk_order("w22@test.dev", "Deep Scan", 29)
c = db()
row_22 = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (o22,)).fetchone())
c.close()
S.transition_order_status(row_22, "PAID",
                          paid_event_id="evt_w22_win",
                          paid_pi="pi_w22_win")
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w22_lose','checkout.session.completed',?,?,?,2900)",
          (o22, S.utcnow(), "pi_w22_lose"))
c.commit()
c.close()
STATE["telegram_ok"] = False
r = stripe_call(evt("evt_w22_lose"),
                sess(2900, "w22@test.dev", pi="pi_w22_lose"))
STATE["telegram_ok"] = True
c = db()
link22 = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w22_lose'").fetchone()[0]
c.close()
check("W22 failed consult alert keeps the link", r[0] == 500
      and link22 == o22
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w22_lose%'", ()) == 0)
S.sweep_paid_side_effects()
c = db()
link22 = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w22_lose'").fetchone()[0]
c.close()
check("W22 sweep settles what the consult could not",
      link22 is None
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w22_lose%'", ()) == 1)

# A5: the receipt send is single-fire PER ORDER. A foreign
#     receipt lock makes the consult step aside (500, nothing
#     sent); once released, the receipt lands exactly once.
o23 = mk_order("a5@test.dev", "Deep Scan", 29)
# The receipt channel is stubbed directly here: by this point in
# the catalog send_resend is the monitoring stub, which cannot
# fail — A5 needs a genuinely failing first send.
keep_resend = S.send_resend
S.send_resend = lambda *a, **k: (False, "down")
stripe_call(evt("evt_a5"), sess(2900, "a5@test.dev", pi="pi_a5"))
S.send_resend = lambda *a, **k: (True, "ok")
c = S.db_connect()
c.execute("INSERT INTO event_locks(event_id,purpose,claimed_at) "
          "VALUES(?,'receipt',?)", (f"receipt:{o23}", time.time()))
c.commit()
c.close()
r = stripe_call(evt("evt_a5"), sess(2900, "a5@test.dev",
                                    pi="pi_a5"))
check("A5 foreign receipt lock: consult steps aside",
      r[0] == 500
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o23,)) == 0)
c = S.db_connect()
c.execute("DELETE FROM event_locks WHERE event_id=?",
          (f"receipt:{o23}",))
c.commit()
c.close()
r = stripe_call(evt("evt_a5"), sess(2900, "a5@test.dev",
                                    pi="pi_a5"))
check("A5 receipt lands once the lock clears",
      r[1].get("duplicate") is True
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o23,)) == 1)
S.send_resend = keep_resend

# ---- Delta-10 catalog (added 2026-11-09, round 10) ----
# W23: one payment wins exactly one order. Payment pi_w23 already
#      won order A; a second event for it candidating order B is
#      rejected by the paid_pi fence and acked as a duplicate of
#      A — B is never fulfilled, no false unmatched alert.
o23a = mk_order("other23@test.dev", "Deep Scan", 29)
c = db()
row_23a = dict(c.execute("SELECT * FROM orders WHERE id=?",
                         (o23a,)).fetchone())
c.close()
S.transition_order_status(row_23a, "PAID",
                          paid_event_id="evt_w23_a",
                          paid_pi="pi_w23")
o23b = mk_order("w23@test.dev", "Deep Scan", 29)
r = stripe_call(evt("evt_w23_b"),
                sess(2900, "w23@test.dev", pi="pi_w23"))
c = db()
link23 = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w23_b'").fetchone()[0]
c.close()
check("W23 one payment, one order (paid_pi fence)",
      r[1].get("duplicate") is True and link23 == o23a
      and order_status(o23b) == "NEW"
      and count("fulfilment_requests", "order_id=?", (o23b,)) == 0
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w23_b%'", ()) == 0)

# W23b: the transition-level fence — a second identity transition
#       carrying an already-won payment_intent loses cleanly.
o23c = mk_order("w23c@test.dev", "Deep Scan", 29)
c = db()
row_23c = dict(c.execute("SELECT * FROM orders WHERE id=?",
                         (o23c,)).fetchone())
c.close()
won23 = S.transition_order_status(row_23c, "PAID",
                                  paid_event_id="evt_w23_c",
                                  paid_pi="pi_w23")
check("W23b second claim on one payment loses",
      won23 is False and order_status(o23c) == "NEW")

# W24: the fresh-match loser keeps its link until the alert is on
#      record. With Telegram down the delivery fails and the link
#      survives; the boot sweep settles it afterwards.
o24 = mk_order("w24@test.dev", "Deep Scan", 29)
race24 = {"fired": False}


def racing_t24(row, new_status, **kw):
    if not race24["fired"] and row["id"] == o24:
        race24["fired"] = True
        real_t(row, new_status, paid_event_id="evt_w24_win",
               paid_pi="pi_w24_win")
    return real_t(row, new_status, **kw)


S.transition_order_status = racing_t24
STATE["telegram_ok"] = False
r = stripe_call(evt("evt_w24"), sess(2900, "w24@test.dev",
                                     pi="pi_w24_lose"))
S.transition_order_status = real_t
STATE["telegram_ok"] = True
c = db()
link24 = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w24'").fetchone()[0]
c.close()
check("W24 failed loser alert keeps the link", r[0] == 500
      and link24 == o24
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w24%'", ()) == 0)
S.sweep_paid_side_effects()
c = db()
link24 = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w24'").fetchone()[0]
c.close()
check("W24 sweep settles the preserved link",
      link24 is None
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w24%'", ()) == 1)

# ---- Delta-11 catalog (added 2026-11-09, round 11) ----
# W25: the consult's fenced loser — the payment already won
#      another order, so the provisional event is relinked to the
#      WINNING order and acked as its duplicate. The NEW order it
#      was provisionally linked to gets no effects, no receipt.
o25a = mk_order("w25a@test.dev", "Deep Scan", 29)
c = db()
row_25a = dict(c.execute("SELECT * FROM orders WHERE id=?",
                         (o25a,)).fetchone())
c.close()
S.transition_order_status(row_25a, "PAID",
                          paid_event_id="evt_w25_win",
                          paid_pi="pi_w25")
o25b = mk_order("w25b@test.dev", "Deep Scan", 29)
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w25_x','checkout.session.completed',?,?,?,2900)",
          (o25b, S.utcnow(), "pi_w25"))
c.commit()
c.close()
r = stripe_call(evt("evt_w25_x"), sess(2900, "w25b@test.dev",
                                       pi="pi_w25"))
c = db()
link25 = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w25_x'").fetchone()[0]
c.close()
check("W25 consult fenced loser relinks to the winner",
      r[1].get("duplicate") is True and link25 == o25a
      and order_status(o25b) == "NEW"
      and count("fulfilment_requests", "order_id=?", (o25b,)) == 0
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o25b,)) == 0
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w25_x%'", ()) == 0)

# W26: the boot sweep settles the same fenced loser the same way.
o26a = mk_order("w26a@test.dev", "Deep Scan", 29)
c = db()
row_26a = dict(c.execute("SELECT * FROM orders WHERE id=?",
                         (o26a,)).fetchone())
c.close()
S.transition_order_status(row_26a, "PAID",
                          paid_event_id="evt_w26_win",
                          paid_pi="pi_w26")
o26b = mk_order("w26b@test.dev", "Deep Scan", 29)
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w26_x','checkout.session.completed',?,?,?,2900)",
          (o26b, S.utcnow(), "pi_w26"))
c.commit()
c.close()
S.sweep_paid_side_effects()
c = db()
link26 = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w26_x'").fetchone()[0]
c.close()
check("W26 sweep fenced loser relinks to the winner",
      link26 == o26a and order_status(o26b) == "NEW"
      and count("fulfilment_requests", "order_id=?", (o26b,)) == 0)

# W27: without the unique index (legacy duplicate paid_pi data
#      blocks its creation) an identity transition fails CLOSED
#      instead of running on the racy pre-check alone.
c = S.db_connect()
c.execute("DROP INDEX idx_orders_paid_pi")
c.execute("UPDATE orders SET paid_pi='pi_w27_dup' WHERE id=?",
          (o25a,))
c.execute("UPDATE orders SET paid_pi='pi_w27_dup' WHERE id=?",
          (o26a,))
c.commit()
c.close()
o27 = mk_order("w27@test.dev", "Deep Scan", 29)
c = db()
row_27 = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (o27,)).fetchone())
c.close()
refused = False
try:
    S.transition_order_status(row_27, "PAID",
                              paid_event_id="evt_w27",
                              paid_pi="pi_w27_new")
except RuntimeError:
    refused = True
check("W27 unfenced transition fails closed", refused
      and order_status(o27) == "NEW")
# Restore a fenced register for any later runs of this file.
c = S.db_connect()
c.execute("UPDATE orders SET paid_pi='pi_w25' WHERE id=?", (o25a,))
c.execute("UPDATE orders SET paid_pi='pi_w26' WHERE id=?", (o26a,))
c.commit()
c.close()
S.db_connect().close()  # recreates the index now that data is clean

# ---- Delta-12 catalog (added 2026-11-09, round 12) ----
# W28: the sweep never settles a link to a still-NEW order — that
#      state is in-flight/recoverable, owned by the delivery, its
#      consult and the linked-NEW loop.
o28 = mk_order("w28@test.dev", "Deep Scan", 29)
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w28','checkout.session.completed',?,?,?,2900)",
          (o28, S.utcnow(), "pi_w28"))
c.commit()
c.close()
S.sweep_paid_side_effects()
c = db()
link28 = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w28'").fetchone()[0]
c.close()
check("W28 sweep leaves NEW links alone",
      link28 == o28
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w28%'", ()) == 0)
# (the same sweep transitioned o28 via the linked-NEW loop, so
# the link is now a proven winner's — settle state is consistent)

# W28b: with the fence DOWN (legacy duplicate paid_pi), a NEW
#       link survives the sweep unsettled; once the data is
#       cleaned and the index returns, the next sweep completes
#       the payment automatically.
o28b = mk_order("w28b@test.dev", "Deep Scan", 29)
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w28b','checkout.session.completed',?,?,?,2900)",
          (o28b, S.utcnow(), "pi_w28b"))
c.execute("DROP INDEX idx_orders_paid_pi")
c.execute("UPDATE orders SET paid_pi='pi_w28b_dup' WHERE id=?",
          (o25a,))
c.execute("UPDATE orders SET paid_pi='pi_w28b_dup' WHERE id=?",
          (o26a,))
c.commit()
c.close()
S.sweep_paid_side_effects()
c = db()
link28b = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w28b'").fetchone()[0]
c.close()
check("W28b fenced-off link survives the sweep",
      link28b == o28b and order_status(o28b) == "NEW"
      and count("events", "event='STRIPE_UNMATCHED' AND "
                "detail LIKE '%evt_w28b%'", ()) == 0)
c = S.db_connect()
c.execute("UPDATE orders SET paid_pi='pi_w25' WHERE id=?", (o25a,))
c.execute("UPDATE orders SET paid_pi='pi_w26' WHERE id=?", (o26a,))
c.commit()
c.close()
S.db_connect().close()  # index recreated on clean data
S.sweep_paid_side_effects()
check("W28b payment recovers once the fence returns",
      order_status(o28b) == "PAID"
      and count("fulfilment_requests", "order_id=?", (o28b,)) == 1)

# ---- Delta-13 catalog (added 2026-11-09, round 13) ----
# W29: the sweep's settle unlink is conditional on the link it
#      judged. If the event is relinked to its true winner while
#      the settle is in flight (simulated inside the alert hook),
#      the sweep must not clear the new link.
o29b = mk_order("w29b@test.dev", "Deep Scan", 29)
o29a = mk_order("w29a@test.dev", "Deep Scan", 29)
c = db()
r29b = dict(c.execute("SELECT * FROM orders WHERE id=?",
                      (o29b,)).fetchone())
r29a = dict(c.execute("SELECT * FROM orders WHERE id=?",
                      (o29a,)).fetchone())
c.close()
S.transition_order_status(r29b, "PAID",
                          paid_event_id="evt_w29_win",
                          paid_pi="pi_w29")
S.transition_order_status(r29a, "PAID",
                          paid_event_id="evt_w29_other",
                          paid_pi="pi_w29_other")
c = S.db_connect()
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at,payment_intent,amount) VALUES"
          "('evt_w29','checkout.session.completed',?,?,?,2900)",
          (o29a, S.utcnow(), "pi_w29"))
c.commit()
c.close()
real_fire29 = S._fire_unmatched_alert


def racing_fire29(event_id, tg_text, log_detail):
    if event_id == "evt_w29":
        cc = S.db_connect()
        cc.execute("UPDATE stripe_events SET order_id=? WHERE "
                   "event_id='evt_w29'", (o29b,))
        cc.commit()
        cc.close()
    return real_fire29(event_id, tg_text, log_detail)


S._fire_unmatched_alert = racing_fire29
S.sweep_paid_side_effects()
S._fire_unmatched_alert = real_fire29
c = db()
link29 = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w29'").fetchone()[0]
c.close()
check("W29 settle never clears a relinked winner link",
      link29 == o29b)

# W30: one monitor run per monitor across processes — a foreign
#      lock holder makes the run skip entirely (no scan, no
#      save); once released, the run proceeds.
o30 = mk_order("w30@test.dev", "Monitoring", 79, status="PAID")
c = S.db_connect()
c.execute("INSERT INTO monitors(order_id,url,email,name,created_at,"
          "next_run_at) VALUES(?,?,?,?,?,?)",
          (o30, "example.com", "w30@test.dev", "W30", S.utcnow(),
           time.time()))
c.commit()
c.close()


def row30():
    c = db()
    m = dict(c.execute("SELECT * FROM monitors WHERE order_id=?",
                       (o30,)).fetchone())
    c.close()
    return m


mid30 = row30()["id"]
foreign30 = S._claim_event_lock(f"monitor:{mid30}", "monitor")
calls30 = {"n": 0}
real_scan30 = S._scan_with_timeout


def counting_scan30(url):
    calls30["n"] += 1
    return real_scan30(url)


S._scan_with_timeout = counting_scan30
S._run_monitor(row30())
check("W30 foreign-held monitor run skips",
      bool(foreign30) and calls30["n"] == 0
      and row30()["last_digest"] is None)
S._release_event_lock(f"monitor:{mid30}", foreign30)
S._run_monitor(row30())
S._scan_with_timeout = real_scan30
check("W30 released monitor run proceeds",
      calls30["n"] == 1 and row30()["last_digest"] is not None)

# ---- Delta-14 catalog (added 2026-11-09, round 14) ----
# W31: the fresh loser's deferred unlink is conditional on the
#      judged link and its claim. If the event is relinked to a
#      winning order while the alert fires (simulated inside the
#      alert hook), the tail must not clear the winning link.
o31 = mk_order("w31@test.dev", "Deep Scan", 29)
o31b = mk_order("w31b@test.dev", "Deep Scan", 29)
race31 = {"fired": False}


def racing_t31(row, new_status, **kw):
    if not race31["fired"] and row["id"] == o31:
        race31["fired"] = True
        real_t(row, new_status, paid_event_id="evt_w31_win",
               paid_pi="pi_w31_win")
    return real_t(row, new_status, **kw)


real_fire31 = S._fire_unmatched_alert


def racing_fire31(event_id, tg_text, log_detail):
    if event_id == "evt_w31":
        c = db()
        r31b = dict(c.execute("SELECT * FROM orders WHERE id=?",
                              (o31b,)).fetchone())
        c.close()
        real_t(r31b, "PAID", paid_event_id="evt_w31_b",
               paid_pi="pi_w31_lose")
        cc = S.db_connect()
        cc.execute("UPDATE stripe_events SET order_id=? WHERE "
                   "event_id='evt_w31'", (o31b,))
        cc.commit()
        cc.close()
    return real_fire31(event_id, tg_text, log_detail)


S.transition_order_status = racing_t31
S._fire_unmatched_alert = racing_fire31
r = stripe_call(evt("evt_w31"), sess(2900, "w31@test.dev",
                                     pi="pi_w31_lose"))
S.transition_order_status = real_t
S._fire_unmatched_alert = real_fire31
c = db()
link31 = c.execute(
    "SELECT order_id FROM stripe_events WHERE "
    "event_id='evt_w31'").fetchone()[0]
c.close()
check("W31 fresh loser unlink spares a relinked winner",
      r[1].get("matched") is False and link31 == o31b)

# W32: a monitor run re-reads its row under the mutex — a stale
#      caller snapshot (no pending alert) must not run: the DB
#      row's retained alert is what gets processed.
o32 = mk_order("w32@test.dev", "Monitoring", 79, status="PAID")
retained32 = {"new": ["HIGH|W32 finding"], "gone": [],
              "grade": "D", "score": 40,
              "digest_after": ["HIGH|W32 finding"],
              "attempts": 1, "since": S.utcnow()}
c = S.db_connect()
c.execute("INSERT INTO monitors(order_id,url,email,name,created_at,"
          "next_run_at,last_digest,pending_alert) "
          "VALUES(?,?,?,?,?,?,?,?)",
          (o32, "example.com", "w32@test.dev", "W32", S.utcnow(),
           time.time(), json.dumps(["LOW|base"]),
           json.dumps(retained32)))
c.commit()
c.close()
c = db()
stale32 = dict(c.execute("SELECT * FROM monitors WHERE order_id=?",
                         (o32,)).fetchone())
c.close()
stale32["pending_alert"] = None  # the caller's old snapshot
prev_resend32 = S.send_resend
S.send_resend = lambda to, subject, text, html=None: (False, "down")
S._run_monitor(stale32)
S.send_resend = prev_resend32
c = db()
m32 = dict(c.execute("SELECT * FROM monitors WHERE order_id=?",
                     (o32,)).fetchone())
c.close()
p32 = json.loads(m32["pending_alert"]) if m32["pending_alert"] \
    else None
check("W32 run works on the fresh row, not the snapshot",
      bool(p32) and p32["attempts"] == 2
      and json.loads(m32["last_digest"]) == ["LOW|base"])

# ---- Delta-15 catalog (added 2026-11-09, round 15) ----
# W33: a scheduler-triggered run revalidates due time on the
#      fresh row — a monitor rescheduled by a completed run is
#      not run early by a stale scheduler snapshot. A direct
#      call remains a deliberate force-run (W33b).
o33 = mk_order("w33@test.dev", "Monitoring", 79, status="PAID")
c = S.db_connect()
c.execute("INSERT INTO monitors(order_id,url,email,name,created_at,"
          "next_run_at) VALUES(?,?,?,?,?,?)",
          (o33, "example.com", "w33@test.dev", "W33", S.utcnow(),
           time.time() + 3600))
c.commit()
c.close()


def row33():
    c = db()
    m = dict(c.execute("SELECT * FROM monitors WHERE order_id=?",
                       (o33,)).fetchone())
    c.close()
    return m


calls33 = {"n": 0}
real_scan33 = S._scan_with_timeout


def counting_scan33(url):
    calls33["n"] += 1
    return real_scan33(url)


S._scan_with_timeout = counting_scan33
stale33 = row33()
stale33["next_run_at"] = time.time() - 10  # snapshot claims due
S._run_monitor(stale33, scheduled=True)
check("W33 scheduled run revalidates due time",
      calls33["n"] == 0 and row33()["last_digest"] is None)
S._run_monitor(row33())
S._scan_with_timeout = real_scan33
check("W33b direct call is a force-run",
      calls33["n"] == 1 and row33()["last_digest"] is not None)

# ---- Round 16 catalog (added 2026-11-10, notification exactly-once
#      incident — Codex/Sol v4b/v5b) ----
# The fulfilment ROW was already unique in every interleaving; the
# notification layer was not: the Deep Scan hook re-logged
# DEEPSCAN_QUEUED and re-sent the HQ Telegram on recovery re-entry
# (F1), ignored a failed send and recorded completion anyway (F2),
# the receipt re-sent when its PAID_EMAIL_SENT record failed to
# persist (F3), and the monitor sent before its durable
# acknowledgement, so a crash re-delivered (F4). The stubs below
# COUNT sends — the older stubs never did, which is exactly how
# the exactly-once gap stayed invisible to the catalog.
N_TG = {"attempts": [], "delivered": []}
N_TG_MODE = {"ok": True, "raise": False}
_prev_tg16 = S.send_telegram


def tg16(text):
    N_TG["attempts"].append(text)
    if N_TG_MODE["raise"]:
        raise RuntimeError("simulated crash inside the send")
    if N_TG_MODE["ok"]:
        N_TG["delivered"].append(text)
    return N_TG_MODE["ok"], "stub"


def tg16_pings(oid):
    return [t for t in N_TG["delivered"]
            if f"Deep Scan order #{oid} is PAID" in t]


S.send_telegram = tg16
_prev_resend16 = S.send_resend
N_MAIL = {"calls": []}


def mail16(to, subject, text, html=None):
    N_MAIL["calls"].append((to, subject))
    return True, "stub-id"


S.send_resend = mail16
_prev_scan16 = S._scan_with_timeout
real_log16 = S.log_event


def mon_row16(oid):
    c = db()
    m = dict(c.execute("SELECT * FROM monitors WHERE order_id=?",
                       (oid,)).fetchone())
    c.close()
    return m


# N1: the v4b interleave — the webhook transition's hook
#     completes, then, BEFORE its completion marker, an admin
#     advance's recovery ensure re-enters the hook. Exactly one
#     row, one DEEPSCAN_QUEUED, one delivered HQ ping; both
#     callers succeed and the order advances.
o16a = mk_order("n1@test.dev", "Deep Scan", 29)
c = db()
row16a = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (o16a,)).fetchone())
c.close()
real_hook16 = S.on_deep_scan_paid
hook16 = {"n": 0}


def interleave_hook(row):
    hook16["n"] += 1
    out = real_hook16(row)
    if hook16["n"] == 1:
        # The admin advance lands here: after the hook returns,
        # before _record_effects_ok (v4b steps 2–4).
        S.ensure_paid_side_effects(row)
    return out


S.on_deep_scan_paid = interleave_hook
won16a = S.transition_order_status(row16a, "PAID")
S.on_deep_scan_paid = real_hook16
row16a["status"] = "PAID"
adv16a = S.transition_order_status(row16a, "IN_PROGRESS")
check("N1 overlap: fulfilment notification exactly once",
      won16a is True and adv16a is True
      and order_status(o16a) == "IN_PROGRESS"
      and count("fulfilment_requests", "order_id=?", (o16a,)) == 1
      and count("events", "order_id=? AND event='DEEPSCAN_QUEUED'",
                (o16a,)) == 1
      and len(tg16_pings(o16a)) == 1)

# N2: crash after the fulfilment row and its notification, before
#     SIDE_EFFECTS_OK persists — the recovery re-entry repeats
#     neither the log nor the ping.
o16b = mk_order("n2@test.dev", "Deep Scan", 29)
c = db()
row16b = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (o16b,)).fetchone())
c.close()
real_rec16 = S._record_effects_ok
rec16 = {"n": 0}


def crashing_rec(oid, tier, note=""):
    rec16["n"] += 1
    if rec16["n"] == 1:
        raise RuntimeError("simulated crash at the marker")
    return real_rec16(oid, tier, note)


S._record_effects_ok = crashing_rec
raised16b = False
try:
    S.transition_order_status(row16b, "PAID")
except RuntimeError:
    raised16b = True
S._record_effects_ok = real_rec16
S.ensure_paid_side_effects(row16b)
check("N2 crash before marker: no repeated notification",
      raised16b and order_status(o16b) == "PAID"
      and count("fulfilment_requests", "order_id=?", (o16b,)) == 1
      and count("events", "order_id=? AND event='DEEPSCAN_QUEUED'",
                (o16b,)) == 1
      and len(tg16_pings(o16b)) == 1
      and count("events", "order_id=? AND event='SIDE_EFFECTS_OK'",
                (o16b,)) == 1)

# N3: the failed-send arm — REWRITTEN in round 18b under the
#     parent's contract-change ruling (cause: Codex delta-17
#     item (g)); the original round-16 (F2) text lives in git
#     history at 5c00365 and in the JOURNAL. The old check
#     pinned the coupling delta-17 refuted as a defect: a
#     stubbed-False HQ send made the transition RAISE and left
#     SIDE_EFFECTS_OK unwritten, so a dead notification
#     channel wedged the order in PAID. Its invariant core
#     survives unchanged and is what is asserted here: exactly
#     one HQ ping once the channel heals, and the order is
#     never lost. Under the round-18 semantics (a plain
#     (False, ...) stub models a DEFINITE rejection — see
#     _send_status) the failure becomes a durable pending
#     record on the notify lock, the transition completes
#     (no raise, marker recorded), and the pending-
#     notification sweep — not the healed channel alone —
#     delivers the queued ping exactly once.
o16c = mk_order("n3@test.dev", "Deep Scan", 29)
c = db()
row16c = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (o16c,)).fetchone())
c.close()
N_TG_MODE["ok"] = False
raised16c = False
won16c = False
try:
    won16c = S.transition_order_status(row16c, "PAID")
except RuntimeError:
    raised16c = True
lock16c = S._lock_row(f"notify:{o16c}")
pre16c = (count("fulfilment_requests", "order_id=?", (o16c,)),
          count("events", "order_id=? AND event='SIDE_EFFECTS_OK'",
                (o16c,)),
          len(tg16_pings(o16c)),
          count("events",
                "order_id=? AND event='DEEPSCAN_NOTIFY_FAILED'",
                (o16c,)))
N_TG_MODE["ok"] = True
# The channel has healed, but nothing re-fires on its own:
# the queued ping stays undelivered until the sweep's
# pending-notification driver runs.
healed16c = len(tg16_pings(o16c))
S.sweep_paid_side_effects()
row16c["status"] = "PAID"
adv16c = S.transition_order_status(row16c, "IN_PROGRESS")
check("N3 failed send: no wedge, sweep delivers once",
      not raised16c and won16c is True
      and pre16c == (1, 1, 0, 1)
      and lock16c is not None
      and lock16c[0] == "deepscan-notify-pending"
      and healed16c == 0
      and adv16c is True
      and order_status(o16c) == "IN_PROGRESS"
      and len(tg16_pings(o16c)) == 1
      and len([t for t in N_TG["attempts"]
               if f"Deep Scan order #{o16c} is PAID"
               in t]) == 2
      and count("events", "order_id=? AND event='DEEPSCAN_QUEUED'",
                (o16c,)) == 1
      and count("events",
                "order_id=? AND event='DEEPSCAN_NOTIFIED'",
                (o16c,)) == 1
      and count("events", "order_id=? AND event='SIDE_EFFECTS_OK'",
                (o16c,)) == 1)

# N4: the ping is delivered but its DEEPSCAN_NOTIFIED record
#     fails to persist — the durable sent-unconfirmed state on
#     the lock row stops a later re-entry from sending it again;
#     the record reconciles on that re-entry.
o16d = mk_order("n4@test.dev", "Deep Scan", 29)
c = db()
row16d = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (o16d,)).fetchone())
c.close()
drop16 = {"notified": True}


def dropping_log16(order_id, event, detail=""):
    if drop16["notified"] and event == "DEEPSCAN_NOTIFIED":
        return  # the write is lost, as log_event swallows failures
    return real_log16(order_id, event, detail)


S.log_event = dropping_log16
won16d = S.transition_order_status(row16d, "PAID")
drop16["notified"] = False
S.log_event = real_log16
S.on_deep_scan_paid(row16d)
check("N4 delivered ping, lost record: no resend",
      won16d is True
      and len(tg16_pings(o16d)) == 1
      and count("events", "order_id=? AND event='DEEPSCAN_NOTIFIED'",
                (o16d,)) == 1
      and count("fulfilment_requests", "order_id=?", (o16d,)) == 1)

# N5: the receipt email is delivered but PAID_EMAIL_SENT fails
#     to persist (F3) — the first ensure reports the send on the
#     strength of the durable sent-unconfirmed record, and the
#     consult never sends a second copy.
o16e = mk_order("n5@test.dev", "Deep Scan", 29)
c = db()
row16e = dict(c.execute("SELECT * FROM orders WHERE id=?",
                        (o16e,)).fetchone())
c.close()
drop16e = {"sent": True}


def dropping_log16e(order_id, event, detail=""):
    if drop16e["sent"] and event == "PAID_EMAIL_SENT":
        return
    return real_log16(order_id, event, detail)


S.log_event = dropping_log16e
first16e = S._ensure_paid_receipt(row16e, 2900)
drop16e["sent"] = False
S.log_event = real_log16
second16e = S._ensure_paid_receipt(row16e, 2900)
check("N5 receipt delivered, record lost: consult honours it",
      first16e is True and second16e is True
      and len([1 for (to, _subj) in N_MAIL["calls"]
               if to == "n5@test.dev"]) == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o16e,)) == 1)

# N6: a retained monitoring alert is delivered, then the process
#     dies before clearing pending_alert (F4) — after the
#     restart the delivered alert is not delivered again.
o16f = mk_order("n6@test.dev", "Monitoring", 79, status="PAID")
pend16f = {"new": ["MEDIUM|N6 hole"], "gone": [], "grade": "B",
           "score": 88,
           "digest_after": ["LOW|base", "MEDIUM|N6 hole"],
           "attempts": 1, "since": S.utcnow()}
c = S.db_connect()
c.execute("INSERT INTO monitors(order_id,url,email,name,created_at,"
          "next_run_at,last_digest,pending_alert) "
          "VALUES(?,?,?,?,?,?,?,?)",
          (o16f, "example.com", "n6@test.dev", "N6", S.utcnow(),
           time.time(), json.dumps(["LOW|base"]),
           json.dumps(pend16f)))
c.commit()
c.close()
S._scan_with_timeout = lambda url: (
    [{"severity": "low", "title": "base"},
     {"severity": "medium", "title": "N6 hole"}],
    {"host": "example.com", "errors": []})
N6_MAIL = {"n": 0, "crash": True}


def mail16f(to, subject, text, html=None):
    if "Monitoring: changes detected" in subject:
        N6_MAIL["n"] += 1
        if N6_MAIL["crash"]:
            N6_MAIL["crash"] = False
            raise RuntimeError(
                "simulated crash after remote acceptance")
    return True, "stub-id"


S.send_resend = mail16f
crashed16f = False
try:
    S._run_monitor(mon_row16(o16f))
except RuntimeError:
    crashed16f = True
S._run_monitor(mon_row16(o16f))
m16f = mon_row16(o16f)
check("N6 retained alert: crash after delivery, no redelivery",
      crashed16f and N6_MAIL["n"] == 1
      and m16f["pending_alert"] is None
      and json.loads(m16f["last_digest"])
      == ["LOW|base", "MEDIUM|N6 hole"])
S.send_resend = mail16

# N7: a fresh monitoring alert is delivered, then the process
#     dies before the state commit (F4) — the alert was retained
#     with its delivery intent first, so the next run reconciles
#     it instead of delivering it again.
o16g = mk_order("n7@test.dev", "Monitoring", 79, status="PAID")
c = S.db_connect()
c.execute("INSERT INTO monitors(order_id,url,email,name,created_at,"
          "next_run_at,last_digest) VALUES(?,?,?,?,?,?,?)",
          (o16g, "example.com", "n7@test.dev", "N7", S.utcnow(),
           time.time(), json.dumps(["LOW|base"])))
c.commit()
c.close()
S._scan_with_timeout = lambda url: (
    [{"severity": "low", "title": "base"},
     {"severity": "medium", "title": "N7 hole"}],
    {"host": "example.com", "errors": []})
N7_MAIL = {"n": 0, "crash": True}


def mail16g(to, subject, text, html=None):
    if "Monitoring: changes detected" in subject:
        N7_MAIL["n"] += 1
        if N7_MAIL["crash"]:
            N7_MAIL["crash"] = False
            raise RuntimeError(
                "simulated crash after remote acceptance")
    return True, "stub-id"


S.send_resend = mail16g
crashed16g = False
try:
    S._run_monitor(mon_row16(o16g))
except RuntimeError:
    crashed16g = True
S._run_monitor(mon_row16(o16g))
m16g = mon_row16(o16g)
check("N7 fresh alert: crash after delivery, no redelivery",
      crashed16g and N7_MAIL["n"] == 1
      and m16g["pending_alert"] is None
      and json.loads(m16g["last_digest"])
      == ["LOW|base", "MEDIUM|N7 hole"])
S.send_resend = mail16

# N8: the attempt-3 escalation Telegram is delivered, then the
#     process dies before 'escalated' persists (F4) — the next
#     run treats the escalation as delivered: no second
#     escalation, weekly cadence.
o16h = mk_order("n8@test.dev", "Monitoring", 79, status="PAID")
pend16h = {"new": ["MEDIUM|N8 hole"], "gone": [], "grade": "B",
           "score": 88,
           "digest_after": ["LOW|base", "MEDIUM|N8 hole"],
           "attempts": 2, "since": S.utcnow()}
c = S.db_connect()
c.execute("INSERT INTO monitors(order_id,url,email,name,created_at,"
          "next_run_at,last_digest,pending_alert) "
          "VALUES(?,?,?,?,?,?,?,?)",
          (o16h, "example.com", "n8@test.dev", "N8", S.utcnow(),
           time.time(), json.dumps(["LOW|base"]),
           json.dumps(pend16h)))
c.commit()
c.close()
S.send_resend = lambda to, subject, text, html=None: (False, "down")
N_TG_MODE["raise"] = True
crashed16h = False
try:
    S._run_monitor(mon_row16(o16h))
except RuntimeError:
    crashed16h = True
N_TG_MODE["raise"] = False
S._run_monitor(mon_row16(o16h))
m16h = mon_row16(o16h)
p16h = json.loads(m16h["pending_alert"])
esc16h = [t for t in N_TG["attempts"]
          if "UNDELIVERED after 3 attempts" in t]
check("N8 escalation: crash after delivery, no re-escalation",
      crashed16h and len(esc16h) == 1
      and p16h["attempts"] == 4 and p16h.get("escalated") is True
      and abs(m16h["next_run_at"] - time.time() - 7 * 86400) < 120)

S.send_telegram = _prev_tg16
S.send_resend = _prev_resend16
S._scan_with_timeout = _prev_scan16

# ---- Round 17 catalog (added 2026-11-10, micro-wave: the
#      MONITOR_ACTIVATED courtesy-log duplicate flagged as an
#      out-of-mandate observation by round 16) ----
# activate_monitor's row was always unique (INSERT OR IGNORE),
# but its MONITOR_ACTIVATED log line fired again on every
# recovery re-entry. The capture below counts log_event calls
# for the event — the stub shape the N-block established.
ACT17 = []


def cap17(order_id, event, detail=""):
    ACT17.append((order_id, event))
    return real_log16(order_id, event, detail)


o17 = mk_order("n9@test.dev", "Monitoring", 79)
c = db()
row17 = dict(c.execute("SELECT * FROM orders WHERE id=?",
                       (o17,)).fetchone())
c.close()
S.log_event = cap17
S.activate_monitor(row17)
# Simulated recovery re-entry: the completion marker never
# landed, the consult re-fires the PAID side effects.
S.ensure_paid_side_effects(row17)
S.log_event = real_log16
check("N9 activation: MONITOR_ACTIVATED exactly once on re-entry",
      len([1 for (oid17, ev17) in ACT17
           if oid17 == o17 and ev17 == "MONITOR_ACTIVATED"]) == 1
      and count("monitors", "order_id=?", (o17,)) == 1
      and count("events", "order_id=? AND event='MONITOR_ACTIVATED'",
                (o17,)) == 1)

# ---- Round 18 catalog (added 2026-11-10, Codex delta-17
#      NO-SHIP: transport truthfulness + guard decoupling) ----
# Delta-17 refuted the round-16/17 guarantees at the TRANSPORT
# seam: the wrappers collapsed a post-acceptance exception into
# a definite failure, so retries duplicated accepted messages
# (a1); a crash between a successful send and its completion
# record left the resend unprotected (a2); log_event emitted
# its process-log line even when the durable insert failed, so
# the reconcile emitted it a second time (b); and F2's raise
# let a failed HQ ping wedge an order in PAID (g). The pins
# below stub the transport BENEATH the wrappers
# (urllib.request.urlopen) — the round-16 stubs replaced the
# wrappers themselves, which model definite outcomes only. The
# genuine wrappers are exercised through a pristine second
# load of server.py (SR): the catalog above permanently
# rebinds S.send_*, so the real functions no longer live in
# S's namespace. SR shares the same throwaway DB.
import importlib.util as _ilu18
import io as _io18
import urllib.error as _uerr18
import urllib.parse as _uparse18
import urllib.request as _ureq18

_spec18 = _ilu18.spec_from_file_location(
    "server_round18", os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "server.py"))
SR = _ilu18.module_from_spec(_spec18)
_spec18.loader.exec_module(SR)
SR.RESEND_API_KEY = "catalog-test-key"
SR.TELEGRAM_BOT_TOKEN = "catalog-test-token"
SR.TELEGRAM_CHAT_ID = "-1004396317271"
SR._guard_public_target = lambda host: None


class _Resp18:
    """A scripted HTTP response. read() returns the body — or
    raises, modelling a provider that ACCEPTED the request and
    whose answer was then lost on the wire."""

    def __init__(self, body=b"{}", read_raises=False):
        self._body = body
        self._read_raises = read_raises

    def read(self, *a):
        if self._read_raises:
            raise OSError("answer lost after acceptance")
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Provider18:
    """Scripted Resend + Telegram behind one urlopen. Email
    deliveries are modelled the way Resend behaves: a request
    carrying an Idempotency-Key is recorded once per key (a
    same-key retry is deduped and returns the original id); a
    request WITHOUT a key is a fresh delivery every time.
    Telegram has no idempotency: every accepted send counts.
    Modes per channel: ok / accept-lost (accepted, then the
    answer is lost) / http4xx (definite rejection, nothing
    accepted) / http5xx."""

    def __init__(self):
        self.mail_mode = "ok"
        self.tg_mode = "ok"
        self.mail_requests = []      # (idem_key, to) per HTTP call
        self.mail_deliveries = {}    # dedupe key -> to (one per key)
        self._mail_seq = 0
        self.tg_requests = []        # text per HTTP call
        self.tg_deliveries = []      # text per accepted send

    def urlopen(self, req, timeout=None):
        if "api.resend.com" in req.full_url:
            return self._mail(req)
        if "api.telegram.org" in req.full_url:
            return self._tg(req)
        raise AssertionError(
            f"unexpected urlopen in round-18 pins: {req.full_url}")

    def _mail(self, req):
        # urllib stores request headers capitalized and its
        # get_header does an exact lookup — scan case-insensitively,
        # as the wire itself is case-insensitive.
        key = None
        for hk, hv in req.headers.items():
            if hk.lower() == "idempotency-key":
                key = hv
        to = json.loads(req.data.decode())["to"][0]
        self.mail_requests.append((key, to))
        if self.mail_mode == "http4xx":
            raise _uerr18.HTTPError(
                req.full_url, 422, "Unprocessable Entity", {},
                _io18.BytesIO(b'{"message":"invalid"}'))
        if self.mail_mode == "http5xx":
            raise _uerr18.HTTPError(
                req.full_url, 500, "Internal Server Error", {},
                _io18.BytesIO(b'{"message":"boom"}'))
        dkey = key if key is not None else f"nokey-{self._mail_seq}"
        self._mail_seq += 1
        if dkey not in self.mail_deliveries:
            self.mail_deliveries[dkey] = to
        if self.mail_mode == "accept-lost":
            return _Resp18(read_raises=True)
        return _Resp18(json.dumps({"id": f"mail-{dkey}"}).encode())

    def _tg(self, req):
        text = _uparse18.parse_qs(req.data.decode())["text"][0]
        self.tg_requests.append(text)
        if self.tg_mode == "http4xx":
            raise _uerr18.HTTPError(
                req.full_url, 400, "Bad Request", {},
                _io18.BytesIO(
                    b'{"ok":false,"description":"bad request"}'))
        if self.tg_mode == "http5xx":
            raise _uerr18.HTTPError(
                req.full_url, 502, "Bad Gateway", {},
                _io18.BytesIO(b'{"ok":false}'))
        self.tg_deliveries.append(text)
        if self.tg_mode == "accept-lost":
            return _Resp18(read_raises=True)
        return _Resp18(b'{"ok":true,"result":{"message_id":1}}')

    def mail_keys_to(self, addr):
        return [k for (k, t) in self.mail_requests if t == addr]

    def mail_delivered_count(self, addr):
        return sum(1 for t in self.mail_deliveries.values()
                   if t == addr)

    def tg_pings(self, oid):
        return [t for t in self.tg_deliveries
                if f"Deep Scan order #{oid} is PAID" in t]

    def tg_attempts(self, oid):
        return [t for t in self.tg_requests
                if f"Deep Scan order #{oid} is PAID" in t]


PROV18 = _Provider18()
_real_urlopen18 = _ureq18.urlopen
_ureq18.urlopen = PROV18.urlopen


def row_of18(oid):
    c = db()
    r = dict(c.execute("SELECT * FROM orders WHERE id=?",
                       (oid,)).fetchone())
    c.close()
    return r


def lock_row18(key):
    c = db()
    r = c.execute("SELECT purpose, claimed_at, owner FROM "
                  "event_locks WHERE event_id=?",
                  (key,)).fetchone()
    c.close()
    return r


class FakeSelf18(SR.Handler):
    """SR twin of FakeSelf: the real webhook entry point with a
    captured reply, signed with the catalog secret."""

    def __init__(self, raw):
        self.replies = []
        self._raw_body = raw
        ts = str(int(time.time()))
        sig = _hmac.new(b"whsec_catalog", ts.encode() + b"." + raw,
                        hashlib.sha256).hexdigest()
        self.headers = {"Stripe-Signature": f"t={ts},v1={sig}"}

    def _send_json(self, code, payload):
        self.replies.append((code, payload))


def stripe_call18(event, session):
    body = dict(event)
    body["data"] = {"object": session}
    fs = FakeSelf18(json.dumps(body).encode())
    SR.Handler._api_stripe_webhook(fs)
    return fs.replies[-1]


class Crash18(BaseException):
    """A process-death simulation: BaseException, so no
    exception handler in the send paths can mistake it for a
    transport outcome."""


# N10: the receipt channel at the transport seam (a1) — Resend
#      accepts, then the answer is lost. The retry must carry
#      the SAME Idempotency-Key; the provider dedupes it into
#      exactly one logical delivery.
o18a = mk_order("n10@test.dev", "Deep Scan", 29, status="PAID")
row18a = row_of18(o18a)
PROV18.mail_mode = "accept-lost"
r18a1 = SR._ensure_paid_receipt(row18a, 2900)
PROV18.mail_mode = "ok"
r18a2 = SR._ensure_paid_receipt(row18a, 2900)
keys18a = PROV18.mail_keys_to("n10@test.dev")
check("N10 receipt: accept-lost retried with same key, one "
      "logical delivery",
      r18a1 is False and r18a2 is True
      and len(keys18a) == 2
      and keys18a[0] == keys18a[1] == f"receipt:{o18a}"
      and PROV18.mail_delivered_count("n10@test.dev") == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o18a,)) == 1)

# N11: the HQ ping at the transport seam (a1) — Telegram
#      accepts, then the answer is lost. Telegram has no
#      idempotency, so the ping is at-most-once: one attempt
#      ever, the durable unknown-outcome state on record, the
#      notification reconciled as delivered, never re-sent.
o18b = mk_order("n11@test.dev", "Deep Scan", 29, status="PAID")
row18b = row_of18(o18b)
PROV18.tg_mode = "accept-lost"
raised18b = False
try:
    SR._fire_deep_scan_notification(row18b)
except Exception:
    raised18b = True
PROV18.tg_mode = "ok"
try:
    SR._fire_deep_scan_notification(row18b)
    SR.ensure_paid_side_effects(row18b)
except Exception:
    raised18b = True
lr18b = lock_row18(f"notify:{o18b}")
check("N11 HQ ping: accept-lost -> one attempt ever, treated "
      "as delivered",
      not raised18b
      and len(PROV18.tg_attempts(o18b)) == 1
      and len(PROV18.tg_pings(o18b)) == 1
      and count("events",
                "order_id=? AND event='DEEPSCAN_NOTIFIED'",
                (o18b,)) == 1
      and lr18b is not None
      and lr18b[0] == "deepscan-notify-pending-unknown")

# N12: the HQ ping DEFINITELY rejected (Telegram 400, nothing
#      accepted) — the failure becomes a durable pending
#      record, the transition completes (no raise, marker
#      recorded), and the sweep retries the pending ping to
#      exactly one delivery.
o18c = mk_order("n12@test.dev", "Deep Scan", 29)
row18c = row_of18(o18c)
PROV18.tg_mode = "http4xx"
won18c = True
try:
    SR.transition_order_status(row18c, "PAID")
except Exception:
    won18c = False
PROV18.tg_mode = "ok"
SR.sweep_paid_side_effects()
check("N12 ping definite failure: pending, no raise, sweep "
      "delivers once",
      won18c and order_status(o18c) == "PAID"
      and count("fulfilment_requests", "order_id=?", (o18c,)) == 1
      and count("events", "order_id=? AND event='SIDE_EFFECTS_OK'",
                (o18c,)) == 1
      and len(PROV18.tg_attempts(o18c)) == 2
      and len(PROV18.tg_pings(o18c)) == 1
      and count("events",
                "order_id=? AND event='DEEPSCAN_NOTIFIED'",
                (o18c,)) == 1)

# N13 (g): Telegram hard-down (definite rejections) must never
#      wedge the order: the payment transition completes, the
#      admin advance PAID -> IN_PROGRESS succeeds with the ping
#      still pending, and once the channel heals the sweep
#      delivers exactly one ping — the order already advanced.
o18d = mk_order("n13@test.dev", "Deep Scan", 29)
row18d = row_of18(o18d)
PROV18.tg_mode = "http4xx"
won18d = True
adv18d = True
try:
    SR.transition_order_status(row18d, "PAID")
except Exception:
    won18d = False
try:
    SR.transition_order_status(row_of18(o18d), "IN_PROGRESS")
except Exception:
    adv18d = False
PROV18.tg_mode = "ok"
SR.sweep_paid_side_effects()
check("N13 (g): Telegram down never wedges the order; ping "
      "lands after advance",
      won18d and adv18d
      and order_status(o18d) == "IN_PROGRESS"
      and count("fulfilment_requests", "order_id=?", (o18d,)) == 1
      and count("events", "order_id=? AND event='SIDE_EFFECTS_OK'",
                (o18d,)) == 1
      and len(PROV18.tg_pings(o18d)) == 1
      and count("events",
                "order_id=? AND event='DEEPSCAN_NOTIFIED'",
                (o18d,)) == 1)

# N14 (g): the receipt channel hard-down (Resend 422) at the
#      webhook — the ack discipline is unchanged (500, Stripe
#      retries), the order still lands PAID and fulfilled and
#      can advance; once Resend heals, the sweep lands exactly
#      one receipt, retried under the same idempotency key.
o18e = mk_order("n14@test.dev", "Deep Scan", 29)
PROV18.mail_mode = "http4xx"
PROV18.tg_mode = "ok"
r18e = stripe_call18(evt("evt_n14"),
                     sess(2900, "n14@test.dev", pi="pi_n14"))
adv18e = True
try:
    SR.transition_order_status(row_of18(o18e), "IN_PROGRESS")
except Exception:
    adv18e = False
PROV18.mail_mode = "ok"
SR.sweep_paid_side_effects()
keys18e = PROV18.mail_keys_to("n14@test.dev")
check("N14 (g): receipt down -> 500 + PAID, advance allowed, "
      "sweep lands one receipt (same key)",
      r18e[0] == 500 and adv18e
      and order_status(o18e) == "IN_PROGRESS"
      and count("fulfilment_requests", "order_id=?", (o18e,)) == 1
      and len(keys18e) == 2
      and keys18e[0] == keys18e[1] == f"receipt:{o18e}"
      and PROV18.mail_delivered_count("n14@test.dev") == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o18e,)) == 1)

# N15 (b): the MONITOR_ACTIVATED events insert fails once —
#      across the fire and the recovery reconcile there is
#      exactly ONE process-log emission and ONE durable record
#      (pre-fix log_event emitted the line even when its insert
#      failed, and the reconcile emitted it again).
o18f = mk_order("n15@test.dev", "Monitoring", 79)
row18f = row_of18(o18f)
EMIT18 = []
_real_log18 = S.log


def _counting_log18(msg):
    EMIT18.append(msg)
    return _real_log18(msg)


_real_connect18 = S.db_connect
_arm18 = {"on": True}


class _FlakyConn18:
    """Fails the first INSERT INTO events at the connection
    seam — the durable write log_event exists to make."""

    def __init__(self, real):
        self._real = real

    def execute(self, sql, args=()):
        if _arm18["on"] and sql.lstrip().upper().startswith(
                "INSERT INTO EVENTS"):
            _arm18["on"] = False
            raise sqlite3.OperationalError(
                "simulated events write failure")
        return self._real.execute(sql, args)

    def __getattr__(self, name):
        return getattr(self._real, name)

    def __setattr__(self, name, value):
        if name == "_real":
            object.__setattr__(self, name, value)
        else:
            setattr(self._real, name, value)


def _flaky_connect18():
    return _FlakyConn18(_real_connect18())


S.db_connect = _flaky_connect18
S.log = _counting_log18
S.activate_monitor(row18f)
S.db_connect = _real_connect18
S.activate_monitor(row18f)
S.log = _real_log18
_emissions18f = [m for m in EMIT18
                 if f"order={o18f} event=MONITOR_ACTIVATED" in m]
check("N15 (b): lost events write -> exactly one process-log "
      "emission",
      len(_emissions18f) == 1
      and count("events",
                "order_id=? AND event='MONITOR_ACTIVATED'",
                (o18f,)) == 1
      and count("monitors", "order_id=?", (o18f,)) == 1)

# N16 (a2): the receipt send is accepted, then the process
#      dies BEFORE the outcome is written (the completion-log
#      call itself is the kill point). The held lock goes stale
#      and is reclaimed; the reclaim resend carries the same
#      idempotency key, so the provider dedupes it — one
#      logical delivery, one completion record.
o18g = mk_order("n16@test.dev", "Deep Scan", 29, status="PAID")
row18g = row_of18(o18g)
_real_log_event18g = SR.log_event
_armed18g = {"on": True}


def _crashing_log18g(order_id, event, detail=""):
    if _armed18g["on"] and event == "PAID_EMAIL_SENT" \
            and order_id == o18g:
        _armed18g["on"] = False
        raise Crash18("crash after provider acceptance")
    return _real_log_event18g(order_id, event, detail)


PROV18.mail_mode = "ok"
SR.log_event = _crashing_log18g
crashed18g = False
try:
    SR._ensure_paid_receipt(row18g, 2900)
except Crash18:
    crashed18g = True
SR.log_event = _real_log_event18g
_c18g = S.db_connect()
_c18g.execute("UPDATE event_locks SET claimed_at=? WHERE "
              "event_id=?", (time.time() - 3700, f"receipt:{o18g}"))
_c18g.commit()
_c18g.close()
r18g = SR._ensure_paid_receipt(row18g, 2900)
keys18g = PROV18.mail_keys_to("n16@test.dev")
check("N16 receipt: crash after acceptance -> same-key "
      "reclaim, one logical delivery",
      crashed18g and r18g is True
      and len(keys18g) == 2
      and keys18g[0] == keys18g[1] == f"receipt:{o18g}"
      and PROV18.mail_delivered_count("n16@test.dev") == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o18g,)) == 1)

# N17 (a2): the HQ ping is accepted, then the process dies
#      BEFORE the outcome is written. The intent record goes
#      stale and is honoured as delivered (at-most-once) — the
#      recovery re-entry reconciles the record and never makes
#      a second attempt.
o18h = mk_order("n17@test.dev", "Deep Scan", 29, status="PAID")
row18h = row_of18(o18h)
_real_log_event18h = SR.log_event
_armed18h = {"on": True}


def _crashing_log18h(order_id, event, detail=""):
    if _armed18h["on"] and event == "DEEPSCAN_NOTIFIED" \
            and order_id == o18h:
        _armed18h["on"] = False
        raise Crash18("crash after provider acceptance")
    return _real_log_event18h(order_id, event, detail)


PROV18.tg_mode = "ok"
SR.log_event = _crashing_log18h
crashed18h = False
try:
    SR._fire_deep_scan_notification(row18h)
except Crash18:
    crashed18h = True
except Exception:
    pass  # pre-fix the hook turns the lost answer into a raise
SR.log_event = _real_log_event18h
_c18h = S.db_connect()
_c18h.execute("UPDATE event_locks SET claimed_at=? WHERE "
              "event_id=?", (time.time() - 3700, f"notify:{o18h}"))
_c18h.commit()
_c18h.close()
raised18h = False
try:
    SR._fire_deep_scan_notification(row18h)
except Exception:
    raised18h = True
check("N17 ping: crash after acceptance -> no second attempt, "
      "reconciled as delivered",
      crashed18h and not raised18h
      and len(PROV18.tg_attempts(o18h)) == 1
      and count("events",
                "order_id=? AND event='DEEPSCAN_NOTIFIED'",
                (o18h,)) == 1)

# N18: a retained monitoring alert whose send ends with the
#      transport outcome UNKNOWN (Resend accepted, the answer
#      was lost) — the outcome is recorded as unknown and the
#      next run retries under the SAME idempotency key (the
#      provider dedupes), instead of the round-16
#      reconcile-as-delivered. Exactly one logical delivery;
#      the digest then advances.
o18i = mk_order("n18@test.dev", "Monitoring", 79, status="PAID")
pend18i = {"new": ["MEDIUM|N18 hole"], "gone": [], "grade": "B",
           "score": 88,
           "digest_after": ["LOW|base", "MEDIUM|N18 hole"],
           "attempts": 1, "since": S.utcnow()}
c = S.db_connect()
c.execute("INSERT INTO monitors(order_id,url,email,name,created_at,"
          "next_run_at,last_digest,pending_alert) "
          "VALUES(?,?,?,?,?,?,?,?)",
          (o18i, "example.com", "n18@test.dev", "N18", S.utcnow(),
           time.time(), json.dumps(["LOW|base"]),
           json.dumps(pend18i)))
c.commit()
c.close()
SR._scan_with_timeout = lambda url: (
    [{"severity": "low", "title": "base"},
     {"severity": "medium", "title": "N18 hole"}],
    {"host": "example.com", "errors": []})
PROV18.mail_mode = "accept-lost"
SR._run_monitor(mon_row16(o18i))
PROV18.mail_mode = "ok"
SR._run_monitor(mon_row16(o18i))
m18i = mon_row16(o18i)
keys18i = PROV18.mail_keys_to("n18@test.dev")
check("N18 monitor alert: unknown outcome -> same-key retry, "
      "one logical delivery",
      len(keys18i) == 2
      and keys18i[0] is not None and keys18i[0] == keys18i[1]
      and PROV18.mail_delivered_count("n18@test.dev") == 1
      and m18i["pending_alert"] is None
      and json.loads(m18i["last_digest"])
      == ["LOW|base", "MEDIUM|N18 hole"])

# N19: the attempt-3 escalation Telegram is accepted, then
#      the answer is lost (UNKNOWN) — at-most-once: the
#      escalation is treated as delivered and never re-fires,
#      even though the email channel keeps failing.
o18j = mk_order("n19@test.dev", "Monitoring", 79, status="PAID")
pend18j = {"new": ["MEDIUM|N19 hole"], "gone": [], "grade": "B",
           "score": 88,
           "digest_after": ["LOW|base", "MEDIUM|N19 hole"],
           "attempts": 2, "since": S.utcnow()}
c = S.db_connect()
c.execute("INSERT INTO monitors(order_id,url,email,name,created_at,"
          "next_run_at,last_digest,pending_alert) "
          "VALUES(?,?,?,?,?,?,?,?)",
          (o18j, "example.com", "n19@test.dev", "N19", S.utcnow(),
           time.time(), json.dumps(["LOW|base"]),
           json.dumps(pend18j)))
c.commit()
c.close()
PROV18.mail_mode = "http4xx"
PROV18.tg_mode = "accept-lost"
SR._run_monitor(mon_row16(o18j))
PROV18.tg_mode = "ok"
SR._run_monitor(mon_row16(o18j))
m18j = mon_row16(o18j)
p18j = json.loads(m18j["pending_alert"])
esc18j = [t for t in PROV18.tg_requests
          if "UNDELIVERED after 3 attempts" in t]
check("N19 escalation: accept-lost -> treated as delivered, "
      "never re-escalated",
      len(esc18j) == 1
      and p18j["attempts"] == 4 and p18j.get("escalated") is True)

_ureq18.urlopen = _real_urlopen18

# ---- Round 19 catalog (added 2026-11-10, Codex delta-18
#      NO-SHIP: classification specimens, the Resend 24h
#      post-window rule, the periodic production driver,
#      orphans, driver isolation, atomic reconcile claims) ----
# Delta-18 certified the N3 contract change and the unmatched
# alert, and refuted four things: (a) a Resend 2xx without an
# id (and a Telegram 2xx without an ok field) were classified
# as definite outcomes instead of unknown; (b) the exactly-
# once claim ignored Resend's 24h idempotency retention — an
# unknown outcome recovered past the window could duplicate;
# (c) the pending-notification driver ran only in the startup
# sweep, order deletion orphaned its locks/links, and one bad
# lookup skipped the rest of a sweep; (d) the sent-unconfirmed
# reconciles (monitor + receipt) had no atomic claim, so two
# racers could both insert + emit. The pins below continue the
# N-block (N20+) against the same beneath-wrapper transport.
import threading as _th19


class _Provider19(_Provider18):
    """Delta-18 (a) specimens: provider answers whose shape
    carries NO proof of acceptance — a Resend 2xx with an
    empty body, a Telegram 2xx with no ok field. Everything
    else inherits the round-18 provider model."""

    def _mail(self, req):
        if self.mail_mode == "empty-ok":
            key = None
            for hk, hv in req.headers.items():
                if hk.lower() == "idempotency-key":
                    key = hv
            to = json.loads(req.data.decode())["to"][0]
            self.mail_requests.append((key, to))
            return _Resp18(b"{}")
        return super()._mail(req)

    def _tg(self, req):
        if self.tg_mode == "no-ok":
            text = _uparse18.parse_qs(
                req.data.decode())["text"][0]
            self.tg_requests.append(text)
            return _Resp18(b'{"result":{"message_id":1}}')
        return super()._tg(req)


PROV19 = _Provider19()
_ureq18.urlopen = PROV19.urlopen


def email_state19(notif_key):
    """The email_delivery row as a tuple, or None — including
    on the pre-fix tree, where the table does not exist."""
    c = db()
    try:
        r = c.execute(
            "SELECT first_unknown_at, post_window_used, settled "
            "FROM email_delivery WHERE notif_key=?",
            (notif_key,)).fetchone()
        return tuple(r) if r is not None else None
    except sqlite3.OperationalError:
        return None
    finally:
        c.close()


def shift_unknown19(notif_key, when):
    c = db()
    try:
        c.execute(
            "UPDATE email_delivery SET first_unknown_at=? "
            "WHERE notif_key=?", (when, notif_key))
        c.commit()
    except sqlite3.OperationalError:
        pass  # pre-fix tree: no table, the pin's state reads fail
    finally:
        c.close()


# N20 (a): a Resend 2xx WITHOUT an id is not proof of
#      acceptance — the wrapper must call it unknown. With an
#      id it is delivered, as before.
PROV19.mail_mode = "empty-ok"
r20a = SR.send_resend("n20@test.dev", "Subject", "body")
PROV19.mail_mode = "ok"
r20b = SR.send_resend("n20@test.dev", "Subject", "body")
check("N20 (a): Resend 2xx without an id -> unknown; with "
      "an id -> delivered",
      SR._send_status(r20a) == "unknown" and r20a[0] is False
      and SR._send_status(r20b) == "delivered"
      and r20b[0] is True)

# N21 (a): a Telegram 2xx WITHOUT an ok field is neither
#      ok:true nor ok:false — unknown, not a definite failure.
PROV19.tg_mode = "no-ok"
r21a = SR.send_telegram("n21 specimen")
PROV19.tg_mode = "ok"
r21b = SR.send_telegram("n21 specimen")
check("N21 (a): Telegram 2xx without ok -> unknown; ok:true "
      "-> delivered",
      SR._send_status(r21a) == "unknown"
      and SR._send_status(r21b) == "delivered")

# N22 (b): a receipt whose first attempt ends UNKNOWN gets
#      its first-attempt time stamped durably; a recovery 2h
#      later (inside the window) retries under the same key —
#      one logical delivery, as in round 18.
o22 = mk_order("n22@test.dev", "Deep Scan", 29, status="PAID")
row22 = row_of18(o22)
PROV19.mail_mode = "accept-lost"
r22a = SR._ensure_paid_receipt(row22, 2900)
st22a = email_state19(f"receipt:{o22}")
shift_unknown19(f"receipt:{o22}", time.time() - 2 * 3600)
PROV19.mail_mode = "ok"
r22b = SR._ensure_paid_receipt(row22, 2900)
keys22 = PROV19.mail_keys_to("n22@test.dev")
st22b = email_state19(f"receipt:{o22}")
check("N22 (b): receipt unknown -> durable first-attempt "
      "stamp; +2h retry same key, one delivery",
      r22a is False and r22b is True
      and st22a is not None and st22a[0] is not None
      and abs(st22a[0] - time.time()) < 120
      and st22b is not None and st22b[1] == 0 and st22b[2] == 0
      and len(keys22) == 2
      and keys22[0] == keys22[1] == f"receipt:{o22}"
      and PROV19.mail_delivered_count("n22@test.dev") == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o22,)) == 1)

# N23 (b): the same receipt recovered 25h after its first
#      unknown attempt — past Resend's retention. Exactly ONE
#      further same-key resend is permitted; whatever its
#      outcome (here: the answer is lost again) the receipt
#      settles as sent-unconfirmed, and a second post-window
#      recovery makes NO further attempt.
o23r = mk_order("n23@test.dev", "Deep Scan", 29, status="PAID")
row23 = row_of18(o23r)
PROV19.mail_mode = "accept-lost"
r23a = SR._ensure_paid_receipt(row23, 2900)
shift_unknown19(f"receipt:{o23r}", time.time() - 25 * 3600)
r23b = SR._ensure_paid_receipt(row23, 2900)
r23c = SR._ensure_paid_receipt(row23, 2900)
keys23 = PROV19.mail_keys_to("n23@test.dev")
st23 = email_state19(f"receipt:{o23r}")
check("N23 (b): receipt past window: one post-window resend, "
      "then settled, no third attempt",
      r23a is False and r23b is True and r23c is True
      and len(keys23) == 2
      and keys23[0] == keys23[1] == f"receipt:{o23r}"
      and PROV19.mail_delivered_count("n23@test.dev") == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o23r,)) == 1
      and st23 is not None and st23[1] == 1 and st23[2] == 1)

# N24 (b): a monitoring alert's first UNKNOWN outcome starts
#      its post-window clock durably (first_unknown_at on the
#      retained record); a recovery 2h later retries under the
#      same key — one logical delivery, digest advances.
o24 = mk_order("n24@test.dev", "Monitoring", 79, status="PAID")
pend24 = {"new": ["MEDIUM|N24 hole"], "gone": [], "grade": "B",
          "score": 88,
          "digest_after": ["LOW|base", "MEDIUM|N24 hole"],
          "attempts": 1, "since": SR.utcnow()}
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,created_at,"
          "next_run_at,last_digest,pending_alert) "
          "VALUES(?,?,?,?,?,?,?,?)",
          (o24, "example.com", "n24@test.dev", "N24", SR.utcnow(),
           time.time(), json.dumps(["LOW|base"]),
           json.dumps(pend24)))
c.commit()
c.close()
SR._scan_with_timeout = lambda url: (
    [{"severity": "low", "title": "base"},
     {"severity": "medium", "title": "N24 hole"}],
    {"host": "example.com", "errors": []})
PROV19.mail_mode = "accept-lost"
SR._run_monitor(mon_row16(o24))
m24a = mon_row16(o24)
p24a = json.loads(m24a["pending_alert"])
stamp24 = p24a.get("first_unknown_at")
if stamp24:
    p24a["first_unknown_at"] = time.time() - 2 * 3600
    c = db()
    c.execute("UPDATE monitors SET pending_alert=? WHERE id=?",
              (json.dumps(p24a), m24a["id"]))
    c.commit()
    c.close()
PROV19.mail_mode = "ok"
SR._run_monitor(mon_row16(o24))
m24b = mon_row16(o24)
keys24 = PROV19.mail_keys_to("n24@test.dev")
check("N24 (b): monitor alert unknown -> clock stamped; +2h "
      "retry same key, one delivery",
      stamp24 is not None and abs(stamp24 - time.time()) < 120
      and len(keys24) == 2 and keys24[0] is not None
      and keys24[0] == keys24[1]
      and PROV19.mail_delivered_count("n24@test.dev") == 1
      and m24b["pending_alert"] is None
      and json.loads(m24b["last_digest"])
      == ["LOW|base", "MEDIUM|N24 hole"])

# N25 (b): a monitoring alert recovered 25h after its first
#      unknown outcome gets exactly ONE further same-key
#      resend; when that resend's answer is lost too, the
#      alert settles as sent-unconfirmed (pending cleared,
#      digest advanced) and a second post-window recovery
#      attempts nothing.
o25 = mk_order("n25@test.dev", "Monitoring", 79, status="PAID")
pend25 = {"new": ["MEDIUM|N25 hole"], "gone": [], "grade": "B",
          "score": 88,
          "digest_after": ["LOW|base", "MEDIUM|N25 hole"],
          "attempts": 1, "since": SR.utcnow(),
          "send_intent": SR.utcnow(), "last_outcome": "unknown",
          "idem": "monitor-alert:n25-pin",
          "first_unknown_at": time.time() - 25 * 3600}
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,created_at,"
          "next_run_at,last_digest,pending_alert) "
          "VALUES(?,?,?,?,?,?,?,?)",
          (o25, "example.com", "n25@test.dev", "N25", SR.utcnow(),
           time.time(), json.dumps(["LOW|base"]),
           json.dumps(pend25)))
c.commit()
c.close()
SR._scan_with_timeout = lambda url: (
    [{"severity": "low", "title": "base"},
     {"severity": "medium", "title": "N25 hole"}],
    {"host": "example.com", "errors": []})
PROV19.mail_mode = "accept-lost"
SR._run_monitor(mon_row16(o25))
PROV19.mail_mode = "ok"
SR._run_monitor(mon_row16(o25))
m25 = mon_row16(o25)
keys25 = PROV19.mail_keys_to("n25@test.dev")
check("N25 (b): monitor alert past window: one post-window "
      "resend, settled, no further attempt",
      len(keys25) == 1 and keys25[0] == "monitor-alert:n25-pin"
      and m25["pending_alert"] is None
      and json.loads(m25["last_digest"])
      == ["LOW|base", "MEDIUM|N25 hole"]
      and count("events", "order_id=? AND event='MONITOR_ALERT_SENT'",
                (o25,)) == 1)

# N26 (c1): the production scheduler tick — not a consult,
#      not a webhook, not the startup sweep — drives a pending
#      ping while the process lives. The order has already
#      advanced; every monitor is parked so the tick's monitor
#      half is idle and only the driver can act.
o26 = mk_order("n26@test.dev", "Deep Scan", 29)
row26 = row_of18(o26)
PROV19.tg_mode = "http4xx"
SR.transition_order_status(row26, "PAID")
SR.transition_order_status(row_of18(o26), "IN_PROGRESS")
c = db()
c.execute("UPDATE monitors SET next_run_at=?",
          (time.time() + 10 ** 9,))
c.commit()
c.close()
PROV19.tg_mode = "ok"
tick19 = getattr(SR, "_monitor_tick", None)
if tick19 is not None:
    tick19()
check("N26 (c1): production tick drives the pending ping",
      tick19 is not None
      and len(PROV19.tg_pings(o26)) == 1
      and count("events",
                "order_id=? AND event='DEEPSCAN_NOTIFIED'",
                (o26,)) == 1)

# N27 (c1): the driver's failure inside a tick is isolated —
#      the tick returns normally, so the scheduler loop (which
#      calls the tick, then sleeps) can never be killed by it.
_real_driver19 = SR._drive_pending_notifications


def _boom_driver19():
    raise RuntimeError("simulated driver failure")


SR._drive_pending_notifications = _boom_driver19
iso27 = tick19 is not None
try:
    if tick19 is not None:
        tick19()
except Exception:
    iso27 = False
SR._drive_pending_notifications = _real_driver19
check("N27 (c1): a failing driver cannot kill the scheduler "
      "tick", iso27)

# N28 (c2): the admin order-delete removes, in the same
#      transaction, the order's notification locks and its
#      stripe_events link rows — nothing is left for the
#      driver to chase or the sweep to misread.
o28 = mk_order("n28@test.dev", "Deep Scan", 29, status="PAID")
c = db()
for _k28, _p28 in ((f"notify:{o28}", "deepscan-notify-pending"),
                   (f"receipt:{o28}", "receipt"),
                   (f"monitor-activate:{o28}", "monitor-activate")):
    c.execute("INSERT INTO event_locks(event_id,purpose,"
              "claimed_at,owner) VALUES(?,?,?,?)",
              (_k28, _p28, time.time(), "pin28"))
c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
          "received_at) VALUES(?,?,?,?)",
          ("evt_n28", "checkout.session.completed", o28,
           SR.utcnow()))
c.commit()
c.close()


class FakeSelf19(SR.Handler):
    """The real admin entry point with a captured reply."""

    def __init__(self):
        self.replies = []
        self.headers = {"X-Admin-Token": "catalog-admin"}

    def _send_json(self, code, payload):
        self.replies.append((code, payload))


SR.ADMIN_TOKEN = "catalog-admin"
fs19 = FakeSelf19()
SR.Handler._api_admin_delete(fs19, f"/api/orders/{o28}")
check("N28 (c2): admin delete removes locks + stripe links "
      "with the order",
      fs19.replies[-1][0] == 200
      and count("orders", "id=?", (o28,)) == 0
      and count("event_locks", "event_id IN (?,?,?)",
                (f"notify:{o28}", f"receipt:{o28}",
                 f"monitor-activate:{o28}")) == 0
      and count("stripe_events", "order_id=?", (o28,)) == 0)

# N29 (c2): a notify lock whose order no longer exists (the
#      pre-round-19 delete left such rows) is garbage-collected
#      by the driver instead of being skipped forever.
ghost29 = 987650
c = db()
c.execute("INSERT INTO event_locks(event_id,purpose,claimed_at,"
          "owner) VALUES(?,?,?,?)",
          (f"notify:{ghost29}", "deepscan-notify-pending",
           time.time(), "pin29"))
c.commit()
c.close()
SR._drive_pending_notifications()
check("N29 (c2): driver collects an orphan notify lock",
      lock_row18(f"notify:{ghost29}") is None)

# N30 (c3): one poisoned item — a database failure on its
#      order lookup — is logged and deferred; the SAME sweep
#      still drives the later item.
o30a = mk_order("n30a@test.dev", "Deep Scan", 29)
o30b = mk_order("n30b@test.dev", "Deep Scan", 29)
PROV19.tg_mode = "http4xx"
SR.transition_order_status(row_of18(o30a), "PAID")
SR.transition_order_status(row_of18(o30b), "PAID")
c = db()
_order30 = [r[0] for r in c.execute(
    "SELECT event_id FROM event_locks WHERE "
    "event_id LIKE 'notify:%' AND purpose IN "
    "('deepscan-notify-pending', 'deepscan-notify-intent', "
    "'deepscan-notify-pending-unknown', "
    "'deepscan-notified-unconfirmed')").fetchall()]
c.close()
_pair30 = [e for e in _order30
           if e in (f"notify:{o30a}", f"notify:{o30b}")]
first30 = int(_pair30[0].split(":", 1)[1])
second30 = o30b if first30 == o30a else o30a
_real_conn19 = SR.db_connect


class _PoisonConn19:
    """Raises on the order lookup for ONE order id — the
    delta-18 (c3) specimen. Everything else delegates."""

    def __init__(self, real):
        self._real = real

    def execute(self, sql, args=()):
        if "FROM orders WHERE id=?" in sql and args \
                and args[0] == first30:
            raise sqlite3.OperationalError(
                "simulated lookup failure (pin N30)")
        return self._real.execute(sql, args)

    def __getattr__(self, name):
        return getattr(self._real, name)

    def __setattr__(self, name, value):
        if name == "_real":
            object.__setattr__(self, name, value)
        else:
            setattr(self._real, name, value)


SR.db_connect = lambda: _PoisonConn19(_real_conn19())
PROV19.tg_mode = "ok"
escaped30 = False
try:
    SR._drive_pending_notifications()
except Exception:
    escaped30 = True
SR.db_connect = _real_conn19
check("N30 (c3): poisoned lookup deferred, later item still "
      "driven in the same sweep",
      not escaped30
      and len(PROV19.tg_pings(second30)) == 1
      and len(PROV19.tg_pings(first30)) == 0)

# N31 (d): two racing MONITOR_ACTIVATED reconciles — both
#      observe the unconfirmed state, but the reconcile is
#      claimed atomically first: exactly one event record and
#      one process-log emission. The slow log_event widens the
#      race so both racers reach the branch before either
#      writes.
o31 = mk_order("n31@test.dev", "Monitoring", 79, status="PAID")
row31 = row_of18(o31)
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,"
          "created_at,next_run_at) VALUES(?,?,?,?,?,?)",
          (o31, "https://example.com", "n31@test.dev", "N31",
           SR.utcnow(), time.time() + 10 ** 9))
c.execute("INSERT INTO event_locks(event_id,purpose,claimed_at,"
          "owner) VALUES(?,?,?,?)",
          (f"monitor-activate:{o31}",
           "monitor-activated-unconfirmed", time.time(), "pin31"))
c.commit()
c.close()
_real_le31 = SR.log_event


def _slow_le31(order_id, event, detail=""):
    if event == "MONITOR_ACTIVATED" and order_id == o31:
        time.sleep(0.5)
    return _real_le31(order_id, event, detail)


EMIT31 = []
_real_log31 = SR.log


def _counting31(msg):
    EMIT31.append(msg)
    return _real_log31(msg)


SR.log_event = _slow_le31
SR.log = _counting31
_ths31 = [_th19.Thread(target=SR.activate_monitor, args=(row31,))
          for _ in range(2)]
for _t in _ths31:
    _t.start()
for _t in _ths31:
    _t.join()
SR.log_event = _real_le31
SR.log = _real_log31
_em31 = [m for m in EMIT31
         if f"order={o31} event=MONITOR_ACTIVATED" in m]
check("N31 (d): racing monitor reconciles -> one record, "
      "one emission",
      len(_em31) == 1
      and count("events",
                "order_id=? AND event='MONITOR_ACTIVATED'",
                (o31,)) == 1
      and count("monitors", "order_id=?", (o31,)) == 1)

# N32 (d): two racing receipt reconciles on the durable
#      sent-unconfirmed record — the claim lives on the lock
#      row's purpose (a takeover transitions the row that
#      already exists; the send path and A5's lifecycle are
#      untouched): exactly one PAID_EMAIL_SENT record and one
#      emission, and the reconcile never sends.
o32 = mk_order("n32@test.dev", "Deep Scan", 29, status="PAID")
row32 = row_of18(o32)
c = db()
c.execute("INSERT INTO event_locks(event_id,purpose,claimed_at,"
          "owner) VALUES(?,?,?,?)",
          (f"receipt:{o32}", "receipt-sent-unconfirmed",
           time.time(), "pin32"))
c.commit()
c.close()
_real_le32 = SR.log_event


def _slow_le32(order_id, event, detail=""):
    if event == "PAID_EMAIL_SENT" and order_id == o32:
        time.sleep(0.5)
    return _real_le32(order_id, event, detail)


EMIT32 = []
_real_log32 = SR.log


def _counting32(msg):
    EMIT32.append(msg)
    return _real_log32(msg)


SR.log_event = _slow_le32
SR.log = _counting32
_ths32 = [_th19.Thread(target=SR._ensure_paid_receipt,
                       args=(row32, 2900)) for _ in range(2)]
for _t in _ths32:
    _t.start()
for _t in _ths32:
    _t.join()
SR.log_event = _real_le32
SR.log = _real_log32
_em32 = [m for m in EMIT32
         if f"order={o32} event=PAID_EMAIL_SENT" in m]
check("N32 (d): racing receipt reconciles -> one record, "
      "one emission, no send",
      len(_em32) == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o32,)) == 1
      and PROV19.mail_keys_to("n32@test.dev") == [])

_ureq18.urlopen = _real_urlopen18

# ---- Round 20 catalog (added 2026-11-10: the periodic tick
#      also drives the paid-side-effects sweep; the admin
#      order-delete cancels a still-queued fulfilment
#      request) ----
# Round 19's final semantics said the durable pending states
# are driven status-independently, and its (c1) wired the
# pending-NOTIFICATION driver into the production tick — but
# pending RECEIPTS were still driven only by webhook consults
# and the startup sweep, so a receipt whose outcome went
# unknown could sit dormant after Stripe's webhook retries
# were exhausted, its bounded post-window attempt never made
# until someone opened the order (the same statement-vs-
# wiring gap delta-18 (c1) caught for pings). And the round-19
# (c2) delete cleanup left a deleted order's
# fulfilment_requests row behind, still offered to the engine
# worker. The pins below continue the N-block (N33+).
_ureq18.urlopen = PROV19.urlopen


def _paid_linked20(email, pi):
    """A Deep Scan order taken PAID by a proven Stripe link:
    the stripe_events row the sweep's receipt loop judges is
    inserted first, then the production transition fires with
    the winning event's identity, exactly as the webhook
    drives it."""
    oid = mk_order(email, "Deep Scan", 29)
    c = db()
    c.execute("INSERT INTO stripe_events(event_id,type,order_id,"
              "received_at,payment_intent,amount) "
              "VALUES(?,?,?,?,?,?)",
              (f"evt_{pi}", "checkout.session.completed", oid,
               SR.utcnow(), pi, 2900))
    c.commit()
    c.close()
    SR.transition_order_status(row_of18(oid), "PAID",
                               paid_event_id=f"evt_{pi}",
                               paid_pi=pi)
    return oid


def _park_monitors20():
    """Idle the tick's monitor half (every monitor parked far
    in the future), as pin N26 does, so only the sweep/driver
    legs can act."""
    c = db()
    c.execute("UPDATE monitors SET next_run_at=?",
              (time.time() + 10 ** 9,))
    c.commit()
    c.close()


# N33 (item 1): a receipt pending on an already-advanced
#      order — first outcome UNKNOWN, channel then healed —
#      is delivered by invoking ONLY the production tick: no
#      webhook, no consult, no startup sweep is called by
#      the pin. One logical delivery under the same
#      idempotency key, as in round 19's N22.
o33 = _paid_linked20("n33@test.dev", "pi_n33")
PROV19.mail_mode = "accept-lost"
r33a = SR._ensure_paid_receipt(row_of18(o33), 2900)
SR.transition_order_status(row_of18(o33), "IN_PROGRESS")
_park_monitors20()
PROV19.mail_mode = "ok"
SR._monitor_tick()
keys33 = PROV19.mail_keys_to("n33@test.dev")
check("N33 (r20): tick alone delivers the pending receipt "
      "on an advanced order, same key, one delivery",
      r33a is False
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o33,)) == 1
      and len(keys33) == 2
      and keys33[0] == keys33[1] == f"receipt:{o33}"
      and PROV19.mail_delivered_count("n33@test.dev") == 1)

# N34 (item 1): the same pending receipt, recovered by the
#      tick alone PAST the 23h safe window (the first unknown
#      outcome was stamped 25h ago): the tick makes the
#      round-19 bounded attempt — exactly one further same-key
#      resend — and the receipt settles as sent-unconfirmed
#      whatever its outcome (here the bounded attempt's answer
#      is lost too); a second tick attempts nothing.
o34 = _paid_linked20("n34@test.dev", "pi_n34")
PROV19.mail_mode = "accept-lost"
r34a = SR._ensure_paid_receipt(row_of18(o34), 2900)
shift_unknown19(f"receipt:{o34}", time.time() - 25 * 3600)
SR.transition_order_status(row_of18(o34), "IN_PROGRESS")
_park_monitors20()
SR._monitor_tick()
st34 = email_state19(f"receipt:{o34}")
keys34a = PROV19.mail_keys_to("n34@test.dev")
SR._monitor_tick()
keys34b = PROV19.mail_keys_to("n34@test.dev")
PROV19.mail_mode = "ok"
check("N34 (r20): tick past window: one bounded same-key "
      "resend, settled, second tick attempts nothing",
      r34a is False
      and len(keys34a) == 2
      and keys34a[0] == keys34a[1] == f"receipt:{o34}"
      and PROV19.mail_delivered_count("n34@test.dev") == 1
      and st34 is not None and st34[1] == 1 and st34[2] == 1
      and count("events", "order_id=? AND event='PAID_EMAIL_SENT'",
                (o34,)) == 1
      and len(keys34b) == 2)

# N35 (item 1): the sweep leg inside the tick is exception-
#      isolated exactly like the driver leg (round 19's N27
#      discipline): a raising sweep neither escapes the tick
#      nor starves the pending-notification driver, which
#      still resolves a pending ping in the same tick. The
#      call counter pins the wiring itself — before round 20
#      the tick never invoked the sweep at all.
o35 = mk_order("n35@test.dev", "Deep Scan", 29)
PROV19.tg_mode = "http4xx"
SR.transition_order_status(row_of18(o35), "PAID")
SR.transition_order_status(row_of18(o35), "IN_PROGRESS")
_park_monitors20()
PROV19.tg_mode = "ok"
_real_sweep20 = SR.sweep_paid_side_effects
_calls35 = []


def _boom_sweep20():
    _calls35.append(1)
    raise RuntimeError("simulated sweep failure (pin N35)")


SR.sweep_paid_side_effects = _boom_sweep20
esc35 = False
try:
    SR._monitor_tick()
except Exception:
    esc35 = True
SR.sweep_paid_side_effects = _real_sweep20
check("N35 (r20): raising sweep isolated in the tick; the "
      "driver still delivers the pending ping",
      not esc35 and len(_calls35) == 1
      and len(PROV19.tg_pings(o35)) == 1)

# N36 (item 2): admin delete of a paid Deep Scan order whose
#      fulfilment request is still queued removes the request
#      in the same transaction — the register the engine
#      worker consumes no longer contains it.
o36 = mk_order("n36@test.dev", "Deep Scan", 29)
SR.transition_order_status(row_of18(o36), "PAID")
q36 = count("fulfilment_requests",
            "order_id=? AND status='queued'", (o36,))
SR.ADMIN_TOKEN = "catalog-admin"
fs20a = FakeSelf19()
SR.Handler._api_admin_delete(fs20a, f"/api/orders/{o36}")
check("N36 (r20): admin delete cancels the queued "
      "fulfilment request",
      q36 == 1
      and fs20a.replies[-1][0] == 200
      and count("orders", "id=?", (o36,)) == 0
      and count("fulfilment_requests", "order_id=?", (o36,)) == 0)

# N37 (item 2): the same delete when the worker has ALREADY
#      picked the request up — a non-queued status, written
#      directly here as the worker's side of the contract
#      writes it ('processing'): the row is left standing and
#      the delete path logs that fact; no cancellation is
#      faked for a fulfilment that may already be running.
o37 = mk_order("n37@test.dev", "Deep Scan", 29)
SR.transition_order_status(row_of18(o37), "PAID")
c = db()
c.execute("UPDATE fulfilment_requests SET status='processing' "
          "WHERE order_id=?", (o37,))
c.commit()
c.close()
LOG37 = []
_real_log37 = SR.log


def _cap_log37(msg):
    LOG37.append(msg)
    return _real_log37(msg)


SR.log = _cap_log37
fs20b = FakeSelf19()
SR.Handler._api_admin_delete(fs20b, f"/api/orders/{o37}")
SR.log = _real_log37
check("N37 (r20): delete leaves an in-flight fulfilment "
      "request standing and logs the fact",
      fs20b.replies[-1][0] == 200
      and count("orders", "id=?", (o37,)) == 0
      and count("fulfilment_requests",
                "order_id=? AND status='processing'",
                (o37,)) == 1
      and any("fulfilment" in m and "left standing" in m
              and f"id={o37}" in m for m in LOG37))

_ureq18.urlopen = _real_urlopen18

failed = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(failed)}/{len(PASS)} catalog checks pass")
if failed:
    print("FAILED:", failed)
    sys.exit(1)
