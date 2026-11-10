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

# ---- Round 21 catalog (added 2026-11-10: Codex delta-19
#      NO-SHIP — (1) a Resend "delivered" requires the message
#      id to be a non-empty STRING; (2a) the post-window spend
#      is claimed atomically, never decided from a pre-claim
#      read, so two racing receipt drivers make exactly one
#      post-window attempt between them; (2b) the first-
#      attempt stamp is written BEFORE the send (first-stamp-
#      wins) for receipts and monitor alerts alike, so a crash
#      at the outcome-recording seam can no longer leave an
#      attempt unstamped; (3) the production tick isolates
#      each monitor run, so one monitor's exception cannot
#      skip the tick's later monitors; (4) deletion is
#      complete — the admin delete and the driver's GC both
#      cover email_delivery rows and monitor:<id> locks;
#      (5) recovery writes are existence-guarded in the same
#      transaction and the send seams re-check existence, so
#      a deleted order gains no new work and no recreated
#      state (a send already inside its HTTP call when the
#      deletion lands may still complete — that residual is
#      accepted, delta-19 (c)). The pins below continue the
#      N-block (N38+) against the same beneath-wrapper
#      transport.


class _Provider21(_Provider19):
    """Delta-19 specimens: a Resend 2xx whose id is not a
    string at all (an object) or an empty string; plus a
    capture hook that snapshots a monitor's retained record
    DURING its alert send — the round-21 pre-send stamp must
    already be on it at that moment."""

    def __init__(self):
        super().__init__()
        self.captured = []   # (to, pending_alert dict | None)

    def _mail(self, req):
        if self.mail_mode in ("object-id", "empty-id"):
            key = None
            for hk, hv in req.headers.items():
                if hk.lower() == "idempotency-key":
                    key = hv
            to = json.loads(req.data.decode())["to"][0]
            self.mail_requests.append((key, to))
            rid = {"unexpected": "object"} \
                if self.mail_mode == "object-id" else ""
            return _Resp18(json.dumps({"id": rid}).encode())
        to = json.loads(req.data.decode())["to"][0]
        c = db()
        r = c.execute(
            "SELECT pending_alert FROM monitors WHERE email=?",
            (to,)).fetchone()
        c.close()
        if r is not None:
            self.captured.append(
                (to, json.loads(r[0]) if r[0] else None))
        return super()._mail(req)

    def captured_for(self, addr):
        return [p for (t, p) in self.captured if t == addr]


PROV21 = _Provider21()
_ureq18.urlopen = PROV21.urlopen


def shift_attempt21(notif_key, when):
    """Age a receipt's first-attempt stamp (round 21); a
    no-op on the pre-fix tree, where the column is absent."""
    c = db()
    try:
        c.execute(
            "UPDATE email_delivery SET first_attempt_at=? "
            "WHERE notif_key=?", (when, notif_key))
        c.commit()
    except sqlite3.OperationalError:
        pass
    finally:
        c.close()


# N38 (1): the Resend wrapper's "delivered" requires the id
#      to be a non-empty string. A truthy non-string id (an
#      object) proves no more about acceptance than a missing
#      one did in round 19: it is unknown.
PROV21.mail_mode = "object-id"
r38a = SR.send_resend("n38@test.dev", "Subject", "body")
PROV21.mail_mode = "empty-id"
r38b = SR.send_resend("n38@test.dev", "Subject", "body")
PROV21.mail_mode = "ok"
r38c = SR.send_resend("n38@test.dev", "Subject", "body")
check("N38 (1): Resend id must be a non-empty string: "
      "object -> unknown, empty -> unknown, string -> "
      "delivered",
      SR._send_status(r38a) == "unknown" and r38a[0] is False
      and SR._send_status(r38b) == "unknown"
      and SR._send_status(r38c) == "delivered"
      and r38c[0] is True)

# N39 (2a): two racing receipt drivers on a receipt past the
#      window — a webhook consult and a scheduler-tick sweep,
#      modelled as two calls on two threads. Driver B is
#      parked at the lock claim AFTER it took its spend
#      decision from the unspent state (the pre-fix order:
#      read state, then claim); driver A then runs a complete
#      pass — claims, spends, sends (answer lost), settles,
#      releases. B resumes and must observe the spent state
#      and settle WITHOUT a second post-window attempt.
o39 = mk_order("n39@test.dev", "Deep Scan", 29, status="PAID")
row39 = row_of18(o39)
PROV21.mail_mode = "accept-lost"
r39a = SR._ensure_paid_receipt(row39, 2900)
shift_unknown19(f"receipt:{o39}", time.time() - 25 * 3600)
_real_claim39 = SR._claim_event_lock
_parked39 = _th19.Event()
_go39 = _th19.Event()
_claims39 = []


def _trap_claim39(key, purpose):
    if key == f"receipt:{o39}" and not _claims39:
        _claims39.append(key)
        _parked39.set()
        _go39.wait(15)
    return _real_claim39(key, purpose)


SR._claim_event_lock = _trap_claim39
_res39 = {}


def _drive39():
    _res39["B"] = SR._ensure_paid_receipt(row39, 2900)


_tB39 = _th19.Thread(target=_drive39)
_tB39.start()
_parked39.wait(5)
_res39["A"] = SR._ensure_paid_receipt(row39, 2900)
_go39.set()
_tB39.join()
SR._claim_event_lock = _real_claim39
PROV21.mail_mode = "ok"
keys39 = PROV21.mail_keys_to("n39@test.dev")
st39 = email_state19(f"receipt:{o39}")
check("N39 (2a): racing drivers past the window -> exactly "
      "one post-window attempt, terminal settled state",
      r39a is False
      and _res39.get("A") is True and _res39.get("B") is True
      and len(keys39) == 2
      and keys39[0] == keys39[1] == f"receipt:{o39}"
      and PROV21.mail_delivered_count("n39@test.dev") == 1
      and st39 is not None and st39[1] == 1 and st39[2] == 1
      and count("events",
                "order_id=? AND event='PAID_EMAIL_SENT'",
                (o39,)) == 1)

# N40 (2b): the crash at the outcome-recording seam — the
#      provider accepted the receipt send, its answer was
#      lost, and the process died BEFORE the unknown outcome
#      could be stamped (the stamping call itself raises a
#      BaseException, as a death would). The attempt itself
#      was stamped BEFORE the send (round 21), so recovery
#      25h later recognizes the expired window and takes the
#      bounded post-window path — one claimed attempt, then
#      settled — never an unrecognized fresh resend.
o40 = mk_order("n40@test.dev", "Deep Scan", 29, status="PAID")
row40 = row_of18(o40)
_real_note40 = SR._email_note_unknown


def _crash_note40(notif_key):
    raise Crash18("process died at outcome recording "
                  "(pin N40)")


SR._email_note_unknown = _crash_note40
PROV21.mail_mode = "accept-lost"
crashed40 = False
try:
    SR._ensure_paid_receipt(row40, 2900)
except Crash18:
    crashed40 = True
SR._email_note_unknown = _real_note40
shift_attempt21(f"receipt:{o40}", time.time() - 25 * 3600)
r40b = SR._ensure_paid_receipt(row40, 2900)
r40c = SR._ensure_paid_receipt(row40, 2900)
PROV21.mail_mode = "ok"
keys40 = PROV21.mail_keys_to("n40@test.dev")
st40 = email_state19(f"receipt:{o40}")
check("N40 (2b): crash after an accepted unknown send -> "
      "+25h recovery takes the bounded claimed path, "
      "settles, attempts nothing further",
      crashed40 and r40b is True and r40c is True
      and len(keys40) == 2
      and keys40[0] == keys40[1] == f"receipt:{o40}"
      and PROV21.mail_delivered_count("n40@test.dev") == 1
      and st40 is not None and st40[1] == 1 and st40[2] == 1)

# N41 (2b): a monitor alert's window stamp precedes its
#      send: while the FRESH alert's send is on the wire,
#      the retained record the provider-side snapshot reads
#      ALREADY carries first_unknown_at (round 19 stamped it
#      only after the outcome returned).
o41 = mk_order("n41@test.dev", "Monitoring", 79, status="PAID")
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,"
          "created_at,next_run_at,last_digest) "
          "VALUES(?,?,?,?,?,?,?)",
          (o41, "example.com", "n41@test.dev", "N41",
           SR.utcnow(), time.time(), json.dumps(["LOW|base"])))
c.commit()
c.close()
SR._scan_with_timeout = lambda url: (
    [{"severity": "low", "title": "base"},
     {"severity": "medium", "title": "N41 hole"}],
    {"host": "example.com", "errors": []})
PROV21.mail_mode = "accept-lost"
SR._run_monitor(mon_row16(o41))
PROV21.mail_mode = "ok"
cap41 = PROV21.captured_for("n41@test.dev")
cap41 = cap41[-1] if cap41 else None
check("N41 (2b): fresh alert: first_unknown_at is on the "
      "retained record before the send",
      cap41 is not None
      and cap41.get("first_unknown_at") is not None
      and abs(cap41["first_unknown_at"] - time.time()) < 120)

# N42 (2b): the same pre-send stamp on the RETAINED path —
#      the intent write that precedes a retained alert's
#      resend carries the stamp too, not just the outcome
#      write that follows it.
o42 = mk_order("n42@test.dev", "Monitoring", 79, status="PAID")
pend42 = {"new": ["MEDIUM|N42 hole"], "gone": [], "grade": "B",
          "score": 88,
          "digest_after": ["LOW|base", "MEDIUM|N42 hole"],
          "attempts": 1, "since": SR.utcnow()}
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,"
          "created_at,next_run_at,last_digest,pending_alert) "
          "VALUES(?,?,?,?,?,?,?,?)",
          (o42, "example.com", "n42@test.dev", "N42",
           SR.utcnow(), time.time(), json.dumps(["LOW|base"]),
           json.dumps(pend42)))
c.commit()
c.close()
SR._scan_with_timeout = lambda url: (
    [{"severity": "low", "title": "base"},
     {"severity": "medium", "title": "N42 hole"}],
    {"host": "example.com", "errors": []})
PROV21.mail_mode = "accept-lost"
SR._run_monitor(mon_row16(o42))
PROV21.mail_mode = "ok"
cap42 = PROV21.captured_for("n42@test.dev")
cap42 = cap42[-1] if cap42 else None
check("N42 (2b): retained alert: first_unknown_at is "
      "stamped with the intent, before the send",
      cap42 is not None
      and cap42.get("first_unknown_at") is not None
      and abs(cap42["first_unknown_at"] - time.time()) < 120)

# N43 (3): the production tick isolates each monitor run:
#      the first due monitor's run raises, and the tick's
#      later monitor still runs in the same pass (its
#      last_run_at advances).
_park_monitors20()
o43a = mk_order("n43a@test.dev", "Monitoring", 79, status="PAID")
o43b = mk_order("n43b@test.dev", "Monitoring", 79, status="PAID")
c = db()
for _o43, _e43, _due43 in (
        (o43a, "n43a@test.dev", time.time() - 10),
        (o43b, "n43b@test.dev", time.time() - 5)):
    c.execute("INSERT INTO monitors(order_id,url,email,name,"
              "created_at,next_run_at,last_digest) "
              "VALUES(?,?,?,?,?,?,?)",
              (_o43, "example.com", _e43, "N43", SR.utcnow(),
               _due43, json.dumps(["LOW|base"])))
c.commit()
c.close()
mid43a = mon_row16(o43a)["id"]
_real_run43 = SR._run_monitor


def _poison_run43(mon, scheduled=False):
    if mon["id"] == mid43a:
        raise RuntimeError("simulated monitor failure "
                           "(pin N43)")
    return _real_run43(mon, scheduled=scheduled)


SR._scan_with_timeout = lambda url: (
    [{"severity": "low", "title": "base"}],
    {"host": "example.com", "errors": []})
SR._run_monitor = _poison_run43
SR._monitor_tick()
SR._run_monitor = _real_run43
m43b = mon_row16(o43b)
check("N43 (3): one monitor's exception does not skip the "
      "tick's later monitors",
      bool(m43b["last_run_at"]) and m43b["last_run_at"] > 0)

# N44 (4): the admin order-delete removes, in the same
#      transaction, the order's email_delivery row and the
#      monitor:<monitor_id> locks of its monitors — the two
#      families round 19/20 left behind.
o44 = mk_order("n44@test.dev", "Monitoring", 79, status="PAID")
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,"
          "created_at,next_run_at) VALUES(?,?,?,?,?,?)",
          (o44, "example.com", "n44@test.dev", "N44",
           SR.utcnow(), time.time() + 10 ** 9))
c.commit()
c.close()
mid44 = mon_row16(o44)["id"]
c = db()
c.execute("INSERT INTO email_delivery(notif_key,"
          "first_unknown_at) VALUES(?,?)",
          (f"receipt:{o44}", time.time()))
c.execute("INSERT INTO event_locks(event_id,purpose,"
          "claimed_at,owner) VALUES(?,?,?,?)",
          (f"monitor:{mid44}", "monitor", time.time(), "pin44"))
c.commit()
c.close()
SR.ADMIN_TOKEN = "catalog-admin"
fs21a = FakeSelf19()
SR.Handler._api_admin_delete(fs21a, f"/api/orders/{o44}")
check("N44 (4): admin delete also removes the order's "
      "email_delivery row and its monitors' locks",
      fs21a.replies[-1][0] == 200
      and count("orders", "id=?", (o44,)) == 0
      and count("monitors", "order_id=?", (o44,)) == 0
      and count("email_delivery", "notif_key=?",
                (f"receipt:{o44}",)) == 0
      and count("event_locks", "event_id=?",
                (f"monitor:{mid44}",)) == 0)

# N45 (4): the driver's garbage collection extends beyond
#      notify: locks — a monitor: lock whose monitor row is
#      gone and an email_delivery row whose order is gone
#      are collected; rows belonging to live monitors and
#      orders are spared.
ghost45 = 987651
live45 = mk_order("n45@test.dev", "Deep Scan", 29, status="PAID")
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,"
          "created_at,next_run_at) VALUES(?,?,?,?,?,?)",
          (live45, "example.com", "n45@test.dev", "N45",
           SR.utcnow(), time.time() + 10 ** 9))
c.commit()
c.close()
mid45live = mon_row16(live45)["id"]
c = db()
c.execute("INSERT INTO event_locks(event_id,purpose,"
          "claimed_at,owner) VALUES(?,?,?,?)",
          (f"monitor:{ghost45}", "monitor", time.time(),
           "pin45"))
c.execute("INSERT INTO event_locks(event_id,purpose,"
          "claimed_at,owner) VALUES(?,?,?,?)",
          (f"monitor:{mid45live}", "monitor", time.time(),
           "pin45"))
c.execute("INSERT INTO email_delivery(notif_key,"
          "first_unknown_at) VALUES(?,?)",
          (f"receipt:{ghost45}", time.time()))
c.execute("INSERT INTO email_delivery(notif_key,"
          "first_unknown_at) VALUES(?,?)",
          (f"receipt:{live45}", time.time()))
c.commit()
c.close()
SR._drive_pending_notifications()
check("N45 (4): driver GC collects orphan monitor locks "
      "and orphan email rows, spares live ones",
      lock_row18(f"monitor:{ghost45}") is None
      and email_state19(f"receipt:{ghost45}") is None
      and email_state19(f"receipt:{live45}") is not None
      and lock_row18(f"monitor:{mid45live}") is not None)

# N46 (5a): the named deletion specimen — a paid snapshot is
#      obtained, the order is deleted, THEN the Deep Scan
#      hook resumes: it must write nothing (no fulfilment
#      row), claim nothing (no notify lock) and send nothing
#      (no ping attempted).
o46 = mk_order("n46@test.dev", "Deep Scan", 29, status="PAID")
row46 = row_of18(o46)
fs21b = FakeSelf19()
SR.Handler._api_admin_delete(fs21b, f"/api/orders/{o46}")
SR.on_deep_scan_paid(row46)
check("N46 (5a): hook resumed after deletion writes "
      "nothing: no fulfilment row, no notify lock, no ping",
      fs21b.replies[-1][0] == 200
      and count("fulfilment_requests", "order_id=?",
                (o46,)) == 0
      and lock_row18(f"notify:{o46}") is None
      and PROV21.tg_attempts(o46) == [])

# N47 (5a): monitor activation resumed after deletion
#      recreates nothing — no monitor row, no activation
#      lock, no MONITOR_ACTIVATED record.
o47 = mk_order("n47@test.dev", "Monitoring", 79, status="PAID")
row47 = row_of18(o47)
fs21c = FakeSelf19()
SR.Handler._api_admin_delete(fs21c, f"/api/orders/{o47}")
SR.activate_monitor(row47)
check("N47 (5a): activation resumed after deletion "
      "recreates no monitor row, lock or log",
      count("monitors", "order_id=?", (o47,)) == 0
      and lock_row18(f"monitor-activate:{o47}") is None
      and count("events",
                "order_id=? AND event='MONITOR_ACTIVATED'",
                (o47,)) == 0)

# N48 (5a): receipt recovery driven for a deleted order
#      writes no durable state (no email_delivery row, no
#      receipt lock) and sends nothing.
o48 = mk_order("n48@test.dev", "Deep Scan", 29, status="PAID")
row48 = row_of18(o48)
fs21d = FakeSelf19()
SR.Handler._api_admin_delete(fs21d, f"/api/orders/{o48}")
PROV21.mail_mode = "ok"
r48 = SR._ensure_paid_receipt(row48, 2900)
check("N48 (5a): receipt recovery on a deleted order "
      "writes no state and sends nothing",
      r48 is False
      and PROV21.mail_keys_to("n48@test.dev") == []
      and email_state19(f"receipt:{o48}") is None
      and lock_row18(f"receipt:{o48}") is None)

# N49 (5b): a monitor run holding its snapshot when its
#      order (and monitor row) is deleted mid-run — the
#      deletion lands inside the retained alert's send
#      preparation — re-reads the monitor row at the send
#      seam and drops the work: no alert send is attempted
#      and no state is recreated.
o49 = mk_order("n49@test.dev", "Monitoring", 79, status="PAID")
pend49 = {"new": ["MEDIUM|N49 hole"], "gone": [],
          "grade": "B", "score": 88,
          "digest_after": ["LOW|base", "MEDIUM|N49 hole"],
          "attempts": 1, "since": SR.utcnow()}
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,"
          "created_at,next_run_at,last_digest,pending_alert) "
          "VALUES(?,?,?,?,?,?,?,?)",
          (o49, "example.com", "n49@test.dev", "N49",
           SR.utcnow(), time.time(), json.dumps(["LOW|base"]),
           json.dumps(pend49)))
c.commit()
c.close()
_real_idem49 = SR._monitor_alert_idem


def _deleting_idem49(mon, pending):
    fs = FakeSelf19()
    SR.Handler._api_admin_delete(fs, f"/api/orders/{o49}")
    return _real_idem49(mon, pending)


SR._monitor_alert_idem = _deleting_idem49
SR._scan_with_timeout = lambda url: (
    [{"severity": "low", "title": "base"}],
    {"host": "example.com", "errors": []})
PROV21.mail_mode = "ok"
SR._run_monitor(mon_row16(o49))
SR._monitor_alert_idem = _real_idem49
check("N49 (5b): monitor deleted mid-run (retained alert): "
      "no alert send attempted, no state recreated",
      PROV21.mail_keys_to("n49@test.dev") == []
      and count("monitors", "order_id=?", (o49,)) == 0)

# N50 (5b): the same seam on the fresh path — the deletion
#      lands while the run is inside its scan; the fresh
#      alert's send is aborted at the seam.
o50 = mk_order("n50@test.dev", "Monitoring", 79, status="PAID")
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,"
          "created_at,next_run_at,last_digest) "
          "VALUES(?,?,?,?,?,?,?)",
          (o50, "example.com", "n50@test.dev", "N50",
           SR.utcnow(), time.time(), json.dumps(["LOW|base"])))
c.commit()
c.close()
_real_scan50 = SR._scan_with_timeout


def _deleting_scan50(url):
    fs = FakeSelf19()
    SR.Handler._api_admin_delete(fs, f"/api/orders/{o50}")
    return ([{"severity": "low", "title": "base"},
             {"severity": "medium", "title": "N50 hole"}],
            {"host": "example.com", "errors": []})


SR._scan_with_timeout = _deleting_scan50
PROV21.mail_mode = "ok"
SR._run_monitor(mon_row16(o50))
SR._scan_with_timeout = _real_scan50
check("N50 (5b): monitor deleted mid-scan (fresh alert): "
      "no alert send attempted, no state recreated",
      PROV21.mail_keys_to("n50@test.dev") == []
      and count("monitors", "order_id=?", (o50,)) == 0)

# N51 (5b): the receipt send seam — the deletion lands in
#      the gap between the pre-send stamp and the send
#      itself (the stamp helper is wrapped to delete after
#      stamping, through the real admin endpoint): no send
#      is attempted and nothing is left behind — the delete
#      transaction itself removed the stamp and the lock.
o51 = mk_order("n51@test.dev", "Deep Scan", 29, status="PAID")
row51 = row_of18(o51)
_note51 = getattr(SR, "_email_note_attempt", None)
if _note51 is not None:
    def _deleting_note51(notif_key):
        _note51(notif_key)
        fs = FakeSelf19()
        SR.Handler._api_admin_delete(fs, f"/api/orders/{o51}")

    SR._email_note_attempt = _deleting_note51
PROV21.mail_mode = "ok"
r51 = SR._ensure_paid_receipt(row51, 2900)
if _note51 is not None:
    SR._email_note_attempt = _note51
check("N51 (5b): order deleted between the receipt stamp "
      "and the send: no send, no state left behind",
      r51 is False
      and PROV21.mail_keys_to("n51@test.dev") == []
      and email_state19(f"receipt:{o51}") is None
      and lock_row18(f"receipt:{o51}") is None)

# N52 (5b): the notify send seam — the deletion lands after
#      the DEEPSCAN_QUEUED record and before the ping (the
#      log write is wrapped to delete through the real
#      admin endpoint once the record lands): no ping is
#      attempted and no notify lock is left standing.
o52 = mk_order("n52@test.dev", "Deep Scan", 29, status="PAID")
row52 = row_of18(o52)
_real_le52 = SR.log_event


def _deleting_le52(order_id, event, detail=""):
    out = _real_le52(order_id, event, detail)
    if event == "DEEPSCAN_QUEUED" and order_id == o52:
        fs = FakeSelf19()
        SR.Handler._api_admin_delete(fs, f"/api/orders/{o52}")
    return out


SR.log_event = _deleting_le52
PROV21.tg_mode = "ok"
SR._fire_deep_scan_notification(row52)
SR.log_event = _real_le52
check("N52 (5b): order deleted between the QUEUED record "
      "and the ping: no ping attempted, no lock left",
      PROV21.tg_attempts(o52) == []
      and lock_row18(f"notify:{o52}") is None)

# ============================================================
# Round 22 (Codex delta-20): tombstone-first deletion,
# no-resurrect bookkeeping, first-unknown basis restored.
# Delta-20 refuted round 21 on three arms: (1) outcome
# bookkeeping RESURRECTS state after deletion
# (_email_note_unknown / _email_mark are UPSERTs; the final
# _record_effects_ok recreates an orphan SIDE_EFFECTS_OK
# event); (2) the existence checks and the sends are separate
# operations — a deletion landing in the check-to-send gap
# still starts a NEW send, and the monitor ESCALATION
# Telegram send has no existence check at all; (3) round 21's
# window basis (the earliest stamp of the row, i.e. the first
# ATTEMPT) is a contract change against round 19's
# first-UNKNOWN basis — the parent REJECTED the widening.
# Round 22: the admin delete writes a durable tombstone
# (deleted_orders) FIRST, inside the same _db_lock
# transaction; every send seam (receipt email, Deep Scan HQ
# ping, monitor alert email, monitor escalation Telegram)
# re-consults existence+tombstone at the seam under the same
# lock discipline, so a seam check after the tombstone aborts
# with no send and no writes; the email bookkeeping writers
# are UPDATE-only / tombstone-guarded; the window basis is
# the first UNKNOWN outcome again, with the conservative
# crash arm (an attempt whose outcome was never recorded
# counts its pre-send attempt stamp). The pins below drive
# the genuine wrappers through SR with the transport stubbed
# beneath them; deletions are executed through the REAL
# admin endpoint (FakeSelf19) from inside the wrapped seam.
PROV22 = _Provider21()
_ureq18.urlopen = PROV22.urlopen


def tombstone_of22(oid):
    """The durable deleted-order tombstone, or False — on the
    pre-fix tree the table does not exist."""
    c = db()
    try:
        r = c.execute("SELECT 1 FROM deleted_orders WHERE "
                      "order_id=?", (oid,)).fetchone()
        return r is not None
    except sqlite3.OperationalError:
        return False
    finally:
        c.close()


def admin_delete22(oid):
    fs = FakeSelf19()
    SR.Handler._api_admin_delete(fs, f"/api/orders/{oid}")
    return fs.replies[-1][0] if fs.replies else None


def _stale_wrap22(target):
    """Wrap SR's existence checks so a deletion lands INSIDE
    the check-to-send gap: the first check for the target
    order executes the real admin delete and still returns
    the stale pre-deletion answer; every later check for that
    order keeps returning the stale answer, modelling a
    caller acting on a decision taken before the deletion.
    The round-22 seam gate consults the tombstone directly
    (not through these helpers), which is exactly the
    serialization the fix adds."""
    real_exists = SR._order_exists
    real_alive = getattr(SR, "_order_alive", None)
    box = {"done": False}

    def _stale(oid):
        if oid == target:
            if not box["done"]:
                box["done"] = True
                admin_delete22(oid)
            return True
        return real_exists(oid)

    SR._order_exists = _stale
    if real_alive is not None:
        SR._order_alive = _stale

    def _restore():
        SR._order_exists = real_exists
        if real_alive is not None:
            SR._order_alive = real_alive
    return _restore


# N53 (1): the receipt seam — a deletion landing inside the
#      entry-check-to-send gap (through the real admin
#      endpoint, inside the wrapped existence check) must
#      abort the send at the round-22 gate: no email starts,
#      no email_delivery row is created, no lock is left.
o53 = mk_order("n53@test.dev", "Deep Scan", 29, status="PAID")
row53 = row_of18(o53)
_restore53 = _stale_wrap22(o53)
PROV22.mail_mode = "ok"
r53 = SR._ensure_paid_receipt(row53, 2900)
_restore53()
check("N53 (1): receipt — deletion inside the check-to-send "
      "gap aborts at the seam gate: no send, no email row, "
      "no lock, tombstone recorded",
      r53 is False
      and PROV22.mail_keys_to("n53@test.dev") == []
      and email_state19(f"receipt:{o53}") is None
      and lock_row18(f"receipt:{o53}") is None
      and tombstone_of22(o53))

# N54 (1): the Deep Scan ping seam, same gap: the ping never
#      starts and the notify lock the fire claimed on the way
#      in is released again.
o54 = mk_order("n54@test.dev", "Deep Scan", 29, status="PAID")
row54 = row_of18(o54)
_restore54 = _stale_wrap22(o54)
PROV22.tg_mode = "ok"
SR._fire_deep_scan_notification(row54)
_restore54()
check("N54 (1): ping — deletion inside the check-to-send "
      "gap aborts at the seam gate: no ping attempted, no "
      "notify lock left",
      PROV22.tg_attempts(o54) == []
      and lock_row18(f"notify:{o54}") is None
      and tombstone_of22(o54))

# N55 (1): the monitor alert email seam — the deletion lands
#      during alert composition (inside the wrapped parts
#      builder, after every earlier existence check passed):
#      the send must not start.
o55 = mk_order("n55@test.dev", "Monitoring", 79, status="PAID")
pend55 = {"since": SR.utcnow(), "new": [], "gone": [],
          "grade": "B", "score": 88,
          "digest_after": "d55", "attempts": 1}
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,"
          "created_at,next_run_at,last_digest,pending_alert) "
          "VALUES(?,?,?,?,?,?,?,?)",
          (o55, "example.com", "n55@test.dev", "N55",
           SR.utcnow(), time.time(), json.dumps(["LOW|base"]),
           json.dumps(pend55)))
c.commit()
c.close()
m55 = mon_row16(o55)
_real_parts55 = SR._monitor_alert_parts


def _deleting_parts55(mon, host, order_id, new, gone,
                      grade, score):
    parts = _real_parts55(mon, host, order_id, new, gone,
                          grade, score)
    admin_delete22(o55)
    return parts


SR._monitor_alert_parts = _deleting_parts55
PROV22.mail_mode = "ok"
SR._run_monitor(dict(m55))
SR._monitor_alert_parts = _real_parts55
check("N55 (1): monitor alert — deletion during composition "
      "aborts at the seam gate: no alert email starts",
      PROV22.mail_keys_to("n55@test.dev") == []
      and count("events", "order_id=?", (o55,)) == 0)

# N56 (1): the monitor ESCALATION Telegram send — delta-20
#      found it has NO existence check at all. A retained
#      alert fails definitely for the third time; the
#      deletion lands inside the failure log write, after
#      which the escalation would start: it must not.
o56 = mk_order("n56@test.dev", "Monitoring", 79, status="PAID")
pend56 = {"since": SR.utcnow(), "new": [], "gone": [],
          "grade": "B", "score": 88,
          "digest_after": "d56", "attempts": 2}
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,"
          "created_at,next_run_at,last_digest,pending_alert) "
          "VALUES(?,?,?,?,?,?,?,?)",
          (o56, "https://n56.example.com", "n56@test.dev",
           "N56", SR.utcnow(), time.time(),
           json.dumps(["LOW|base"]), json.dumps(pend56)))
c.commit()
c.close()
m56 = mon_row16(o56)
_real_le56 = SR.log_event


def _deleting_le56(order_id, event, detail=""):
    out = _real_le56(order_id, event, detail)
    if event == "MONITOR_ALERT_FAILED" and order_id == o56:
        admin_delete22(o56)
    return out


SR.log_event = _deleting_le56
PROV22.mail_mode = "http4xx"
PROV22.tg_mode = "ok"
SR._run_monitor(dict(m56))
SR.log_event = _real_le56
check("N56 (1): escalation — order deleted after the third "
      "failed attempt, before the escalation send: no "
      "escalation Telegram starts",
      [t for t in PROV22.tg_requests
       if "n56.example.com" in t] == [])

# N57 (1): a pending-work driver pass over a TOMBSTONED
#      order (its order row still present — the tombstone,
#      not the row removal, is what marks the work dead):
#      the pending ping is dropped without firing and the GC
#      collects the notify lock and the receipt email row.
o57 = mk_order("n57@test.dev", "Deep Scan", 29, status="PAID")
c = db()
c.execute("INSERT INTO event_locks(event_id, purpose, "
          "claimed_at, owner) VALUES(?,?,?,?)",
          (f"notify:{o57}", "deepscan-notify-pending",
           SR.time.time(), "owner-57"))
try:
    c.execute("INSERT INTO email_delivery(notif_key) "
              "VALUES(?)", (f"receipt:{o57}",))
except sqlite3.OperationalError:
    pass
try:
    c.execute("INSERT INTO deleted_orders(order_id, "
              "deleted_at) VALUES(?,?)",
              (o57, SR.time.time()))
except sqlite3.OperationalError:
    pass  # pre-fix tree: no tombstone table — the driver
    # fires the pending ping and the pin fails as required
c.commit()
c.close()
PROV22.tg_mode = "ok"
SR._drive_pending_notifications()
check("N57 (1): driver over a tombstoned order: pending "
      "ping dropped unfired, notify lock and receipt email "
      "row collected, order row itself untouched",
      PROV22.tg_attempts(o57) == []
      and lock_row18(f"notify:{o57}") is None
      and email_state19(f"receipt:{o57}") is None
      and count("orders", "id=?", (o57,)) == 1)

# N58 (2): an in-flight receipt send whose answer is lost
#      (unknown) AFTER the order was deleted mid-send (the
#      deletion executes inside the wrapped transport): the
#      outcome bookkeeping must not resurrect the
#      email_delivery row the delete transaction removed,
#      and no event may be written for the dead order. The
#      direct-call arm pins the writers themselves.
o58 = mk_order("n58@test.dev", "Deep Scan", 29, status="PAID")
row58 = row_of18(o58)
_real_send58 = SR.send_resend


def _deleting_send58(to, subject, text, html=None):
    admin_delete22(o58)
    return SR._SendOutcome(False, "answer lost after "
                           "acceptance", "unknown")


SR.send_resend = _deleting_send58
r58 = SR._ensure_paid_receipt(row58, 2900)
SR.send_resend = _real_send58
SR._email_note_unknown(f"receipt:{o58}")
SR._email_mark(f"receipt:{o58}", "settled")
check("N58 (2): unknown outcome recorded after deletion "
      "does not resurrect the email row; no orphan events",
      r58 is False
      and email_state19(f"receipt:{o58}") is None
      and count("events", "order_id=?", (o58,)) == 0)

# N59 (2): ensure_paid_side_effects paused after its entry
#      check (the wrapped activate_monitor deletes the order
#      through the real endpoint, then runs the real
#      activation, which no-ops on the dead order): the final
#      _record_effects_ok must skip — no orphan
#      SIDE_EFFECTS_OK event is recreated.
o59 = mk_order("n59@test.dev", "Monitoring", 79, status="PAID")
row59 = row_of18(o59)
_real_act59 = SR.activate_monitor


def _deleting_act59(order):
    admin_delete22(o59)
    return _real_act59(order)


SR.activate_monitor = _deleting_act59
SR.ensure_paid_side_effects(row59)
SR.activate_monitor = _real_act59
check("N59 (2): ensure resumed after deletion writes no "
      "SIDE_EFFECTS_OK event for the dead order",
      count("events", "order_id=? AND event='SIDE_EFFECTS_OK'",
            (o59,)) == 0
      and count("events", "order_id=?", (o59,)) == 0)

# N60 (3): the restored first-UNKNOWN basis, arm (i) — a
#      definite failure at T0 never starts the window: age
#      the attempt stamp 25h, then lose the next answer
#      (unknown). The recovery must still retry FREELY (no
#      post-window claim consumed, nothing settled), and a
#      third attempt still goes out.
o60 = mk_order("n60@test.dev", "Deep Scan", 29, status="PAID")
row60 = row_of18(o60)
PROV22.mail_mode = "http4xx"
r60a = SR._ensure_paid_receipt(row60, 2900)
shift_attempt21(f"receipt:{o60}", time.time() - 25 * 3600)
PROV22.mail_mode = "accept-lost"
r60b = SR._ensure_paid_receipt(row60, 2900)
r60c = SR._ensure_paid_receipt(row60, 2900)
st60 = email_state19(f"receipt:{o60}")
check("N60 (3): definite failure at T0 + first unknown at "
      "T0+25h: recovery retries freely — no post-window "
      "claim, no settle, third attempt sent",
      r60a is False and r60b is False and r60c is False
      and len(PROV22.mail_keys_to("n60@test.dev")) == 3
      and st60 is not None and st60[0] is not None
      and st60[1] == 0 and st60[2] == 0)

# N61 (3): the same arm on the monitor alert window — a
#      definite failure must not leave a first_unknown_at
#      stamp on the retained record (round 21's pre-send
#      stamp is popped when the attempt it belonged to ends
#      definitely), so a later unknown starts the window at
#      its own time and retries continue freely.
o61 = mk_order("n61@test.dev", "Monitoring", 79, status="PAID")
pend61 = {"since": SR.utcnow(), "new": [], "gone": [],
          "grade": "B", "score": 88,
          "digest_after": "d61", "attempts": 1}
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,"
          "created_at,next_run_at,last_digest,pending_alert) "
          "VALUES(?,?,?,?,?,?,?,?)",
          (o61, "example.com", "n61@test.dev", "N61",
           SR.utcnow(), time.time(), json.dumps(["LOW|base"]),
           json.dumps(pend61)))
c.commit()
c.close()
m61 = mon_row16(o61)
SR._scan_with_timeout = lambda url, stored=None: (
    True, "ok", {"findings": []}, "d61")
PROV22.mail_mode = "http4xx"
SR._run_monitor(dict(m61))
c = db()
row61a = c.execute("SELECT pending_alert FROM monitors "
                   "WHERE id=?", (m61["id"],)).fetchone()
c.close()
pend61a = json.loads(row61a[0]) if row61a and row61a[0] \
    else None
# Age whatever stamp the definite attempt left (pre-fix:
# round 21's pre-send stamp survives and would start the
# window 25h ago; post-fix: none was left to age).
if pend61a is not None and pend61a.get("first_unknown_at"):
    pend61a["first_unknown_at"] = time.time() - 25 * 3600
    c = db()
    c.execute("UPDATE monitors SET pending_alert=? WHERE "
              "id=?", (json.dumps(pend61a), m61["id"]))
    c.commit()
    c.close()
PROV22.mail_mode = "accept-lost"
SR._run_monitor(dict(m61))
SR._run_monitor(dict(m61))
c = db()
row61b = c.execute("SELECT pending_alert FROM monitors "
                   "WHERE id=?", (m61["id"],)).fetchone()
c.close()
pend61b = json.loads(row61b[0]) if row61b and row61b[0] \
    else None
check("N61 (3): monitor — definite failure leaves no "
      "window stamp; the later unknown retries freely and "
      "the alert stays pending, unspent",
      pend61a is not None
      and not pend61a.get("first_unknown_at")
      and len(PROV22.mail_keys_to("n61@test.dev")) == 3
      and pend61b is not None
      and not pend61b.get("post_window_used"))

# ============================================================
# Round 23 (Codex delta-21): ATOMICITY — every aliveness
# check and the act it guards collapse into one _db_lock
# critical section (or, for the claim, a check inside the
# claim's own acquisition). Delta-21 refuted round 22 on
# three arms, all one class: (1) _send_gate releases the
# lock before the HTTP call, so a send can still START
# after deletion completes — and several monitor Telegrams
# (retained-delivered, baseline, fresh-change, SSRF and
# scan-crash arms) have no gate at all; (2) _log_event_alive
# and _record_effects_ok check and insert in separate
# steps, and direct log_event calls (receipt settle arms,
# monitor error/baseline/rescan/change) are unguarded —
# log_event itself inserts with no alive predicate;
# (3) _claim_event_lock inserts an order-keyed lock after
# a stale entry check, where a crash leaves it for the GC.
# Round 23: _db_lock becomes an RLock (the pins' own seam
# wraps execute deletions from inside wrapped sends on the
# same thread — N58's shape); log_event itself is the
# guarded atomic writer (order_id present => check+INSERT
# in one acquisition; _log_event_alive delegates to it);
# every order/monitor notification send runs gate+provider
# call inside one acquisition (_gated_send); order/monitor
# -keyed claims and takeovers consult aliveness inside
# their own acquisition and refuse a dead owner with None.

# N62 (1): the gate-to-send gap for the receipt, threaded —
#      the send is parked INSIDE its provider call (past
#      every gate); the admin deletion, attempted from
#      another thread, must NOT complete while the send is
#      parked (the gate and the call are one critical
#      section now, and the delete transaction needs the
#      same lock), and after it completes no second send
#      may start for the tombstoned order.
o62 = mk_order("n62@test.dev", "Deep Scan", 29, status="PAID")
row62 = row_of18(o62)
_real_send62 = SR.send_resend
_send62_calls = []
_parked62 = threading.Event()
_release62 = threading.Event()


def _parking_send62(to, subject, text, html=None):
    _send62_calls.append(to)
    _parked62.set()
    _release62.wait(30)
    return SR._SendOutcome(True, "mail-n62", "delivered")


SR.send_resend = _parking_send62
_box62 = {}


def _drive62():
    _box62["r"] = SR._ensure_paid_receipt(row62, 2900)


th62 = threading.Thread(target=_drive62)
th62.start()
_parked62.wait(30)
_del62 = {}


def _delete62():
    _del62["code"] = admin_delete22(o62)


dth62 = threading.Thread(target=_delete62)
dth62.start()
time.sleep(1.0)
_blocked62 = dth62.is_alive() \
    and count("orders", "id=?", (o62,)) == 1 \
    and not tombstone_of22(o62)
_release62.set()
th62.join(30)
dth62.join(30)
SR.send_resend = _real_send62
r62b = SR._ensure_paid_receipt(row62, 2900)
check("N62 (1): receipt — deletion attempted while the "
      "send is parked inside its provider call cannot "
      "complete until the send returns; afterwards no "
      "second send starts for the tombstoned order",
      _blocked62
      and _del62.get("code") == 200
      and tombstone_of22(o62)
      and count("orders", "id=?", (o62,)) == 0
      and _send62_calls == ["n62@test.dev"]
      and r62b is False)

# N63 (1): a previously UNGATED monitor Telegram arm — the
#      baseline message. The order is deleted mid-scan
#      (inside the wrapped scanner, through the real admin
#      endpoint); when the run resumes, no baseline
#      Telegram may start and no MONITOR_BASELINE event
#      may be written for the dead order.
o63 = mk_order("n63@test.dev", "Monitoring", 79, status="PAID")
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,"
          "created_at,next_run_at) VALUES(?,?,?,?,?,?)",
          (o63, "https://n63.example.com", "n63@test.dev",
           "N63", SR.utcnow(), time.time()))
c.commit()
c.close()
m63 = mon_row16(o63)
_real_scan63 = SR._scan_with_timeout


def _deleting_scan63(url, timeout=None):
    admin_delete22(o63)
    return ([{"severity": "low", "title": "Missing header X"}],
            {"host": "n63.example.com", "errors": []})


SR._scan_with_timeout = _deleting_scan63
PROV22.tg_mode = "ok"
SR._run_monitor(dict(m63))
SR._scan_with_timeout = _real_scan63
check("N63 (1): baseline — order deleted mid-scan: no "
      "baseline Telegram starts and no event is written "
      "for the dead order",
      [t for t in PROV22.tg_requests
       if "n63.example.com" in t] == []
      and count("events", "order_id=?", (o63,)) == 0)

# N64 (2): the event check-to-insert gap, threaded — the
#      writer is parked at the guarded writer's threshold
#      (inside the wrapped log_event, before the real
#      insert) while the deletion completes from another
#      thread; released afterwards, the writer must not
#      land an event row for the dead order.
o64 = mk_order("n64@test.dev", "Deep Scan", 29, status="PAID")
_real_le64 = SR.log_event
_parked64 = threading.Event()
_release64 = threading.Event()


def _parking_le64(order_id, event, detail=""):
    if event == "N64_EVENT" and order_id == o64:
        _parked64.set()
        _release64.wait(30)
    return _real_le64(order_id, event, detail)


SR.log_event = _parking_le64


def _write64():
    SR._log_event_alive(o64, "N64_EVENT", "round-23 pin")


wth64 = threading.Thread(target=_write64)
wth64.start()
_parked64.wait(30)
_del64 = {}


def _delete64():
    _del64["code"] = admin_delete22(o64)


dth64 = threading.Thread(target=_delete64)
dth64.start()
dth64.join(30)
_release64.set()
wth64.join(30)
SR.log_event = _real_le64
check("N64 (2): event writer — deletion completes while "
      "the writer is parked between its caller's check "
      "and the insert: no event row for the dead order",
      _del64.get("code") == 200
      and count("events", "order_id=? AND event='N64_EVENT'",
                (o64,)) == 0
      and count("events", "order_id=?", (o64,)) == 0)

# N65 (2): delta-20's _record_effects_ok specimen again,
#      with the deletion inside the check-to-insert gap
#      itself (the wrapped log_event deletes through the
#      real endpoint before delegating): no orphan
#      SIDE_EFFECTS_OK may be recreated, and the call must
#      not raise for the dead order.
o65 = mk_order("n65@test.dev", "Deep Scan", 29, status="PAID")
_real_le65 = SR.log_event
_box65 = {"done": False}


def _deleting_le65(order_id, event, detail=""):
    if event == "SIDE_EFFECTS_OK" and order_id == o65 \
            and not _box65["done"]:
        _box65["done"] = True
        admin_delete22(o65)
    return _real_le65(order_id, event, detail)


SR.log_event = _deleting_le65
SR._record_effects_ok(o65, "Deep Scan")
SR.log_event = _real_le65
check("N65 (2): _record_effects_ok — deletion inside the "
      "check-to-insert gap writes no SIDE_EFFECTS_OK "
      "orphan and recreates no event",
      _box65["done"]
      and count("events",
                "order_id=? AND event='SIDE_EFFECTS_OK'",
                (o65,)) == 0
      and count("events", "order_id=?", (o65,)) == 0)

# N66 (3): claim-after-delete for both key families — the
#      worker's entry check passed, THEN the deletion
#      completes, THEN the claim is attempted: an
#      order-keyed notify: claim and a monitor-keyed
#      monitor: claim must both be refused (None), create
#      NO lock row, and leave the GC nothing to collect.
o66 = mk_order("n66@test.dev", "Deep Scan", 29, status="PAID")
SR._order_alive(o66)  # the stale entry check: passed
admin_delete22(o66)
tok66a = SR._claim_event_lock(f"notify:{o66}",
                              "deepscan-notify-intent")
o66m = mk_order("n66m@test.dev", "Monitoring", 79,
                status="PAID")
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,"
          "created_at,next_run_at) VALUES(?,?,?,?,?,?)",
          (o66m, "https://n66.example.com", "n66m@test.dev",
           "N66", SR.utcnow(), time.time()))
c.commit()
c.close()
m66 = mon_row16(o66m)
SR._monitor_alive(m66["id"])  # the stale entry check: passed
admin_delete22(o66m)
tok66b = SR._claim_event_lock(f"monitor:{m66['id']}",
                              "monitor")
SR._gc_notification_orphans()
check("N66 (3): claim after deletion — notify: and "
      "monitor: claims are refused (None), no lock row "
      "is created, the GC finds nothing to collect",
      tok66a is None and tok66b is None
      and lock_row18(f"notify:{o66}") is None
      and lock_row18(f"monitor:{m66['id']}") is None)
if tok66a:
    SR._release_event_lock(f"notify:{o66}", tok66a)
if tok66b:
    SR._release_event_lock(f"monitor:{m66['id']}", tok66b)

# N67 (1): the scan-CRASH arm (the other ungated error
#      Telegram) — the order is deleted inside the wrapped
#      scanner, which then raises: no MONITOR_ERROR event
#      and no crash Telegram may be produced for the dead
#      order when the arm runs.
o67 = mk_order("n67@test.dev", "Monitoring", 79, status="PAID")
c = db()
c.execute("INSERT INTO monitors(order_id,url,email,name,"
          "created_at,next_run_at) VALUES(?,?,?,?,?,?)",
          (o67, "https://n67.example.com", "n67@test.dev",
           "N67", SR.utcnow(), time.time()))
c.commit()
c.close()
m67 = mon_row16(o67)
_real_scan67 = SR._scan_with_timeout


def _crashing_scan67(url, timeout=None):
    admin_delete22(o67)
    raise RuntimeError("n67 scan boom")


SR._scan_with_timeout = _crashing_scan67
SR._run_monitor(dict(m67))
SR._scan_with_timeout = _real_scan67
check("N67 (1): scan-crash arm — order deleted mid-scan: "
      "no MONITOR_ERROR event and no crash Telegram for "
      "the dead order",
      [t for t in PROV22.tg_requests
       if "n67.example.com" in t] == []
      and count("events", "order_id=?", (o67,)) == 0)

# ============================================================
# Round 24 (Codex delta-22): THE TOTAL DEADLINE — round
# 23's final semantics (point 5) bounded a delete's wait
# for an in-flight gated send by "the provider timeout
# (20 s)", but urllib's timeout caps each socket operation,
# not the call: a provider dribbling its response body
# (every read prompt, the whole minutes long) held _db_lock
# — and with it a waiting delete — far past 20 s. The bound
# is now true by construction: _gated_send arms a TOTAL
# wall-clock deadline (_GATED_SEND_DEADLINE, 30 s in
# production) for the provider call, and the genuine
# wrappers enforce it on their transport — the response is
# read against the deadline and the wrappers' own exception
# arm classifies the cut as "unknown" (the provider may
# have accepted the message; never a definite outcome).
# The pins below patch the deadline constant the way the
# catalog patches SR's other module state, and drive a
# dribbling transport beneath the GENUINE send_resend: each
# read1 returns promptly with a small slice (modelling
# socket reads that each make progress well inside the
# per-operation timeout), while the full body would take
# ~5 s — far past the patched 2 s deadline.

_BODY68 = json.dumps(
    {"id": "mail-n68", "pad": "x" * 4000}).encode()


class _DribbleResp68:
    """A provider response that dribbles: every individual
    read returns promptly with a small slice; the whole
    body takes seconds. read(amt) composes read1 slices,
    the way a real buffered response satisfies one large
    read from many small socket reads."""

    def __init__(self, body, chunk=64, delay=0.08):
        self._body = body
        self._pos = 0
        self._chunk = chunk
        self._delay = delay
        self.started = threading.Event()

    def read1(self, n=-1):
        if self._pos >= len(self._body):
            return b""
        self.started.set()
        time.sleep(self._delay)
        take = min(self._chunk, len(self._body) - self._pos)
        if n is not None and n >= 0:
            take = min(take, n)
        out = self._body[self._pos:self._pos + take]
        self._pos += take
        return out

    def read(self, amt=-1):
        out = b""
        while amt is None or amt < 0 or len(out) < amt:
            piece = self.read1(
                65536 if amt is None or amt < 0
                else amt - len(out))
            if not piece:
                break
            out += piece
        return out

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_drib68 = {"resp": None, "calls": 0}


def _urlopen68(req, timeout=None):
    assert "api.resend.com" in req.full_url, req.full_url
    _drib68["calls"] += 1
    _drib68["resp"] = _DribbleResp68(_BODY68)
    return _drib68["resp"]


_saved_open68 = _ureq18.urlopen
_saved_deadline68 = getattr(SR, "_GATED_SEND_DEADLINE", None)
SR._GATED_SEND_DEADLINE = 2.0
_ureq18.urlopen = _urlopen68

# N68 (1): the direct arm — a gated send whose provider
#      dribbles past the total deadline returns at the
#      deadline with an outcome _send_status classifies as
#      UNKNOWN (the wrappers' own machinery: the cut is a
#      transport exception, like a lost answer), never a
#      definite outcome and never the delivered result the
#      full dribble would have produced.
o68a = mk_order("n68a@test.dev", "Deep Scan", 29,
                status="PAID")
_t068a = time.time()
res68a = SR._gated_send(o68a, SR.send_resend,
                        "n68a@test.dev",
                        "Payment received — Deep Scan", "body")
_el68a = time.time() - _t068a
check("N68 (1): gated send cut at the TOTAL deadline — "
      "classified unknown by the wrapper's own machinery, "
      "returned at the deadline, not after the full dribble",
      res68a is not None
      and SR._send_status(res68a) == "unknown"
      and _drib68["calls"] == 1
      and 1.8 <= _el68a < 3.0)

# N68 (2)+(3): the threaded arm — the receipt send dribbles
#      inside its provider call (past the gate, holding
#      _db_lock); an admin deletion attempted from another
#      thread completes at the total deadline (it genuinely
#      waited for the in-flight call, and was released by
#      the deadline — not by the full ~5 s dribble); the
#      receipt does not land; and afterwards no durable
#      state is attributable to the interrupted send.
o68 = mk_order("n68@test.dev", "Deep Scan", 29, status="PAID")
row68 = row_of18(o68)
_drib68["calls"] = 0
_drib68["resp"] = None
_box68 = {}


def _drive68():
    _box68["t0"] = time.time()
    _box68["r"] = SR._ensure_paid_receipt(row68, 2900)


th68 = threading.Thread(target=_drive68)
th68.start()
_deadline68 = time.time() + 10
while _drib68["resp"] is None and time.time() < _deadline68:
    time.sleep(0.01)
if _drib68["resp"] is not None:
    _drib68["resp"].started.wait(10)
_del68 = {}


def _delete68():
    _del68["code"] = admin_delete22(o68)
    _del68["done"] = time.time()


dth68 = threading.Thread(target=_delete68)
dth68.start()
th68.join(20)
dth68.join(20)
_el_del68 = _del68.get("done", 0) - _box68.get("t0", 0)
check("N68 (2): deletion attempted while the receipt send "
      "dribbles inside its provider call completes at the "
      "total deadline — not after the full dribble — and "
      "the receipt does not land",
      _del68.get("code") == 200
      and 1.5 <= _el_del68 < 3.5
      and _box68.get("r") is False
      and _drib68["calls"] == 1)
check("N68 (3): after the deadline cut and the deletion, "
      "no state is attributable to the interrupted send: "
      "tombstone present, no email_delivery row, no events",
      tombstone_of22(o68)
      and email_state19(f"receipt:{o68}") is None
      and count("events", "order_id=?", (o68,)) == 0)
_ureq18.urlopen = _saved_open68
if _saved_deadline68 is None:
    try:
        del SR._GATED_SEND_DEADLINE
    except AttributeError:
        pass
else:
    SR._GATED_SEND_DEADLINE = _saved_deadline68

_ureq18.urlopen = _real_urlopen18

# ============================================================
# Round 25 (Codex delta-23): THE DEADLINE IS PHASE-COMPLETE
# — delta-23 certified the round-24 substitution itself
# (same-thread enforcement, no abandoned worker) but
# refuted it as not phase-complete: (1) a header dribble
# inside urlopen outlived the deadline — every socket
# operation stayed under its own timeout while the
# aggregate ran past 30 s — yet the JOURNAL's final
# statement claimed the bound unconditionally; (2) a
# chunk-framing dribble hid inside http.client's read1()
# (its internal chunk-size/trailer reads were never
# clock-checked between read1 calls), and the no-read1
# fallback read a body in one unchecked call; (3) a
# deadline cut inside an HTTPError body read was swallowed
# by both wrappers' error arms and classified by status
# (definite) instead of unknown. Round 25 moves the
# enforcement BELOW http.client's parsing, onto the raw
# socket: every blocking socket operation of a gated send
# re-caps its timeout to what is left of the deadline and
# refuses once it is spent, so no phase — connect, request
# send, response headers, body (chunk framing and trailers
# included), error body — can outlive the deadline in
# aggregate; the expiry is a dedicated exception type and
# both HTTPError arms classify it UNKNOWN.
# These pins drive the GENUINE wrappers over a REAL
# localhost socket — a threaded HTTP server that dribbles
# — not an in-memory model. The wrappers are pointed at
# the test server two ways at once: the round-25 base-URL
# constants are patched where they exist, and a
# redirecting urlopen carries the pre-fix tree (whose
# wrappers build the provider URL inline) to the same
# server through the genuine urllib/http.client stack.

import http.server as _hs25

_HITS25 = {}
_ARRIVED25 = {p: threading.Event()
              for p in ("/hdr", "/chunk", "/err", "/tgerr")}


class _DribHandler25(_hs25.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        try:
            left = int(self.headers.get("Content-Length")
                       or 0)
        except Exception:
            left = 0
        while left > 0:
            piece = self.rfile.read(min(left, 65536))
            if not piece:
                break
            left -= len(piece)
        mode = self.path
        if mode.startswith("/bot"):
            mode = "/tgerr"
        _HITS25[mode] = _HITS25.get(mode, 0) + 1
        ev = _ARRIVED25.get(mode)
        if ev is not None:
            ev.set()
        try:
            getattr(self, "_m_" + mode.strip("/"))()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            pass

    def _raw(self, data):
        self.connection.sendall(data)

    def _drip(self, data, interval):
        for i in range(len(data)):
            self.connection.sendall(data[i:i + 1])
            time.sleep(interval)

    def _m_hdr(self):
        # Status line prompt, then the header block one byte
        # at a time (~6.5 s at 0.12 s/byte): every socket
        # read makes progress well inside its per-operation
        # timeout, so only an AGGREGATE bound can cut this.
        self._raw(b"HTTP/1.1 200 OK\r\n")
        self._drip(b"Content-Type: application/json\r\n"
                   b"X-Dribble: n69-headers-pad\r\n", 0.12)
        body = b'{"id": "mail-n69"}'
        self._raw(b"Content-Length: %d\r\n\r\n" % len(body)
                  + body)

    def _m_chunk(self):
        # Headers prompt; the chunk-SIZE line dribbled one
        # byte at a time (~4.5 s) — the dribble lives inside
        # http.client's chunk parsing, within a single
        # read1() call from the wrapper's point of view.
        body = b'{"id": "mail-n70"}'
        assert len(body) == 18
        self._raw(b"HTTP/1.1 200 OK\r\n"
                  b"Content-Type: application/json\r\n"
                  b"Transfer-Encoding: chunked\r\n\r\n")
        self._drip(b"00000012\r\n", 0.45)
        self._raw(body + b"\r\n0\r\n\r\n")

    def _err_body(self, status, body):
        self._raw(status
                  + b"\r\nContent-Type: application/json\r\n"
                  b"Content-Length: "
                  + str(len(body)).encode() + b"\r\n\r\n")
        for i in range(0, len(body), 64):
            self.connection.sendall(body[i:i + 64])
            time.sleep(0.25)

    def _m_err(self):
        # 422 promptly; the ERROR body dribbles (~9.5 s).
        self._err_body(
            b"HTTP/1.1 422 Unprocessable Entity",
            b'{"message":"n71 dribbled error","pad":"'
            + b"x" * 2400 + b'"}')

    def _m_tgerr(self):
        # 400 promptly; the ERROR body dribbles (~9.5 s).
        self._err_body(
            b"HTTP/1.1 400 Bad Request",
            b'{"ok":false,"description":"n71 tg dribble",'
            b'"pad":"' + b"x" * 2400 + b'"}')


_SRV25 = _hs25.ThreadingHTTPServer(("127.0.0.1", 0),
                                   _DribHandler25)
_PORT25 = _SRV25.server_address[1]
_th25srv = threading.Thread(
    target=_SRV25.serve_forever,
    kwargs={"poll_interval": 0.05}, daemon=True)
_th25srv.start()
_BASE25 = f"http://127.0.0.1:{_PORT25}"
_MODE25 = {"resend": "/hdr"}
_real_open25 = _ureq18.urlopen


def _redirect25(req, timeout=None):
    url = req.full_url
    if "api.resend.com" in url:
        req.full_url = _BASE25 + _MODE25["resend"]
    elif "api.telegram.org" in url:
        req.full_url = _BASE25 + "/tgerr"
    if timeout is None:
        return _real_open25(req)
    return _real_open25(req, timeout=timeout)


def _point25(path):
    _MODE25["resend"] = path
    SR._RESEND_API_URL = _BASE25 + path


def _failed_detail25(oid):
    c = db()
    try:
        r = c.execute(
            "SELECT detail FROM events WHERE order_id=? AND "
            "event='PAID_EMAIL_FAILED' ORDER BY id DESC "
            "LIMIT 1", (oid,)).fetchone()
        return r["detail"] if r is not None else ""
    finally:
        c.close()


_saved_open25 = _ureq18.urlopen
_saved_url25 = getattr(SR, "_RESEND_API_URL", None)
_saved_tgbase25 = getattr(SR, "_TELEGRAM_API_BASE", None)
_saved_dl25 = getattr(SR, "_GATED_SEND_DEADLINE", None)
SR._GATED_SEND_DEADLINE = 2.0
SR._TELEGRAM_API_BASE = _BASE25
_ureq18.urlopen = _redirect25

# N69 (1): HEADER dribble, threaded — the receipt send is
#      parked inside urlopen's header phase (past the
#      gate, holding _db_lock) while the server dribbles
#      response headers byte-by-byte; an admin deletion
#      attempted from another thread completes at the
#      TOTAL deadline (released by the deadline cut inside
#      the header phase — not by the ~6.5 s dribble), and
#      the receipt does not land. Afterwards no durable
#      state is attributable to the interrupted send.
_point25("/hdr")
_ARRIVED25["/hdr"].clear()
_hits69 = _HITS25.get("/hdr", 0)
o69 = mk_order("n69@test.dev", "Deep Scan", 29, status="PAID")
row69 = row_of18(o69)
_box69 = {}


def _drive69():
    _box69["t0"] = time.time()
    _box69["r"] = SR._ensure_paid_receipt(row69, 2900)


th69 = threading.Thread(target=_drive69)
th69.start()
_ARRIVED25["/hdr"].wait(10)
_del69 = {}


def _delete69():
    _del69["code"] = admin_delete22(o69)
    _del69["done"] = time.time()


dth69 = threading.Thread(target=_delete69)
dth69.start()
th69.join(25)
dth69.join(25)
_el69 = _del69.get("done", 0) - _box69.get("t0", 0)
check("N69 (1): header dribble over a real socket — the "
      "gated receipt send is cut at the TOTAL deadline "
      "inside the header phase; a waiting deletion "
      "completes in the same envelope, the receipt does "
      "not land, and no state remains attributable to "
      "the interrupted send",
      _del69.get("code") == 200
      and 1.5 <= _el69 < 3.5
      and _box69.get("r") is False
      and _HITS25.get("/hdr", 0) == _hits69 + 1
      and tombstone_of22(o69)
      and email_state19(f"receipt:{o69}") is None
      and count("events", "order_id=?", (o69,)) == 0)

# N70 (1): CHUNK-FRAMING dribble, direct arm — the
#      chunk-size line arrives byte-by-byte, inside
#      http.client's chunk parsing (a single read1() from
#      the wrapper's side): the gated send still returns
#      at the TOTAL deadline, classified unknown.
_point25("/chunk")
_hits70 = _HITS25.get("/chunk", 0)
o70 = mk_order("n70@test.dev", "Deep Scan", 29, status="PAID")
_t070 = time.time()
res70 = SR._gated_send(o70, SR.send_resend, "n70@test.dev",
                       "Payment received — Deep Scan", "body")
_el70 = time.time() - _t070
check("N70 (1): chunk-framing dribble over a real socket "
      "— gated send cut at the TOTAL deadline inside "
      "chunk parsing, classified unknown, returned at "
      "the deadline and not after the full dribble",
      res70 is not None
      and SR._send_status(res70) == "unknown"
      and _HITS25.get("/chunk", 0) == _hits70 + 1
      and 1.7 <= _el70 < 3.5)

# N71 (1): ERROR-BODY dribble, Resend arm — a 422 arrives
#      promptly but its body dribbles: the deadline cut
#      inside the HTTPError body read classifies UNKNOWN
#      (a possibly-accepted send with a lost answer),
#      never the definite failure the status code alone
#      would suggest, and returns at the deadline.
_point25("/err")
_hits71 = _HITS25.get("/err", 0)
o71 = mk_order("n71@test.dev", "Deep Scan", 29, status="PAID")
_t071 = time.time()
res71 = SR._gated_send(o71, SR.send_resend, "n71@test.dev",
                       "Payment received — Deep Scan", "body")
_el71 = time.time() - _t071
check("N71 (1): 4xx error-body dribble (Resend) — the "
      "deadline cut inside the HTTPError body read "
      "classifies unknown, not definite, at the deadline",
      res71 is not None
      and SR._send_status(res71) == "unknown"
      and _HITS25.get("/err", 0) == _hits71 + 1
      and 1.7 <= _el71 < 3.5)

# N71 (2): ERROR-BODY dribble, Telegram arm — same shape:
#      a 400 whose body dribbles is UNKNOWN at the
#      deadline, not the definite ok:false/4xx failure.
_hits71tg = _HITS25.get("/tgerr", 0)
o71tg = mk_order("n71tg@test.dev", "Monitoring", 79,
                 status="PAID")
_t071tg = time.time()
res71tg = SR._gated_send(o71tg, SR.send_telegram,
                         "n71 telegram dribble probe")
_el71tg = time.time() - _t071tg
check("N71 (2): 4xx error-body dribble (Telegram) — the "
      "deadline cut inside the HTTPError body read "
      "classifies unknown, not definite, at the deadline",
      res71tg is not None
      and SR._send_status(res71tg) == "unknown"
      and _HITS25.get("/tgerr", 0) == _hits71tg + 1
      and 1.7 <= _el71tg < 3.5)

# N71 (3): the receipt recovery treats a deadline-cut
#      error body as a LOST ANSWER: the first-unknown
#      stamp is recorded (the idempotency clock starts,
#      the retry is deduped) and the failure event carries
#      the unknown classification — not the 422's
#      definite failure.
_point25("/err")
o71r = mk_order("n71r@test.dev", "Deep Scan", 29,
                status="PAID")
row71r = row_of18(o71r)
r71r = SR._ensure_paid_receipt(row71r, 2900)
st71r = email_state19(f"receipt:{o71r}")
check("N71 (3): receipt recovery treats a deadline-cut "
      "error body as a lost answer — first-unknown stamp "
      "recorded and the failure event classified unknown, "
      "not the definite 422",
      r71r is False
      and st71r is not None and st71r[0] is not None
      and "transport outcome unknown"
      in _failed_detail25(o71r))

_ureq18.urlopen = _saved_open25
for _attr25, _saved25 in (
        ("_RESEND_API_URL", _saved_url25),
        ("_TELEGRAM_API_BASE", _saved_tgbase25),
        ("_GATED_SEND_DEADLINE", _saved_dl25)):
    if _saved25 is None:
        try:
            delattr(SR, _attr25)
        except AttributeError:
            pass
    else:
        setattr(SR, _attr25, _saved25)
_SRV25.shutdown()
_SRV25.server_close()

# ============================================================
# Round 26 (Codex delta-24): HTTPS CONSTRUCTION + CONNECT
# PHASE — delta-24 refuted round 25 on two points the
# HTTP-only specimens could not see: (1) PRODUCTION-
# BREAKING: under the http.client class swap, Python
# 3.12's HTTPSConnection.__init__ resolves its explicit
# super() against the REPLACED global, so constructing
# an HTTPS connection raised TypeError — every armed
# send to the real (HTTPS) providers would have
# returned unknown WITHOUT SENDING, and an unarmed send
# concurrent with the swap could hit the same failure;
# (2) the connect phase (DNS, per-address connects,
# proxy CONNECT, TLS handshake) ran BEFORE the shim
# wrapped the socket and was not aggregate-bounded, so
# the stated 30 s bound (which includes connect) did
# not hold. These pins cover the PRODUCTION SCHEME: a
# local TLS server (self-signed; the genuine wrapper is
# made to trust it the way stdlib supplies trust on the
# urllib path — an installed opener whose HTTPS handler
# carries the unverified context into every construction
# [round-27 contract change: the seam originally used
# here, patching the server module's context factory,
# is one urllib never consults — see JOURNAL round 27]),
# a TLS-handshake stall, and an unarmed HTTPS send
# executed while an armed exchange's swap window is open.

import http.client as _hc26
import socket as _sock26
import ssl as _ssl26
import subprocess as _sp26
import tempfile as _tf26

_certdir26 = _tf26.mkdtemp(prefix="vf-tls26-")
_cert26 = os.path.join(_certdir26, "cert.pem")
_key26 = os.path.join(_certdir26, "key.pem")
_sp26.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
           "-keyout", _key26, "-out", _cert26, "-days", "2",
           "-nodes", "-subj", "/CN=127.0.0.1",
           "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
          check=True, capture_output=True, timeout=60)
_srvctx26 = _ssl26.SSLContext(_ssl26.PROTOCOL_TLS_SERVER)
_srvctx26.load_cert_chain(_cert26, _key26)

_HITS26 = {}
_ARRIVED26 = {p: threading.Event() for p in ("/tls-ok", "/tls-hdr")}


class _TlsHandler26(_hs25.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        try:
            left = int(self.headers.get("Content-Length") or 0)
        except Exception:
            left = 0
        try:
            while left > 0:
                piece = self.rfile.read(min(left, 65536))
                if not piece:
                    break
                left -= len(piece)
        except Exception:
            return
        mode = self.path
        _HITS26[mode] = _HITS26.get(mode, 0) + 1
        ev = _ARRIVED26.get(mode)
        if ev is not None:
            ev.set()
        try:
            if mode == "/tls-ok":
                body = b'{"id": "mail-n72-ok"}'
                self.connection.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: %d\r\n\r\n" % len(body)
                    + body)
            elif mode == "/tls-hdr":
                # Status line prompt; the header block one
                # byte at a time (~6.5 s) over TLS — only an
                # aggregate bound on the real production
                # scheme can cut this.
                self.connection.sendall(b"HTTP/1.1 200 OK\r\n")
                drip = (b"Content-Type: application/json\r\n"
                        b"X-Dribble: n72-headers-pad\r\n")
                for i in range(len(drip)):
                    self.connection.sendall(drip[i:i + 1])
                    time.sleep(0.12)
                body = b'{"id": "mail-n72-late"}'
                self.connection.sendall(
                    b"Content-Length: %d\r\n\r\n" % len(body)
                    + body)
        except Exception:
            pass


_SRV26 = _hs25.ThreadingHTTPServer(("127.0.0.1", 0),
                                   _TlsHandler26)
_SRV26.socket = _srvctx26.wrap_socket(_SRV26.socket,
                                      server_side=True)
_PORT26 = _SRV26.server_address[1]
_th26srv = threading.Thread(
    target=_SRV26.serve_forever,
    kwargs={"poll_interval": 0.05}, daemon=True)
_th26srv.start()
_BASE26 = f"https://127.0.0.1:{_PORT26}"


class _Stall26:
    """A raw TCP listener that accepts one connection,
    reads the TLS ClientHello and then stalls the
    handshake for ~6 s: the exchange can only die on
    time if the HANDSHAKE ITSELF is budget-capped."""

    def __init__(self):
        self.ls = _sock26.socket()
        self.ls.setsockopt(_sock26.SOL_SOCKET,
                           _sock26.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(1)
        self.port = self.ls.getsockname()[1]
        self.accepted = threading.Event()

    def run(self):
        try:
            conn, _ = self.ls.accept()
        except OSError:
            return
        self.accepted.set()
        try:
            conn.settimeout(5)
            try:
                conn.recv(4096)
            except OSError:
                pass
            time.sleep(6)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        try:
            self.ls.close()
        except OSError:
            pass


_STALL26 = _Stall26()
_th26stall = threading.Thread(target=_STALL26.run, daemon=True)
_th26stall.start()

_orig_http26 = _hc26.HTTPConnection
_orig_https26 = _hc26.HTTPSConnection
_saved_open26 = _ureq18.urlopen
_saved_url26 = SR._RESEND_API_URL
_saved_opener26 = _ureq18._opener
_saved_dl26 = SR._GATED_SEND_DEADLINE
_ureq18.urlopen = _real_urlopen18
_testopener26 = _ureq18.build_opener(
    _ureq18.HTTPSHandler(
        context=_ssl26._create_unverified_context()))
_ureq18.install_opener(_testopener26)
SR._GATED_SEND_DEADLINE = 2.0

# N72 (2): plain armed HTTPS SUCCESS — the genuine
#      wrapper constructs an HTTPS connection (no
#      TypeError), completes a normal TLS exchange and
#      classifies the provider id as delivered. Proves
#      HTTPS sends WORK, not only that they die on time.
SR._RESEND_API_URL = _BASE26 + "/tls-ok"
_hits72ok = _HITS26.get("/tls-ok", 0)
o72ok = mk_order("n72ok@test.dev", "Deep Scan", 29, status="PAID")
_t072ok = time.time()
res72ok = SR._gated_send(o72ok, SR.send_resend, "n72ok@test.dev",
                         "Payment received — Deep Scan", "body")
_el72ok = time.time() - _t072ok
check("N72 (2): armed HTTPS success over a real TLS "
      "socket — construction works, the exchange "
      "completes and the provider id classifies delivered",
      res72ok is not None
      and SR._send_status(res72ok) == "delivered"
      and res72ok[1] == "mail-n72-ok"
      and _HITS26.get("/tls-ok", 0) == _hits72ok + 1
      and _el72ok < 1.5)

# N72 (1): HTTPS HEADER dribble — the TLS exchange is
#      under way and the server dribbles response
#      headers byte-by-byte: the gated send is cut at
#      the patched deadline and classifies unknown.
SR._RESEND_API_URL = _BASE26 + "/tls-hdr"
_hits72 = _HITS26.get("/tls-hdr", 0)
o72 = mk_order("n72@test.dev", "Deep Scan", 29, status="PAID")
_t072 = time.time()
res72 = SR._gated_send(o72, SR.send_resend, "n72@test.dev",
                       "Payment received — Deep Scan", "body")
_el72 = time.time() - _t072
check("N72 (1): HTTPS header dribble over a real TLS "
      "socket — construction works and the gated send "
      "is cut at the deadline, classified unknown",
      res72 is not None
      and SR._send_status(res72) == "unknown"
      and _HITS26.get("/tls-hdr", 0) == _hits72 + 1
      and 1.7 <= _el72 < 3.5)

# N73 (1): CONNECT-PHASE specimen — the TCP connection
#      succeeds but the TLS HANDSHAKE never completes
#      (the peer stalls after the ClientHello): the
#      exchange dies inside the deadline envelope
#      instead of after a per-attempt timeout stack.
SR._RESEND_API_URL = f"https://127.0.0.1:{_STALL26.port}/stall"
o73 = mk_order("n73@test.dev", "Deep Scan", 29, status="PAID")
_t073 = time.time()
res73 = SR._gated_send(o73, SR.send_resend, "n73@test.dev",
                       "Payment received — Deep Scan", "body")
_el73 = time.time() - _t073
check("N73 (1): TLS handshake stall — the gated HTTPS "
      "send dies at the deadline inside connection "
      "establishment, classified unknown",
      res73 is not None
      and SR._send_status(res73) == "unknown"
      and _STALL26.accepted.is_set()
      and 1.7 <= _el73 < 3.5)

# N74 (1): UNARMED send inside an armed swap window —
#      an armed HTTPS exchange is parked in its header
#      dribble (the http.client classes are swapped for
#      the duration of its urlopen call) while a second,
#      UNARMED send runs: it must construct and complete
#      with legacy behaviour (delivered), never the
#      swap's construction failure. After the armed
#      exchange ends, the http.client globals are the
#      original classes again.
SR._GATED_SEND_DEADLINE = 5.0
SR._RESEND_API_URL = _BASE26 + "/tls-hdr"
_ARRIVED26["/tls-hdr"].clear()
_hits74hdr = _HITS26.get("/tls-hdr", 0)
_hits74ok = _HITS26.get("/tls-ok", 0)
o74 = mk_order("n74@test.dev", "Deep Scan", 29, status="PAID")
_box74 = {}


def _armed74():
    _box74["r"] = SR._gated_send(
        o74, SR.send_resend, "n74a@test.dev",
        "Payment received — Deep Scan", "body")


th74 = threading.Thread(target=_armed74)
th74.start()
_ARRIVED26["/tls-hdr"].wait(10)
SR._RESEND_API_URL = _BASE26 + "/tls-ok"
_t074u = time.time()
res74u = SR.send_resend("n74u@test.dev",
                        "Payment received — Deep Scan", "body")
_el74u = time.time() - _t074u
th74.join(20)
check("N74 (1): unarmed HTTPS send during an armed "
      "swap window constructs and completes with legacy "
      "behaviour (delivered); the armed exchange is cut "
      "at its deadline and the http.client globals are "
      "restored afterwards",
      SR._send_status(res74u) == "delivered"
      and res74u[1] == "mail-n72-ok"
      and _el74u < 3
      and _box74.get("r") is not None
      and SR._send_status(_box74["r"]) == "unknown"
      and _HITS26.get("/tls-ok", 0) == _hits74ok + 1
      and _HITS26.get("/tls-hdr", 0) == _hits74hdr + 1
      and _hc26.HTTPConnection is _orig_http26
      and _hc26.HTTPSConnection is _orig_https26)

_ureq18.urlopen = _saved_open26
SR._RESEND_API_URL = _saved_url26
SR._GATED_SEND_DEADLINE = _saved_dl26
_ureq18.install_opener(_saved_opener26)
_SRV26.shutdown()
_SRV26.server_close()
_STALL26.close()

# ============================================================
# Round 27 (Codex delta-25): FAITHFUL CONTEXTS, CACHED
# FACTORY CONTEXTS, PER-EXCHANGE RESOLUTIONS — delta-25
# certified round 26's construction safety, per-attempt
# capping, tunnel, cleanup and catalog, and refuted
# three points: (1) the deadline HTTPS class DISCARDED
# a caller-supplied SSLContext and substituted a
# factory default — while on the genuine urllib path
# trust arrives exactly as a supplied context (the
# opener's HTTPS handler passes its context object into
# every construction; the handler itself is never
# consulted about the module factory). The round-26
# pins above originally patched that factory — a seam
# urllib never consults; under the round-27 CONTRACT
# CHANGE (parent ruling, JOURNAL round 27) their SETUP
# now installs an opener whose handler carries the
# unverified context, every assertion byte-identical —
# so N72/N73/N74 now prove the wrapper path carries
# the handler's context through the swapped class.
# (2) The factory ran per connection inside the timed
# path; factory contexts are now cached process-wide
# per factory. (3) A redirect inside one exchange
# resolved the host once per connection; armed
# resolutions are now cached per exchange. The pins
# below drive DIRECT constructions — the path where
# caller contexts and the factory are the whole story.

import socket as _sock27
import ssl as _ssl27
import subprocess as _sp27
import tempfile as _tf27

_certdir27 = _tf27.mkdtemp(prefix="vf-tls27-")
_cert27 = os.path.join(_certdir27, "cert.pem")
_key27 = os.path.join(_certdir27, "key.pem")
_sp27.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
           "-keyout", _key27, "-out", _cert27, "-days", "2",
           "-nodes", "-subj", "/CN=127.0.0.1",
           "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
          check=True, capture_output=True, timeout=60)
_srvctx27 = _ssl27.SSLContext(_ssl27.PROTOCOL_TLS_SERVER)
_srvctx27.load_cert_chain(_cert27, _key27)


class _TlsHandler27(_hs25.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/ok":
            body = b'{"id": "mail-n27-ok"}'
            self.connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body)
                + body)


_SRV27 = _hs25.ThreadingHTTPServer(("127.0.0.1", 0),
                                   _TlsHandler27)
_SRV27.socket = _srvctx27.wrap_socket(_SRV27.socket,
                                      server_side=True)
_PORT27 = _SRV27.server_address[1]
_th27srv = threading.Thread(
    target=_SRV27.serve_forever,
    kwargs={"poll_interval": 0.05}, daemon=True)
_th27srv.start()


class _RedirHandler27(_hs25.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        try:
            left = int(self.headers.get("Content-Length") or 0)
        except Exception:
            left = 0
        try:
            while left > 0:
                piece = self.rfile.read(min(left, 65536))
                if not piece:
                    break
                left -= len(piece)
        except Exception:
            return
        if self.path == "/redir":
            self.connection.sendall(
                b"HTTP/1.1 302 Found\r\n"
                b"Location: /target\r\n"
                b"Content-Length: 0\r\n\r\n")

    def do_GET(self):
        if self.path == "/target":
            body = b'{"id": "mail-n76-ok"}'
            self.connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body)
                + body)


_RSRV27 = _hs25.ThreadingHTTPServer(("127.0.0.1", 0),
                                    _RedirHandler27)
_RPORT27 = _RSRV27.server_address[1]
_th27rsrv = threading.Thread(
    target=_RSRV27.serve_forever,
    kwargs={"poll_interval": 0.05}, daemon=True)
_th27rsrv.start()

_saved_url27 = SR._RESEND_API_URL
_saved_dl27 = SR._GATED_SEND_DEADLINE
_saved_open27 = _ureq18.urlopen
_saved_factory27 = SR._HTTPS_CONTEXT_FACTORY


def _direct27(port, context, armed):
    """One direct deadline-HTTPS construction + GET /ok;
    returns the body, or the exception the exchange
    raised. The deadline is armed generously when
    `armed` — arming is the only difference between the
    two connect paths."""
    tok = None
    if armed:
        tok = SR._SEND_DEADLINE_AT.set(time.monotonic() + 10.0)
    try:
        conn = SR._DeadlineHTTPSConnection(
            "127.0.0.1", port, context=context)
        conn.request("GET", "/ok")
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return body
    except BaseException as exc:
        return exc
    finally:
        if tok is not None:
            SR._SEND_DEADLINE_AT.reset(tok)


# N75: caller-context fidelity, two discriminating arms
# x both connect paths. Arm (i): the caller supplies an
# UNVERIFIED context while the factory would produce a
# VERIFYING one — the exchange succeeds only if the
# caller's context is used verbatim, and the counting
# factory proves it was never consulted. Arm (ii): the
# caller supplies a VERIFYING context (system roots —
# the local self-signed certificate is not among them)
# while the factory would produce an UNVERIFIED one —
# the exchange must FAIL with a certificate error.
_calls75 = []


def _factory75_verify(vsn):
    _calls75.append(vsn)
    return _ssl27.create_default_context()


def _factory75_unverified(vsn):
    _calls75.append(vsn)
    return _ssl27._create_unverified_context()


SR._HTTPS_CONTEXT_FACTORY = _factory75_verify
_calls75.clear()
_r75a = _direct27(_PORT27, _ssl27._create_unverified_context(),
                  armed=True)
check("N75 (1): direct construction, armed — a supplied "
      "unverified context is used verbatim (the exchange "
      "succeeds against the self-signed server) and the "
      "verifying factory is never consulted",
      _r75a == b'{"id": "mail-n27-ok"}' and _calls75 == [])

_calls75.clear()
_r75b = _direct27(_PORT27, _ssl27._create_unverified_context(),
                  armed=False)
check("N75 (2): direct construction, unarmed — a supplied "
      "unverified context is used verbatim and the "
      "verifying factory is never consulted",
      _r75b == b'{"id": "mail-n27-ok"}' and _calls75 == [])

SR._HTTPS_CONTEXT_FACTORY = _factory75_unverified
_calls75.clear()
_r75c = _direct27(_PORT27, _ssl27.create_default_context(),
                  armed=True)
check("N75 (3): direct construction, armed — a supplied "
      "verifying context is used verbatim (the exchange "
      "fails with a certificate error against the "
      "self-signed server) and the unverified factory is "
      "never consulted",
      isinstance(_r75c, _ssl27.SSLError) and _calls75 == [])

_calls75.clear()
_r75d = _direct27(_PORT27, _ssl27.create_default_context(),
                  armed=False)
check("N75 (4): direct construction, unarmed — a supplied "
      "verifying context is used verbatim (certificate "
      "error) and the unverified factory is never "
      "consulted",
      isinstance(_r75d, _ssl27.SSLError) and _calls75 == [])

SR._HTTPS_CONTEXT_FACTORY = _saved_factory27

# N76 (1): per-exchange resolution cache — a genuine
# wrapper exchange redirected (302) to a second path on
# the SAME host opens a second connection inside the
# same urlopen call; the host is resolved exactly once
# for the whole exchange (pre-fix: once per connection).
_real_gai27 = _sock27.getaddrinfo
_gai27 = []


def _counting_gai27(host, port, *a, **kw):
    if host == "127.0.0.1":
        _gai27.append((host, port))
    return _real_gai27(host, port, *a, **kw)


_ureq18.urlopen = _real_urlopen18
SR._GATED_SEND_DEADLINE = 10.0
SR._RESEND_API_URL = f"http://127.0.0.1:{_RPORT27}/redir"
_sock27.getaddrinfo = _counting_gai27
o76 = mk_order("n76@test.dev", "Deep Scan", 29, status="PAID")
res76 = SR._gated_send(o76, SR.send_resend, "n76@test.dev",
                       "Payment received — Deep Scan", "body")
_sock27.getaddrinfo = _real_gai27
check("N76 (1): redirected gated exchange — the final "
      "response classifies delivered and the host is "
      "resolved exactly once across both connections of "
      "the exchange",
      res76 is not None
      and SR._send_status(res76) == "delivered"
      and res76[1] == "mail-n76-ok"
      and len(_gai27) == 1)
_ureq18.urlopen = _saved_open27

# N77 (1): fresh factory contexts — CONTRACT CHANGE #2
# (parent ruling, JOURNAL round 28). This pin was added
# in the round-27 wave to pin the process-wide factory
# cache (one consultation, one shared object); delta-26
# refuted the cache itself (finding 3: ONE MUTABLE
# context handed to separate context=None callers
# diverges from stdlib's fresh-per-construction
# semantics), so the cache is removed and this pin is
# REWRITTEN to pin the replacement semantics: two
# context=None constructions under one counting factory
# consult it exactly TWICE (once per construction),
# carry DISTINCT context objects (the ones the factory
# made, in order), and both objects functionally
# complete real TLS exchanges. The pin was added in an
# uncertified wave (no SHIP ever certified it); every
# other pin is untouched by this change.
_made77 = []
_calls77 = []


def _factory77(vsn):
    _calls77.append(vsn)
    _ctx = _ssl27._create_unverified_context()
    _made77.append(_ctx)
    return _ctx


SR._HTTPS_CONTEXT_FACTORY = _factory77
_c77a = SR._DeadlineHTTPSConnection("127.0.0.1", _PORT27)
_c77b = SR._DeadlineHTTPSConnection("127.0.0.1", _PORT27)
_c77a.request("GET", "/ok")
_resp77 = _c77a.getresponse()
_body77 = _resp77.read()
_c77a.close()
_c77b.request("GET", "/ok")
_resp77b = _c77b.getresponse()
_body77b = _resp77b.read()
_c77b.close()
SR._HTTPS_CONTEXT_FACTORY = _saved_factory27
check("N77 (1): two context=None constructions under one "
      "factory consult it once per construction and "
      "carry distinct fresh context objects, both of "
      "which complete real TLS exchanges",
      len(_calls77) == 2
      and len(_made77) == 2
      and _c77a._context is _made77[0]
      and _c77b._context is _made77[1]
      and _c77a._context is not _c77b._context
      and _body77 == b'{"id": "mail-n27-ok"}'
      and _body77b == b'{"id": "mail-n27-ok"}')

SR._RESEND_API_URL = _saved_url27
SR._GATED_SEND_DEADLINE = _saved_dl27
_SRV27.shutdown()
_SRV27.server_close()
_RSRV27.shutdown()
_RSRV27.server_close()

# ============================================================
# Round 28 (Codex delta-26): WARM-UP, HOST-KEYED
# RESOLUTIONS, FRESH FACTORY CONTEXTS — delta-26
# certified round 27's Option A seam move, the
# caller-context fidelity (factory consulted 0 times on
# the wrapper path), the resolution cache's bracketing
# and the catalog chain to 150, and refuted three
# points, all in round 27's additions: (1) on a
# process's FIRST gated call with urllib's global
# opener still unset, urlopen lazily built the opener
# and its HTTPS handler created a default context
# INSIDE the timed exchange; a cold context=None
# construction could likewise create during an armed
# exchange. (2) The per-exchange resolution cache was
# keyed (host, port): a same-host redirect to another
# port resolved again, contradicting "per distinct
# host". (3) The process-wide factory-context cache
# handed ONE MUTABLE context to separate context=None
# callers, diverging from stdlib's fresh-per-
# construction semantics. Fixes: the module installs
# the global opener at import when unset (exactly
# urlopen's lazy build_opener() act, moved to process
# start); the resolution cache is keyed by host alone
# and each connection substitutes its own port into
# the cached sockaddrs; the context cache is removed
# (fresh factory context per context=None construction
# — pinned by the rewritten N77 above, contract change
# #2). N78 and N79 below pin (1) and (2).

import re as _re28
import socket as _sock28
import ssl as _ssl28
import subprocess as _sp28
import tempfile as _tf28

_certdir28 = _tf28.mkdtemp(prefix="vf-tls28-")
_ca28 = os.path.join(_certdir28, "ca.pem")
_cakey28 = os.path.join(_certdir28, "ca.key")
_sp28.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
           "-keyout", _cakey28, "-out", _ca28, "-days", "2",
           "-nodes", "-subj", "/CN=vf-ca28",
           "-addext", "basicConstraints=critical,CA:TRUE",
           "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
          check=True, capture_output=True, timeout=60)
_cert28 = os.path.join(_certdir28, "cert.pem")
_key28 = os.path.join(_certdir28, "key.pem")
_csr28 = os.path.join(_certdir28, "srv.csr")
_ext28 = os.path.join(_certdir28, "srv.ext")
_sp28.run(["openssl", "req", "-newkey", "rsa:2048",
           "-keyout", _key28, "-out", _csr28, "-nodes",
           "-subj", "/CN=127.0.0.1"],
          check=True, capture_output=True, timeout=60)
with open(_ext28, "w") as _fext28:
    _fext28.write("subjectAltName=IP:127.0.0.1\n")
_sp28.run(["openssl", "x509", "-req", "-in", _csr28,
           "-CA", _ca28, "-CAkey", _cakey28,
           "-CAcreateserial", "-out", _cert28, "-days", "2",
           "-extfile", _ext28],
          check=True, capture_output=True, timeout=60)
_srvctx28 = _ssl28.SSLContext(_ssl28.PROTOCOL_TLS_SERVER)
_srvctx28.load_cert_chain(_cert28, _key28)


class _TlsHandler28(_hs25.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        try:
            left = int(self.headers.get("Content-Length") or 0)
        except Exception:
            left = 0
        try:
            while left > 0:
                piece = self.rfile.read(min(left, 65536))
                if not piece:
                    break
                left -= len(piece)
        except Exception:
            return
        if self.path == "/tls-ok":
            body = b'{"id": "mail-n78-ok"}'
            self.connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body)
                + body)


_SRV28 = _hs25.ThreadingHTTPServer(("127.0.0.1", 0),
                                   _TlsHandler28)
_SRV28.socket = _srvctx28.wrap_socket(_SRV28.socket,
                                      server_side=True)
_PORT28 = _SRV28.server_address[1]
_th28srv = threading.Thread(
    target=_SRV28.serve_forever,
    kwargs={"poll_interval": 0.05}, daemon=True)
_th28srv.start()


class _Redir28B(_hs25.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/target":
            body = b'{"id": "mail-n79-ok"}'
            self.connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body)
                + body)


_HSRV28B = _hs25.ThreadingHTTPServer(("127.0.0.1", 0),
                                     _Redir28B)
_HPORT28B = _HSRV28B.server_address[1]
_th28bsrv = threading.Thread(
    target=_HSRV28B.serve_forever,
    kwargs={"poll_interval": 0.05}, daemon=True)
_th28bsrv.start()


class _Redir28A(_hs25.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        try:
            left = int(self.headers.get("Content-Length") or 0)
        except Exception:
            left = 0
        try:
            while left > 0:
                piece = self.rfile.read(min(left, 65536))
                if not piece:
                    break
                left -= len(piece)
        except Exception:
            return
        if self.path == "/redir":
            self.connection.sendall(
                b"HTTP/1.1 302 Found\r\n"
                b"Location: http://127.0.0.1:%d/target\r\n"
                b"Content-Length: 0\r\n\r\n" % _HPORT28B)


_HSRV28A = _hs25.ThreadingHTTPServer(("127.0.0.1", 0),
                                     _Redir28A)
_HPORT28A = _HSRV28A.server_address[1]
_th28asrv = threading.Thread(
    target=_HSRV28A.serve_forever,
    kwargs={"poll_interval": 0.05}, daemon=True)
_th28asrv.start()

# N78 (1): opener warm-up — a FRESH SUBPROCESS specimen
# (the catalog's own process built its opener long ago;
# only a child interpreter starts cold). The driver
# wraps the stdlib context creators with counters
# BEFORE importing the server module, prints an
# IMPORT-DONE marker, then performs ONE gated send
# against the CA-signed local TLS server above and
# prints the send-phase counts. Trust design: the
# driver does NOT install a test opener — any install
# before the send would itself build an opener and
# mask the very defect under test. Instead the child's
# environment carries SSL_CERT_FILE=<the local CA>, so
# the default context — created by whichever opener
# build happens, at import (post-fix) or lazily inside
# the first urlopen (pre-fix) — trusts the test server,
# and the send runs through the installed opener with
# production mechanics on both trees. The trees differ
# ONLY in when the handler's context comes into
# existence: import phase (post-fix) vs inside the
# timed exchange (pre-fix).
_DRIVER78 = '''import http.client
import os
import ssl
import sys
import urllib.request

repo = sys.argv[1]
port = int(sys.argv[2])
dbpath = sys.argv[3]
sys.path.insert(0, repo)
os.environ["VF_DB_PATH"] = dbpath

counts = {"import": 0, "import_ssl": 0,
          "send": 0, "send_ssl": 0}
_phase = ["import"]
_real_hc = http.client._create_https_context
_real_ssl = ssl._create_default_https_context


def _counting_hc(http_version):
    counts[_phase[0]] += 1
    return _real_hc(http_version)


def _counting_ssl(*a, **kw):
    counts[_phase[0] + "_ssl"] += 1
    return _real_ssl(*a, **kw)


http.client._create_https_context = _counting_hc
ssl._create_default_https_context = _counting_ssl

import server as SRV

print("IMPORT-DONE hc=%d ssl=%d opener=%s" % (
    counts["import"], counts["import_ssl"],
    "set" if urllib.request._opener is not None
    else "unset"), flush=True)

_phase[0] = "send"
SRV.RESEND_API_KEY = "catalog-test-key"
SRV._GATED_SEND_DEADLINE = 10.0
SRV._RESEND_API_URL = "https://127.0.0.1:%d/tls-ok" % port
_conn = SRV.db_connect()
_cur = _conn.execute(
    "INSERT INTO orders(created_at,name,email,url,tier,"
    "notes,amount,status) VALUES(?,?,?,?,?,?,?,?)",
    (SRV.utcnow(), "Cat T", "n78@test.dev",
     "https://example.com", "Deep Scan", "", 29, "PAID"))
_oid = _cur.lastrowid
_conn.commit()
_conn.close()
_res = SRV._gated_send(_oid, SRV.send_resend,
                       "n78@test.dev",
                       "Payment received — Deep Scan", "body")
print("SEND status=%s id=%s hc=%d ssl=%d" % (
    SRV._send_status(_res), _res[1],
    counts["send"], counts["send_ssl"]), flush=True)
'''

_drvdir28 = _tf28.mkdtemp(prefix="vf-n78-")
_drvfile28 = os.path.join(_drvdir28, "driver78.py")
with open(_drvfile28, "w") as _fdrv28:
    _fdrv28.write(_DRIVER78)
_env78 = dict(os.environ)
_env78["SSL_CERT_FILE"] = _ca28
_run78 = _sp28.run(
    [sys.executable, _drvfile28,
     os.path.dirname(os.path.abspath(__file__)),
     str(_PORT28), os.path.join(_drvdir28, "n78.db")],
    env=_env78, capture_output=True, text=True, timeout=180)
_out78 = _run78.stdout or ""
print("N78 driver rc=%d stdout:\n%s"
      % (_run78.returncode, _out78))
if _run78.stderr:
    print("N78 driver stderr (tail):\n"
          + _run78.stderr[-2000:])
_mimp78 = _re28.search(
    r"IMPORT-DONE hc=(\d+) ssl=(\d+) opener=(set|unset)",
    _out78)
_msnd78 = _re28.search(
    r"SEND status=(\S+) id=(\S+) hc=(\d+) ssl=(\d+)",
    _out78)
check("N78 (1): fresh subprocess — importing the server "
      "module builds the global opener at import (its "
      "HTTPS handler's context is created in the import "
      "phase and the opener is set), and the first gated "
      "send creates no context inside the exchange and "
      "classifies delivered",
      _run78.returncode == 0
      and _mimp78 is not None
      and int(_mimp78.group(1)) >= 1
      and _mimp78.group(3) == "set"
      and _msnd78 is not None
      and _msnd78.group(1) == "delivered"
      and _msnd78.group(2) == "mail-n78-ok"
      and int(_msnd78.group(3)) == 0
      and int(_msnd78.group(4)) == 0)

# N79 (1): host-keyed resolution cache — a genuine
# wrapper exchange redirected (302) from the host on
# one port to the SAME host on ANOTHER port opens its
# second connection against the cached address set
# (its own port substituted): the host is resolved
# exactly once for the whole exchange (pre-fix: the
# (host, port) key missed and the host resolved twice).
_saved_url28 = SR._RESEND_API_URL
_saved_dl28 = SR._GATED_SEND_DEADLINE
_saved_open28 = _ureq18.urlopen
_real_gai28 = _sock28.getaddrinfo
_gai28 = []


def _counting_gai28(host, port, *a, **kw):
    if host == "127.0.0.1":
        _gai28.append((host, port))
    return _real_gai28(host, port, *a, **kw)


_ureq18.urlopen = _real_urlopen18
SR._GATED_SEND_DEADLINE = 10.0
SR._RESEND_API_URL = f"http://127.0.0.1:{_HPORT28A}/redir"
_sock28.getaddrinfo = _counting_gai28
o79 = mk_order("n79@test.dev", "Deep Scan", 29, status="PAID")
res79 = SR._gated_send(o79, SR.send_resend, "n79@test.dev",
                       "Payment received — Deep Scan", "body")
_sock28.getaddrinfo = _real_gai28
check("N79 (1): gated exchange redirected from the host "
      "on one port to the same host on another port — "
      "the final response classifies delivered and the "
      "host is resolved exactly once across both "
      "connections of the exchange",
      res79 is not None
      and SR._send_status(res79) == "delivered"
      and res79[1] == "mail-n79-ok"
      and len(_gai28) == 1)
_ureq18.urlopen = _saved_open28
SR._RESEND_API_URL = _saved_url28
SR._GATED_SEND_DEADLINE = _saved_dl28
_SRV28.shutdown()
_SRV28.server_close()
_HSRV28A.shutdown()
_HSRV28A.server_close()
_HSRV28B.shutdown()
_HSRV28B.server_close()

# ============================================================
# ROUND 29 — Codex delta-27: NO-SHIP on 383272a, two
# findings, both at the round-28 warm-up's edges.
# Certified (untouched): the host-keyed resolution
# cache; the context-cache removal; contract change
# #2; N78's specimen; catalog integrity. Findings:
# (1) the import-time warm-up was check-then-act — it
# tested _opener is None, built, then installed
# UNCONDITIONALLY, so a host opener installed
# concurrently during build_opener() was clobbered.
# Fix: build into a local, install only if the global
# is STILL None at install time (a re-check stdlib's
# own lazy branch does not perform). (2) The bound's
# "context creation never occurs inside a gated
# exchange" was broader than the mechanism: a
# pre-installed host opener (preserved by design) may
# create contexts inside its OWN machinery, and
# foreign direct constructions during an armed window
# follow stdlib on their own account. The statement is
# narrowed to the gated sends' OWN operation set with
# both exclusions named (JOURNAL round 29). N80 pins
# (1); N81 pins the pre-installed-opener guard that
# exclusion (i) of the narrowed statement relies on.

import re as _re29
import subprocess as _sp29
import tempfile as _tf29

# N80 (1): warm-up race — a FRESH SUBPROCESS specimen
# in N78's pattern. The driver patches
# urllib.request.build_opener BEFORE importing the
# server module: the patched builder builds a real
# opener, then installs a SENTINEL opener (simulating
# a host thread installing its own opener WHILE the
# warm-up's build is in flight), and returns the built
# opener. After the import, the driver reports whether
# the process-global opener is the sentinel. Pre-fix
# (check-then-act): the warm-up's unconditional
# install_opener(built) overwrites the sentinel —
# opener=other, the check fails. Post-fix (build into
# a local, re-check at install time): the warm-up sees
# the global is no longer None and does not install —
# opener=sentinel.
_DRIVER80 = '''import os
import sys
import urllib.request

repo = sys.argv[1]
dbpath = sys.argv[2]
sys.path.insert(0, repo)
os.environ["VF_DB_PATH"] = dbpath

_real_build_opener = urllib.request.build_opener
_SENTINEL = _real_build_opener()


def _racing_build_opener(*a, **kw):
    built = _real_build_opener(*a, **kw)
    # A host install landing DURING the build: by the
    # time build_opener() returns, the global opener
    # is the sentinel.
    urllib.request.install_opener(_SENTINEL)
    return built


urllib.request.build_opener = _racing_build_opener

import server as SRV

print("RACE80 opener=%s" % (
    "sentinel" if urllib.request._opener is _SENTINEL
    else "other"), flush=True)
'''

_drvdir29 = _tf29.mkdtemp(prefix="vf-n80-")
_drvfile80 = os.path.join(_drvdir29, "driver80.py")
with open(_drvfile80, "w") as _fdrv80:
    _fdrv80.write(_DRIVER80)
_run80 = _sp29.run(
    [sys.executable, _drvfile80,
     os.path.dirname(os.path.abspath(__file__)),
     os.path.join(_drvdir29, "n80.db")],
    capture_output=True, text=True, timeout=180)
_out80 = _run80.stdout or ""
print("N80 driver rc=%d stdout:\n%s"
      % (_run80.returncode, _out80))
if _run80.stderr:
    print("N80 driver stderr (tail):\n"
          + _run80.stderr[-2000:])
_mrace80 = _re29.search(r"RACE80 opener=(sentinel|other)",
                        _out80)
check("N80 (1): fresh subprocess — an opener installed "
      "concurrently DURING the warm-up's build_opener() "
      "survives the import: the warm-up builds into a "
      "local and installs only if the global opener is "
      "still unset at install time",
      _run80.returncode == 0
      and _mrace80 is not None
      and _mrace80.group(1) == "sentinel")

# N81 (1): guard regression pin — a FRESH SUBPROCESS
# specimen. The driver installs its own custom opener
# BEFORE importing the server module and asserts the
# global opener's identity is unchanged after import.
# This pin is GREEN on 383272a too: the warm-up's
# is-None guard already preserves a pre-installed
# opener; the pin exists because the narrowed
# statement's exclusion (i) — a host opener installed
# before import is preserved untouched by design —
# relies on exactly this guard. It is a regression
# pin, not a defect specimen.
_DRIVER81 = '''import os
import sys
import urllib.request

repo = sys.argv[1]
dbpath = sys.argv[2]
sys.path.insert(0, repo)
os.environ["VF_DB_PATH"] = dbpath

_HOST_OPENER = urllib.request.build_opener()
urllib.request.install_opener(_HOST_OPENER)

import server as SRV

print("GUARD81 opener=%s" % (
    "preserved" if urllib.request._opener is _HOST_OPENER
    else "replaced"), flush=True)
'''

_drvfile81 = os.path.join(_drvdir29, "driver81.py")
with open(_drvfile81, "w") as _fdrv81:
    _fdrv81.write(_DRIVER81)
_run81 = _sp29.run(
    [sys.executable, _drvfile81,
     os.path.dirname(os.path.abspath(__file__)),
     os.path.join(_drvdir29, "n81.db")],
    capture_output=True, text=True, timeout=180)
_out81 = _run81.stdout or ""
print("N81 driver rc=%d stdout:\n%s"
      % (_run81.returncode, _out81))
if _run81.stderr:
    print("N81 driver stderr (tail):\n"
          + _run81.stderr[-2000:])
_mguard81 = _re29.search(
    r"GUARD81 opener=(preserved|replaced)", _out81)
check("N81 (1): fresh subprocess — an opener a host "
      "process installed BEFORE importing the server "
      "module is preserved untouched by the import-time "
      "warm-up (guard regression pin; pins the is-None "
      "guard the narrowed statement's host-opener "
      "exclusion relies on)",
      _run81.returncode == 0
      and _mguard81 is not None
      and _mguard81.group(1) == "preserved")

# ============================================================
# ROUND 30 — Codex delta-28: NO-SHIP on 35f9423, ONE
# finding, statement-layer only. Certified (untouched):
# the double-check warm-up mechanics; pins N80/N81;
# catalog integrity and scope. The finding: the
# double-check also preserves an opener installed
# DURING the warm-up build (N80's sentinel case), but
# the JOURNAL's exclusion (i) named only openers
# installed BEFORE import; and the statement's handler
# rationale ("the global opener's handler passes its
# context to every construction") is established only
# for the STANDARD handler, not for arbitrary preserved
# host openers. Plus a wording qualification: the
# residual window spans from the final check until the
# install call completes — not a literal one-bytecode
# interval. THIS ROUND CHANGES NO PRODUCTION CODE:
# the JOURNAL statement is corrected (generalized
# exclusion; positive claim scoped to exchanges
# through the default opener; window phrase fixed),
# and N82 below is the statement's factual basis for
# the DURING-import case: a functional foreign opener
# installed during the build is preserved AND carries
# a gated send on its own context, with the module
# factory consulted 0 times. N82 is GREEN on 35f9423
# by design — the round-29 defect was documentary, in
# the text, not in behaviour; it is a basis pin, not
# a defect specimen.

import http.server as _hs30
import re as _re30
import ssl as _ssl30
import subprocess as _sp30
import tempfile as _tf30

_certdir30 = _tf30.mkdtemp(prefix="vf-tls30-")
_cert30 = os.path.join(_certdir30, "cert.pem")
_key30 = os.path.join(_certdir30, "key.pem")
_sp30.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
           "-keyout", _key30, "-out", _cert30, "-days", "2",
           "-nodes", "-subj", "/CN=127.0.0.1",
           "-addext", "subjectAltName=IP:127.0.0.1"],
          check=True, capture_output=True, timeout=60)
_srvctx30 = _ssl30.SSLContext(_ssl30.PROTOCOL_TLS_SERVER)
_srvctx30.load_cert_chain(_cert30, _key30)


class _TlsHandler30(_hs30.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        try:
            left = int(self.headers.get("Content-Length") or 0)
        except Exception:
            left = 0
        try:
            while left > 0:
                piece = self.rfile.read(min(left, 65536))
                if not piece:
                    break
                left -= len(piece)
        except Exception:
            return
        if self.path == "/tls-ok":
            body = b'{"id": "mail-n82-ok"}'
            self.connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body)
                + body)


_SRV30 = _hs30.ThreadingHTTPServer(("127.0.0.1", 0),
                                   _TlsHandler30)
_SRV30.socket = _srvctx30.wrap_socket(_SRV30.socket,
                                      server_side=True)
_PORT30 = _SRV30.server_address[1]
_th30srv = threading.Thread(
    target=_SRV30.serve_forever,
    kwargs={"poll_interval": 0.05}, daemon=True)
_th30srv.start()

# N82 (1): foreign opener installed DURING the import
# — a FRESH SUBPROCESS specimen in N78/N80's pattern.
# The driver patches urllib.request.build_opener
# BEFORE importing the server module: the patched
# builder builds the requested opener, then installs
# a FUNCTIONAL foreign opener (a real opener whose
# HTTPSHandler carries the unverified context the
# local self-signed test server needs — the round-26
# section's seam) — a host install landing DURING the
# warm-up's build. After the import the driver asserts
# the process-global opener IS that foreign opener
# (preserved through the warm-up by the double-check),
# wraps the module factory with a counter, and runs
# ONE gated send to the local TLS server: the send
# must classify delivered RIDING THE FOREIGN OPENER'S
# context (the handler supplies it; the deadline class
# uses it verbatim), with the module factory consulted
# 0 times during the send.
_DRIVER82 = '''import os
import ssl
import sys
import urllib.request

repo = sys.argv[1]
port = int(sys.argv[2])
dbpath = sys.argv[3]
sys.path.insert(0, repo)
os.environ["VF_DB_PATH"] = dbpath

_real_build_opener = urllib.request.build_opener
_FOREIGN = _real_build_opener(
    urllib.request.HTTPSHandler(
        context=ssl._create_unverified_context()))


def _installing_build_opener(*a, **kw):
    built = _real_build_opener(*a, **kw)
    # A host install landing DURING the build — here a
    # FUNCTIONAL opener: its HTTPSHandler carries the
    # unverified context the local test server needs.
    urllib.request.install_opener(_FOREIGN)
    return built


urllib.request.build_opener = _installing_build_opener

import server as SRV

print("FOREIGN82 opener=%s" % (
    "preserved" if urllib.request._opener is _FOREIGN
    else "replaced"), flush=True)

_real_factory82 = SRV._HTTPS_CONTEXT_FACTORY
_factory82 = [0]


def _counting_factory82(http_vsn):
    _factory82[0] += 1
    return _real_factory82(http_vsn)


SRV._HTTPS_CONTEXT_FACTORY = _counting_factory82

SRV.RESEND_API_KEY = "catalog-test-key"
SRV._GATED_SEND_DEADLINE = 10.0
SRV._RESEND_API_URL = "https://127.0.0.1:%d/tls-ok" % port
_conn = SRV.db_connect()
_cur = _conn.execute(
    "INSERT INTO orders(created_at,name,email,url,tier,"
    "notes,amount,status) VALUES(?,?,?,?,?,?,?,?)",
    (SRV.utcnow(), "Cat T", "n82@test.dev",
     "https://example.com", "Deep Scan", "", 29, "PAID"))
_oid = _cur.lastrowid
_conn.commit()
_conn.close()
_res = SRV._gated_send(_oid, SRV.send_resend,
                       "n82@test.dev",
                       "Payment received — Deep Scan", "body")
print("SEND status=%s id=%s factory=%d" % (
    SRV._send_status(_res), _res[1],
    _factory82[0]), flush=True)
'''

_drvdir30 = _tf30.mkdtemp(prefix="vf-n82-")
_drvfile82 = os.path.join(_drvdir30, "driver82.py")
with open(_drvfile82, "w") as _fdrv82:
    _fdrv82.write(_DRIVER82)
_run82 = _sp30.run(
    [sys.executable, _drvfile82,
     os.path.dirname(os.path.abspath(__file__)),
     str(_PORT30), os.path.join(_drvdir30, "n82.db")],
    capture_output=True, text=True, timeout=180)
_out82 = _run82.stdout or ""
print("N82 driver rc=%d stdout:\n%s"
      % (_run82.returncode, _out82))
if _run82.stderr:
    print("N82 driver stderr (tail):\n"
          + _run82.stderr[-2000:])
_mown82 = _re30.search(
    r"FOREIGN82 opener=(preserved|replaced)", _out82)
_msnd82 = _re30.search(
    r"SEND status=(\S+) id=(\S+) factory=(\d+)", _out82)
check("N82 (1): fresh subprocess — a FUNCTIONAL foreign "
      "opener installed DURING the warm-up's build is "
      "preserved as the process-global opener, and a "
      "gated send rides that opener's own machinery: "
      "delivered on the foreign handler's context with "
      "the module factory consulted 0 times (statement "
      "basis pin for the generalized host-opener "
      "exclusion; green by design on the pre-round tree "
      "— the defect it backs was in the statement text, "
      "not in behaviour)",
      _run82.returncode == 0
      and _mown82 is not None
      and _mown82.group(1) == "preserved"
      and _msnd82 is not None
      and _msnd82.group(1) == "delivered"
      and _msnd82.group(2) == "mail-n82-ok"
      and int(_msnd82.group(3)) == 0)
_SRV30.shutdown()
_SRV30.server_close()

# ROUND 31 — Codex delta-29: NO-SHIP on 87840b4, ONE
# finding, statement-layer only. Certified (untouched):
# the no-code-change round itself (server.py the same
# git blob), pin N82, the catalog chain, the generalized
# exclusion (i), the corrected window phrase, and
# everything behavioural through delta-28. The finding:
# the round-30 positive claim scoped the no-creation
# guarantee to the default opener "built by this
# module's warm-up OR the identical one built by
# urlopen's lazy branch" — but the lazy branch builds
# DURING the call, creating its handler's context
# inside the exchange, so the claim exceeded its scope
# for that sub-case. THIS ROUND CHANGES NO PRODUCTION
# CODE: the JOURNAL statement is corrected again — the
# claim's default-opener scope is narrowed to the
# module-warmed opener ALONE, and the lazy-build event
# is named in the bound as a residual: with the warm-up
# in place the process-global opener is built from
# process start, so urlopen's lazy branch can run
# inside a gated call ONLY if the process's own code
# reset the private global urllib.request._opener to
# None after import; the FIRST gated call after such a
# reset then contains stdlib's lazy build (once per
# reset, performed by stdlib itself), and subsequent
# calls ride the built opener under the claim. N83
# below is that residual's factual basis. N83 is GREEN
# on 87840b4 by design — the round-30 defect was in the
# claim's scope, in the text, not in behaviour; it is a
# basis pin, not a defect specimen.

import http.server as _hs31
import re as _re31
import ssl as _ssl31
import subprocess as _sp31
import tempfile as _tf31

_certdir31 = _tf31.mkdtemp(prefix="vf-tls31-")
_ca31 = os.path.join(_certdir31, "ca.pem")
_cakey31 = os.path.join(_certdir31, "ca.key")
_sp31.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
           "-keyout", _cakey31, "-out", _ca31, "-days", "2",
           "-nodes", "-subj", "/CN=vf-ca31",
           "-addext", "basicConstraints=critical,CA:TRUE",
           "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
          check=True, capture_output=True, timeout=60)
_cert31 = os.path.join(_certdir31, "cert.pem")
_key31 = os.path.join(_certdir31, "key.pem")
_csr31 = os.path.join(_certdir31, "srv.csr")
_ext31 = os.path.join(_certdir31, "srv.ext")
_sp31.run(["openssl", "req", "-newkey", "rsa:2048",
           "-keyout", _key31, "-out", _csr31, "-nodes",
           "-subj", "/CN=127.0.0.1"],
          check=True, capture_output=True, timeout=60)
with open(_ext31, "w") as _fext31:
    _fext31.write("subjectAltName=IP:127.0.0.1\n")
_sp31.run(["openssl", "x509", "-req", "-in", _csr31,
           "-CA", _ca31, "-CAkey", _cakey31,
           "-CAcreateserial", "-out", _cert31, "-days", "2",
           "-extfile", _ext31],
          check=True, capture_output=True, timeout=60)
_srvctx31 = _ssl31.SSLContext(_ssl31.PROTOCOL_TLS_SERVER)
_srvctx31.load_cert_chain(_cert31, _key31)


class _TlsHandler31(_hs31.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        try:
            left = int(self.headers.get("Content-Length") or 0)
        except Exception:
            left = 0
        try:
            while left > 0:
                piece = self.rfile.read(min(left, 65536))
                if not piece:
                    break
                left -= len(piece)
        except Exception:
            return
        if self.path == "/tls-ok":
            body = b'{"id": "mail-n83-ok"}'
            self.connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body)
                + body)


_SRV31 = _hs31.ThreadingHTTPServer(("127.0.0.1", 0),
                                   _TlsHandler31)
_SRV31.socket = _srvctx31.wrap_socket(_SRV31.socket,
                                      server_side=True)
_PORT31 = _SRV31.server_address[1]
_th31srv = threading.Thread(
    target=_SRV31.serve_forever,
    kwargs={"poll_interval": 0.05}, daemon=True)
_th31srv.start()

# N83 (1): the lazy-build residual — a FRESH SUBPROCESS
# specimen in N78's pattern. The driver imports the
# server module (the warm-up installs the global opener
# at process start), then the driver itself RESETS
# urllib.request._opener to None — simulating the
# process's own code dropping the private global after
# import, the only route by which urlopen's lazy branch
# can still run inside a gated call. The driver wraps
# the stdlib context creators (http.client's and ssl's)
# in one counter and runs TWO gated sends to the local
# CA-signed TLS server (the child's environment carries
# SSL_CERT_FILE=<the local CA>, N78's arrangement, so
# the default context — whenever built — trusts the
# server and both sends run on production mechanics):
# the FIRST send must classify delivered AND record at
# least one context creation inside the call (the lazy
# build: opener construction, including its HTTPS
# handler's context creation, performed by stdlib
# itself during that call); the SECOND send must
# classify delivered with ZERO creations (it rides the
# opener the lazy branch built). Together they are the
# exact shape the corrected statement names: one
# creation-bearing call per reset, excluded from the
# no-creation claim; every later call under the claim.
_DRIVER83 = '''import http.client
import os
import ssl
import sys
import urllib.request

repo = sys.argv[1]
port = int(sys.argv[2])
dbpath = sys.argv[3]
sys.path.insert(0, repo)
os.environ["VF_DB_PATH"] = dbpath

import server as SRV

print("WARMED83 opener=%s" % (
    "set" if urllib.request._opener is not None
    else "unset"), flush=True)

# The foreign reset: the process's own code drops the
# private global opener AFTER import (the warm-up had
# installed one at process start). urlopen's lazy branch
# is now the only way the next call can obtain an
# opener — and it builds one DURING that call.
urllib.request._opener = None

_created = [0]
_real_hc = http.client._create_https_context
_real_ssl = ssl._create_default_https_context


def _counting_hc(http_version):
    _created[0] += 1
    return _real_hc(http_version)


def _counting_ssl(*a, **kw):
    _created[0] += 1
    return _real_ssl(*a, **kw)


http.client._create_https_context = _counting_hc
ssl._create_default_https_context = _counting_ssl

SRV.RESEND_API_KEY = "catalog-test-key"
SRV._GATED_SEND_DEADLINE = 10.0
SRV._RESEND_API_URL = "https://127.0.0.1:%d/tls-ok" % port
_conn = SRV.db_connect()
_cur = _conn.execute(
    "INSERT INTO orders(created_at,name,email,url,tier,"
    "notes,amount,status) VALUES(?,?,?,?,?,?,?,?)",
    (SRV.utcnow(), "Cat T", "n83@test.dev",
     "https://example.com", "Deep Scan", "", 29, "PAID"))
_oid = _cur.lastrowid
_conn.commit()
_conn.close()
_res1 = SRV._gated_send(_oid, SRV.send_resend,
                        "n83@test.dev",
                        "Payment received — Deep Scan", "body")
print("SEND1 status=%s id=%s created=%d" % (
    SRV._send_status(_res1), _res1[1],
    _created[0]), flush=True)
_created[0] = 0
_res2 = SRV._gated_send(_oid, SRV.send_resend,
                        "n83@test.dev",
                        "Payment received — Deep Scan", "body")
print("SEND2 status=%s id=%s created=%d" % (
    SRV._send_status(_res2), _res2[1],
    _created[0]), flush=True)
'''

_drvdir31 = _tf31.mkdtemp(prefix="vf-n83-")
_drvfile83 = os.path.join(_drvdir31, "driver83.py")
with open(_drvfile83, "w") as _fdrv83:
    _fdrv83.write(_DRIVER83)
_env83 = dict(os.environ)
_env83["SSL_CERT_FILE"] = _ca31
_run83 = _sp31.run(
    [sys.executable, _drvfile83,
     os.path.dirname(os.path.abspath(__file__)),
     str(_PORT31), os.path.join(_drvdir31, "n83.db")],
    env=_env83, capture_output=True, text=True, timeout=180)
_out83 = _run83.stdout or ""
print("N83 driver rc=%d stdout:\n%s"
      % (_run83.returncode, _out83))
if _run83.stderr:
    print("N83 driver stderr (tail):\n"
          + _run83.stderr[-2000:])
_mwarm83 = _re31.search(r"WARMED83 opener=(set|unset)",
                        _out83)
_msnd83a = _re31.search(
    r"SEND1 status=(\S+) id=(\S+) created=(\d+)", _out83)
_msnd83b = _re31.search(
    r"SEND2 status=(\S+) id=(\S+) created=(\d+)", _out83)
check("N83 (1): fresh subprocess — the warm-up leaves "
      "the global opener set at import; after the "
      "process's own code resets urllib.request._opener "
      "to None, the FIRST gated send contains stdlib's "
      "lazy build (delivered, provider id returned, and "
      ">=1 stdlib context creation recorded inside the "
      "call) and the SECOND gated send rides the built "
      "opener (delivered, zero creations) — the factual "
      "basis of the statement's lazy-build residual "
      "(basis pin, green by design on the pre-round "
      "tree: the round-30 defect was in the claim's "
      "scope, not in behaviour)",
      _run83.returncode == 0
      and _mwarm83 is not None
      and _mwarm83.group(1) == "set"
      and _msnd83a is not None
      and _msnd83a.group(1) == "delivered"
      and _msnd83a.group(2) == "mail-n83-ok"
      and int(_msnd83a.group(3)) >= 1
      and _msnd83b is not None
      and _msnd83b.group(1) == "delivered"
      and _msnd83b.group(2) == "mail-n83-ok"
      and int(_msnd83b.group(3)) == 0)
_SRV31.shutdown()
_SRV31.server_close()

# ROUND 32 — Codex delta-30: NO-SHIP on e64146a, TWO
# findings, both documentary, both in the claim's
# enumeration. Certified (untouched): the no-code-change
# round itself, pin N83 (as a sequential basis pin), the
# catalog chain, exclusions (i)/(ii), and the deadline /
# classification / deletion provisions. Finding (1): the
# round-31 lazy-build residual guaranteed "the first
# gated call after the reset contains the build, one
# event per reset" and placed subsequent calls on the
# lazy-built opener "inside the claim" — a foreign
# urlopen can build first, concurrent foreign None-checks
# can build more than once, a failed build retries, and
# the lazy-built opener is not the module-warmed opener
# the claim was scoped to. Finding (2): the enumeration
# omitted concurrent creation routes — the module's OWN
# scanner seam (_tls_info, a fresh default context per
# probed connection) and ANY build_opener construction
# of an uninstalled opener (including a concurrent
# module reload re-running the warm-up build). THIS
# ROUND CHANGES NO PRODUCTION CODE: the JOURNAL bound
# is RESTRUCTURED around the invariant that is true —
# within a gated send's own operations no TLS context
# is created; the claim covers exchanges riding an
# ALREADY-BUILT opener OF THE STANDARD CONSTRUCTION
# (module-warmed or lazy-built — the identical
# build_opener() product; the two differ only in WHICH
# build event created them, and build events are
# excluded as a class); creation happens ONLY at the
# named non-send events of a four-class taxonomy:
# (1) opener/handler BUILD events (by whomever
# initiated, installed or never installed; NO guarantee
# about which call contains a lazy build or
# exactly-once-per-reset), (2) the module's own scanner
# seam's per-probe wraps, (3) foreign openers' machinery
# — exclusion (i), unchanged, (4) foreign direct
# constructions — exclusion (ii), unchanged. N84 and
# N85 below are that taxonomy's factual basis for
# classes (2) and (1) respectively. N84/N85 are GREEN
# on e64146a by design — basis pins for a documentary
# restructure, not defect specimens: the round-31
# defects were in the statement's guarantees and
# enumeration, not in the tree's behaviour.

import http.server as _hs32
import re as _re32
import socket as _sock32
import ssl as _ssl32
import subprocess as _sp32
import tempfile as _tf32

_certdir32 = _tf32.mkdtemp(prefix="vf-tls32-")
_ca32 = os.path.join(_certdir32, "ca.pem")
_cakey32 = os.path.join(_certdir32, "ca.key")
_sp32.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
           "-keyout", _cakey32, "-out", _ca32, "-days", "2",
           "-nodes", "-subj", "/CN=vf-ca32",
           "-addext", "basicConstraints=critical,CA:TRUE",
           "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
          check=True, capture_output=True, timeout=60)
_cert32 = os.path.join(_certdir32, "cert.pem")
_key32 = os.path.join(_certdir32, "key.pem")
_csr32 = os.path.join(_certdir32, "srv.csr")
_ext32 = os.path.join(_certdir32, "srv.ext")
_sp32.run(["openssl", "req", "-newkey", "rsa:2048",
           "-keyout", _key32, "-out", _csr32, "-nodes",
           "-subj", "/CN=127.0.0.1"],
          check=True, capture_output=True, timeout=60)
with open(_ext32, "w") as _fext32:
    _fext32.write("subjectAltName=IP:127.0.0.1\n")
_sp32.run(["openssl", "x509", "-req", "-in", _csr32,
           "-CA", _ca32, "-CAkey", _cakey32,
           "-CAcreateserial", "-out", _cert32, "-days", "2",
           "-extfile", _ext32],
          check=True, capture_output=True, timeout=60)
_srvctx32 = _ssl32.SSLContext(_ssl32.PROTOCOL_TLS_SERVER)
_srvctx32.load_cert_chain(_cert32, _key32)


class _TlsHandler32(_hs32.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        try:
            left = int(self.headers.get("Content-Length") or 0)
        except Exception:
            left = 0
        try:
            while left > 0:
                piece = self.rfile.read(min(left, 65536))
                if not piece:
                    break
                left -= len(piece)
        except Exception:
            return
        _ids32 = {"/tls-ok84": b"mail-n84-ok",
                  "/tls-ok85": b"mail-n85-ok"}
        if self.path in _ids32:
            body = b'{"id": "' + _ids32[self.path] + b'"}'
            self.connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body)
                + body)


_SRV32 = _hs32.ThreadingHTTPServer(("127.0.0.1", 0),
                                   _TlsHandler32)
_SRV32.socket = _srvctx32.wrap_socket(_SRV32.socket,
                                      server_side=True)
_PORT32 = _SRV32.server_address[1]
_th32srv = threading.Thread(
    target=_SRV32.serve_forever,
    kwargs={"poll_interval": 0.05}, daemon=True)
_th32srv.start()

# A raw TLS listener on 127.0.0.1:443 for the genuine
# _tls_info (its direct path connects to port 443 by
# construction): accept, complete the handshake with
# the same CA-signed cert, drain, close. Quiet by
# construction — every failure is swallowed per
# connection so the listener survives bad probes.
_lsock443 = _sock32.socket(_sock32.AF_INET,
                           _sock32.SOCK_STREAM)
_lsock443.setsockopt(_sock32.SOL_SOCKET,
                     _sock32.SO_REUSEADDR, 1)
_lsock443.bind(("127.0.0.1", 443))
_lsock443.listen(8)
_lsock443.settimeout(0.2)
_stop443 = [False]


def _one443(_c):
    try:
        _tls = _srvctx32.wrap_socket(_c, server_side=True)
        _tls.settimeout(2.0)
        try:
            _tls.recv(4096)
        except Exception:
            pass
        _tls.close()
    except Exception:
        try:
            _c.close()
        except Exception:
            pass


def _serve443():
    while not _stop443[0]:
        try:
            _conn443, _ = _lsock443.accept()
        except _sock32.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_one443, args=(_conn443,),
                         daemon=True).start()


_th443 = threading.Thread(target=_serve443, daemon=True)
_th443.start()

# N84 (1): taxonomy class (2) — a FRESH SUBPROCESS
# specimen in N78's pattern. The driver imports the
# server module (the warm-up installs the global
# opener), wraps ALL the stdlib context-creator seams
# in one counter (ssl.create_default_context — the
# seam _tls_info itself calls — plus ssl's and
# http.client's private creators, the N83 pair), forces
# _tls_info's DIRECT branch (it keys on HTTPS_PROXY at
# call time) with the SSRF guard opened to loopback,
# and calls the GENUINE SRV._tls_info("127.0.0.1")
# against the local CA-signed TLS server on port 443:
# the probe must RETURN a TLS version (proof the real
# function executed end to end — context creation,
# handshake, cert parse) with creations >= 1 recorded.
# The driver then zeroes the counter and runs ONE
# gated send on the built opener: delivered with ZERO
# creations — the scanner's creations are real and
# concurrent-capable, and none of them is a send
# operation. (The child's environment carries
# SSL_CERT_FILE=<the local CA>, N78's arrangement, so
# the default contexts — the probe's and the opener's —
# trust the local servers and everything runs on
# production mechanics.)
_DRIVER84 = '''import http.client
import os
import ssl
import sys
import urllib.request

repo = sys.argv[1]
port = int(sys.argv[2])
dbpath = sys.argv[3]
sys.path.insert(0, repo)
os.environ["VF_DB_PATH"] = dbpath

import server as SRV

print("WARMED84 opener=%s" % (
    "set" if urllib.request._opener is not None
    else "unset"), flush=True)

# Force _tls_info's direct branch (HTTPS_PROXY is read
# at call time) and let the SSRF guard accept the
# loopback target (also read at call time).
os.environ.pop("HTTPS_PROXY", None)
os.environ.pop("https_proxy", None)
os.environ["VF_ALLOW_PRIVATE_TARGETS"] = "1"

_created = [0]
_real_pub = ssl.create_default_context
_real_priv = ssl._create_default_https_context
_real_hc = http.client._create_https_context


def _counting_pub(*a, **kw):
    _created[0] += 1
    return _real_pub(*a, **kw)


def _counting_priv(*a, **kw):
    _created[0] += 1
    return _real_priv(*a, **kw)


def _counting_hc(http_version):
    _created[0] += 1
    return _real_hc(http_version)


ssl.create_default_context = _counting_pub
ssl._create_default_https_context = _counting_priv
http.client._create_https_context = _counting_hc

# Taxonomy class (2): the module's OWN scanner seam —
# the genuine _tls_info against the local TLS server
# on 127.0.0.1:443 (its direct path pins port 443).
_info = SRV._tls_info("127.0.0.1")
print("PROBE84 version=%s created=%d" % (
    _info["version"], _created[0]), flush=True)
_created[0] = 0

SRV.RESEND_API_KEY = "catalog-test-key"
SRV._GATED_SEND_DEADLINE = 10.0
SRV._RESEND_API_URL = "https://127.0.0.1:%d/tls-ok84" % port
_conn = SRV.db_connect()
_cur = _conn.execute(
    "INSERT INTO orders(created_at,name,email,url,tier,"
    "notes,amount,status) VALUES(?,?,?,?,?,?,?,?)",
    (SRV.utcnow(), "Cat T", "n84@test.dev",
     "https://example.com", "Deep Scan", "", 29, "PAID"))
_oid = _cur.lastrowid
_conn.commit()
_conn.close()
_res = SRV._gated_send(_oid, SRV.send_resend,
                       "n84@test.dev",
                       "Payment received — Deep Scan", "body")
print("SEND84 status=%s id=%s created=%d" % (
    SRV._send_status(_res), _res[1],
    _created[0]), flush=True)
'''

_drvdir32 = _tf32.mkdtemp(prefix="vf-n84-")
_drvfile84 = os.path.join(_drvdir32, "driver84.py")
with open(_drvfile84, "w") as _fdrv84:
    _fdrv84.write(_DRIVER84)
_env84 = dict(os.environ)
_env84["SSL_CERT_FILE"] = _ca32
_run84 = _sp32.run(
    [sys.executable, _drvfile84,
     os.path.dirname(os.path.abspath(__file__)),
     str(_PORT32), os.path.join(_drvdir32, "n84.db")],
    env=_env84, capture_output=True, text=True, timeout=180)
_out84 = _run84.stdout or ""
print("N84 driver rc=%d stdout:\n%s"
      % (_run84.returncode, _out84))
if _run84.stderr:
    print("N84 driver stderr (tail):\n"
          + _run84.stderr[-2000:])
_mwarm84 = _re32.search(r"WARMED84 opener=(set|unset)",
                        _out84)
_mprb84 = _re32.search(
    r"PROBE84 version=(\S+) created=(\d+)", _out84)
_msnd84 = _re32.search(
    r"SEND84 status=(\S+) id=(\S+) created=(\d+)", _out84)
check("N84 (1): fresh subprocess — the module's own "
      "scanner seam creates per probe while a gated "
      "send creates nothing: the genuine _tls_info "
      "against the local CA-signed TLS server returns "
      "a TLS version with >=1 counted stdlib context "
      "creation (taxonomy class (2): the scanner's "
      "per-probe wraps, by design, not send "
      "operations), and one gated send on the built "
      "opener is delivered with ZERO creations (basis "
      "pin, green by design on the pre-round tree: "
      "the round-31 defects were in the statement's "
      "guarantees and enumeration, not in behaviour)",
      _run84.returncode == 0
      and _mwarm84 is not None
      and _mwarm84.group(1) == "set"
      and _mprb84 is not None
      and int(_mprb84.group(2)) >= 1
      and _msnd84 is not None
      and _msnd84.group(1) == "delivered"
      and _msnd84.group(2) == "mail-n84-ok"
      and int(_msnd84.group(3)) == 0)

# N85 (1): taxonomy class (1) — a FRESH SUBPROCESS
# specimen in N78's pattern. The driver imports the
# server module (the warm-up installs the global
# opener), wraps the stdlib context creators in one
# counter, then calls urllib.request.build_opener()
# and does NOT install the result: the build event
# itself must record creations >= 1 (the HTTPS
# handler's context is created AT CONSTRUCTION —
# installed or never installed makes no difference),
# and the process-global opener must still be the
# warmed one afterwards, NOT the built object. The
# driver then zeroes the counter and runs ONE gated
# send on the built (warmed) opener: delivered with
# ZERO creations — creation belongs to the build
# event, never to a send operation on an
# already-built opener.
_DRIVER85 = '''import http.client
import os
import ssl
import sys
import urllib.request

repo = sys.argv[1]
port = int(sys.argv[2])
dbpath = sys.argv[3]
sys.path.insert(0, repo)
os.environ["VF_DB_PATH"] = dbpath

import server as SRV

print("WARMED85 opener=%s" % (
    "set" if urllib.request._opener is not None
    else "unset"), flush=True)

_created = [0]
_real_pub = ssl.create_default_context
_real_priv = ssl._create_default_https_context
_real_hc = http.client._create_https_context


def _counting_pub(*a, **kw):
    _created[0] += 1
    return _real_pub(*a, **kw)


def _counting_priv(*a, **kw):
    _created[0] += 1
    return _real_priv(*a, **kw)


def _counting_hc(http_version):
    _created[0] += 1
    return _real_hc(http_version)


ssl.create_default_context = _counting_pub
ssl._create_default_https_context = _counting_priv
http.client._create_https_context = _counting_hc

# Taxonomy class (1): an opener/handler BUILD event —
# build_opener() called and the result NEVER
# installed. Creation happens at the build; the
# global opener remains the warmed one.
_built = urllib.request.build_opener()
print("BUILD85 created=%d global=%s" % (
    _created[0],
    "warmed" if urllib.request._opener is not _built
    else "replaced"), flush=True)
_created[0] = 0

SRV.RESEND_API_KEY = "catalog-test-key"
SRV._GATED_SEND_DEADLINE = 10.0
SRV._RESEND_API_URL = "https://127.0.0.1:%d/tls-ok85" % port
_conn = SRV.db_connect()
_cur = _conn.execute(
    "INSERT INTO orders(created_at,name,email,url,tier,"
    "notes,amount,status) VALUES(?,?,?,?,?,?,?,?)",
    (SRV.utcnow(), "Cat T", "n85@test.dev",
     "https://example.com", "Deep Scan", "", 29, "PAID"))
_oid = _cur.lastrowid
_conn.commit()
_conn.close()
_res = SRV._gated_send(_oid, SRV.send_resend,
                       "n85@test.dev",
                       "Payment received — Deep Scan", "body")
print("SEND85 status=%s id=%s created=%d" % (
    SRV._send_status(_res), _res[1],
    _created[0]), flush=True)
'''

_drvfile85 = os.path.join(_drvdir32, "driver85.py")
with open(_drvfile85, "w") as _fdrv85:
    _fdrv85.write(_DRIVER85)
_env85 = dict(os.environ)
_env85["SSL_CERT_FILE"] = _ca32
_run85 = _sp32.run(
    [sys.executable, _drvfile85,
     os.path.dirname(os.path.abspath(__file__)),
     str(_PORT32), os.path.join(_drvdir32, "n85.db")],
    env=_env85, capture_output=True, text=True, timeout=180)
_out85 = _run85.stdout or ""
print("N85 driver rc=%d stdout:\n%s"
      % (_run85.returncode, _out85))
if _run85.stderr:
    print("N85 driver stderr (tail):\n"
          + _run85.stderr[-2000:])
_mwarm85 = _re32.search(r"WARMED85 opener=(set|unset)",
                        _out85)
_mbld85 = _re32.search(
    r"BUILD85 created=(\d+) global=(warmed|replaced)",
    _out85)
_msnd85 = _re32.search(
    r"SEND85 status=(\S+) id=(\S+) created=(\d+)", _out85)
check("N85 (1): fresh subprocess — an opener/handler "
      "BUILD event creates at construction while a "
      "gated send creates nothing: build_opener() "
      "called and never installed records >=1 counted "
      "stdlib context creation and leaves the global "
      "opener the warmed one (taxonomy class (1): "
      "build events, installed or never installed), "
      "and one gated send on the built opener is "
      "delivered with ZERO creations (basis pin, "
      "green by design on the pre-round tree: the "
      "round-31 defects were in the statement's "
      "guarantees and enumeration, not in behaviour)",
      _run85.returncode == 0
      and _mwarm85 is not None
      and _mwarm85.group(1) == "set"
      and _mbld85 is not None
      and int(_mbld85.group(1)) >= 1
      and _mbld85.group(2) == "warmed"
      and _msnd85 is not None
      and _msnd85.group(1) == "delivered"
      and _msnd85.group(2) == "mail-n85-ok"
      and int(_msnd85.group(3)) == 0)
_stop443[0] = True
_lsock443.close()
_SRV32.shutdown()
_SRV32.server_close()

# ROUND 33 — Codex delta-31: NO-SHIP on b793cd9, ONE
# finding, a genuine census catch. Certified
# (untouched): the restructured operative claim, the
# no-guarantee sentence for build events, classes
# (1)/(3)/(4) as far as they go, pins N84/N85 as
# honest basis evidence, the catalog chain to 158
# and the no-code-change round itself. The census
# mapped EVERY context-constructor site in
# server.py; exactly ONE was unassigned:
# server.py:1544, inside the scanner's
# _pinned_request — immediately after its own
# explicit wrap, the module constructs
# http.client.HTTPSConnection WITHOUT a context,
# and the constructor creates ANOTHER fresh context
# per construction by its own semantics (stdlib's
# constructor when unarmed; under the armed swap,
# the module's deadline class and its factory, on
# the scanner's account as initiator). Class (2)
# described only probe WRAPS; class (4) names
# FOREIGN direct constructions; a module-owned
# direct construction outside the send machinery
# belonged to neither, so the taxonomy did not
# close. THIS ROUND CHANGES NO PRODUCTION CODE:
# the JOURNAL widens class (2) by OWNERSHIP — THE
# MODULE'S OWN NON-SEND CONSTRUCTIONS: every
# TLS-context creation performed by this module's
# code outside the gated-send operations,
# comprising (2a) the scanner seam's explicit probe
# wraps (_tls_info and _pinned_request's wrap
# sites, a fresh default context per probed
# connection) and (2b) the scanner seam's DIRECT
# connection constructions without a supplied
# context (_pinned_request's HTTPSConnection
# construction) — with the precedence rule stated
# explicitly: opener/handler constructions are
# class (1) whoever initiates them (the warm-up is
# the module's own build and stays class (1));
# class (2) is the module's remaining non-send
# creations. N86 below is that widening's factual
# basis for class (2b). N86 is GREEN on b793cd9 by
# design — a basis pin for a documentary widening,
# not a defect specimen: behaviour does not change
# this round; the round-32 defect was in the
# taxonomy's enumeration, not in the tree's
# behaviour.

import http.server as _hs33
import re as _re33
import ssl as _ssl33
import subprocess as _sp33
import tempfile as _tf33

_certdir33 = _tf33.mkdtemp(prefix="vf-tls33-")
_ca33 = os.path.join(_certdir33, "ca.pem")
_cakey33 = os.path.join(_certdir33, "ca.key")
_sp33.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
           "-keyout", _cakey33, "-out", _ca33, "-days", "2",
           "-nodes", "-subj", "/CN=vf-ca33",
           "-addext", "basicConstraints=critical,CA:TRUE",
           "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
          check=True, capture_output=True, timeout=60)
_cert33 = os.path.join(_certdir33, "cert.pem")
_key33 = os.path.join(_certdir33, "key.pem")
_csr33 = os.path.join(_certdir33, "srv.csr")
_ext33 = os.path.join(_certdir33, "srv.ext")
_sp33.run(["openssl", "req", "-newkey", "rsa:2048",
           "-keyout", _key33, "-out", _csr33, "-nodes",
           "-subj", "/CN=127.0.0.1"],
          check=True, capture_output=True, timeout=60)
with open(_ext33, "w") as _fext33:
    _fext33.write("subjectAltName=IP:127.0.0.1\n")
_sp33.run(["openssl", "x509", "-req", "-in", _csr33,
           "-CA", _ca33, "-CAkey", _cakey33,
           "-CAcreateserial", "-out", _cert33, "-days", "2",
           "-extfile", _ext33],
          check=True, capture_output=True, timeout=60)
_srvctx33 = _ssl33.SSLContext(_ssl33.PROTOCOL_TLS_SERVER)
_srvctx33.load_cert_chain(_cert33, _key33)


class _TlsHandler33(_hs33.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        try:
            left = int(self.headers.get("Content-Length") or 0)
        except Exception:
            left = 0
        try:
            while left > 0:
                piece = self.rfile.read(min(left, 65536))
                if not piece:
                    break
                left -= len(piece)
        except Exception:
            return
        _ids33 = {"/tls-ok86": b"mail-n86-ok"}
        if self.path in _ids33:
            body = b'{"id": "' + _ids33[self.path] + b'"}'
            self.connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body)
                + body)


_SRV33 = _hs33.ThreadingHTTPServer(("127.0.0.1", 0),
                                   _TlsHandler33)
_SRV33.socket = _srvctx33.wrap_socket(_SRV33.socket,
                                      server_side=True)
_PORT33 = _SRV33.server_address[1]
_th33srv = threading.Thread(
    target=_SRV33.serve_forever,
    kwargs={"poll_interval": 0.05}, daemon=True)
_th33srv.start()

# N86 (1): taxonomy class (2b) — a FRESH SUBPROCESS
# specimen in N78's pattern. The driver imports the
# server module (the warm-up installs the global
# opener) and wraps the two creator seams in
# SEPARATE counters: ssl.create_default_context
# (the explicit-wrap seam) and
# http.client._create_https_context (the
# constructor seam — the function a context=None
# HTTPSConnection construction invokes for its own
# fresh context). The driver then drives the
# GENUINE scanner fetch path — SRV._fetch, the
# free-scan fetcher, which resolves, guard-checks
# and pins by SRV._pinned_request exactly as its
# production callers do — against the local
# CA-signed TLS server, with the SSRF guard opened
# to loopback: the probe must PERFORM its fetch (a
# real response status comes back over the wrapped
# socket) with the WRAP seam >= 1 (its own explicit
# ssl.create_default_context) AND the CONSTRUCTOR
# seam >= 1 — the server.py:1544 construction's own
# creation, a SECOND context distinct from the
# wrap's, on the scanner's account as initiator.
# The driver then zeroes both counters and runs ONE
# gated send on the built opener: delivered with
# BOTH counters at ZERO — the module's non-send
# constructions create on their own account, never
# as send operations. (The child's environment
# carries SSL_CERT_FILE=<the local CA>, N78's
# arrangement, so the default contexts trust the
# local server and everything runs on production
# mechanics.)
_DRIVER86 = '''import http.client
import os
import ssl
import sys
import urllib.request

repo = sys.argv[1]
port = int(sys.argv[2])
dbpath = sys.argv[3]
sys.path.insert(0, repo)
os.environ["VF_DB_PATH"] = dbpath

import server as SRV

print("WARMED86 opener=%s" % (
    "set" if urllib.request._opener is not None
    else "unset"), flush=True)

os.environ.pop("HTTPS_PROXY", None)
os.environ.pop("https_proxy", None)
os.environ["VF_ALLOW_PRIVATE_TARGETS"] = "1"

_wrap = [0]
_ctor = [0]
_real_wrap = ssl.create_default_context
_real_ctor = http.client._create_https_context


def _counting_wrap(*a, **kw):
    _wrap[0] += 1
    return _real_wrap(*a, **kw)


def _counting_ctor(http_version):
    _ctor[0] += 1
    return _real_ctor(http_version)


ssl.create_default_context = _counting_wrap
http.client._create_https_context = _counting_ctor

# Taxonomy class (2): the module's OWN non-send
# constructions — the genuine _fetch driving the
# genuine _pinned_request against the local TLS
# server on the URL's own port: the explicit wrap
# (class (2a)) and the context=None HTTPSConnection
# construction at server.py:1544 (class (2b)) each
# create, on separate seams.
_out = SRV._fetch("https://127.0.0.1:%d/probe86" % port)
print("PROBE86 status=%s wrap=%d ctor=%d" % (
    _out["status"], _wrap[0], _ctor[0]), flush=True)
_wrap[0] = 0
_ctor[0] = 0

SRV.RESEND_API_KEY = "catalog-test-key"
SRV._GATED_SEND_DEADLINE = 10.0
SRV._RESEND_API_URL = "https://127.0.0.1:%d/tls-ok86" % port
_conn = SRV.db_connect()
_cur = _conn.execute(
    "INSERT INTO orders(created_at,name,email,url,tier,"
    "notes,amount,status) VALUES(?,?,?,?,?,?,?,?)",
    (SRV.utcnow(), "Cat T", "n86@test.dev",
     "https://example.com", "Deep Scan", "", 29, "PAID"))
_oid = _cur.lastrowid
_conn.commit()
_conn.close()
_res = SRV._gated_send(_oid, SRV.send_resend,
                       "n86@test.dev",
                       "Payment received — Deep Scan", "body")
print("SEND86 status=%s id=%s wrap=%d ctor=%d" % (
    SRV._send_status(_res), _res[1],
    _wrap[0], _ctor[0]), flush=True)
'''

_drvdir33 = _tf33.mkdtemp(prefix="vf-n86-")
_drvfile86 = os.path.join(_drvdir33, "driver86.py")
with open(_drvfile86, "w") as _fdrv86:
    _fdrv86.write(_DRIVER86)
_env86 = dict(os.environ)
_env86["SSL_CERT_FILE"] = _ca33
_run86 = _sp33.run(
    [sys.executable, _drvfile86,
     os.path.dirname(os.path.abspath(__file__)),
     str(_PORT33), os.path.join(_drvdir33, "n86.db")],
    env=_env86, capture_output=True, text=True, timeout=180)
_out86 = _run86.stdout or ""
print("N86 driver rc=%d stdout:\n%s"
      % (_run86.returncode, _out86))
if _run86.stderr:
    print("N86 driver stderr (tail):\n"
          + _run86.stderr[-2000:])
_mwarm86 = _re33.search(r"WARMED86 opener=(set|unset)",
                        _out86)
_mprb86 = _re33.search(
    r"PROBE86 status=(\S+) wrap=(\d+) ctor=(\d+)",
    _out86)
_msnd86 = _re33.search(
    r"SEND86 status=(\S+) id=(\S+) wrap=(\d+) ctor=(\d+)",
    _out86)
check("N86 (1): fresh subprocess — the module's own "
      "NON-SEND constructions create on the scanner's "
      "account while a gated send creates nothing: "
      "the genuine _fetch/_pinned_request against the "
      "local CA-signed TLS server performs its fetch "
      "(a real response status returns) with the "
      "explicit-wrap seam >=1 AND the constructor "
      "seam >=1 — the server.py:1544 context=None "
      "HTTPSConnection construction's OWN fresh "
      "context, a second creation distinct from the "
      "wrap's (taxonomy class (2) as widened by "
      "ownership in round 33: (2a) probe wraps, (2b) "
      "the seam's direct constructions without a "
      "supplied context) — and one gated send on the "
      "built opener is delivered with BOTH seams at "
      "ZERO (basis pin, green by design on the "
      "pre-round tree: the round-32 defect was in "
      "the taxonomy's enumeration, not in behaviour)",
      _run86.returncode == 0
      and _mwarm86 is not None
      and _mwarm86.group(1) == "set"
      and _mprb86 is not None
      and _mprb86.group(1) != "None"
      and int(_mprb86.group(2)) >= 1
      and int(_mprb86.group(3)) >= 1
      and _msnd86 is not None
      and _msnd86.group(1) == "delivered"
      and _msnd86.group(2) == "mail-n86-ok"
      and int(_msnd86.group(3)) == 0
      and int(_msnd86.group(4)) == 0)
_SRV33.shutdown()
_SRV33.server_close()

failed = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(failed)}/{len(PASS)} catalog checks pass")
if failed:
    print("FAILED:", failed)
    sys.exit(1)
