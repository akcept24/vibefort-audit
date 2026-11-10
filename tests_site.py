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
c.execute("INSERT INTO event_locks(event_id,purpose,claimed_at) "
          "VALUES('evt_w16','unmatched-alert',?)", (time.time(),))
c.commit()
c.close()
r = stripe_call(evt("evt_w16"), sess(200, "w16@test.dev",
                                     pi="pi_w16"))
check("W16 foreign alert lock: step aside silently",
      r[0] == 500 and tg16["n"] == 0)
c = S.db_connect()
c.execute("DELETE FROM event_locks WHERE event_id='evt_w16'")
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

failed = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(failed)}/{len(PASS)} catalog checks pass")
if failed:
    print("FAILED:", failed)
    sys.exit(1)
