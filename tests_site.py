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

failed = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(failed)}/{len(PASS)} catalog checks pass")
if failed:
    print("FAILED:", failed)
    sys.exit(1)
