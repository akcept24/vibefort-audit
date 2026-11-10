# The Bridge — site → engine fulfilment exporter

**What this is.** The site's certified paid hook records every paid
Deep Scan as a durable row in the site DB's `fulfilment_requests`
table (status `queued`, payload = the order JSON). The engine robot
on the same host polls an inbox *directory* of JSON files. This
sidecar is the missing link between them: `exporter.py` runs inside
the site container next to `server.py`, reads the queued rows, and
drops each payload — verbatim, atomically — into the engine inbox as
`fulfilment-<order_id>.json`. The engine takes it from there; the
client-facing flow becomes: pay → row → file → robot scans → robot
emails the report, with no human touch.

**Files.** `exporter.py` (the sidecar, Python stdlib only),
`entrypoint.sh` (starts the exporter in the background, then execs
the original `python3 server.py` unchanged), `tests_exporter.py`
(its own catalog: `python3 tests_exporter.py`). `server.py` and
`tests_site.py` are untouched — byte-identical to the frozen tree.

**Env contract.**

| Var | Meaning | Default |
|---|---|---|
| `SITE_DB_PATH` | Site SQLite DB to read (read-only) | `$VF_DB_PATH` or `/data/vibefort.db` |
| `EXPORTER_INBOX_DIR` | Engine inbox directory (a mount, see below) | `/data/inbox` |
| `EXPORTER_LEDGER_PATH` | Exporter's own ledger, on the site volume | `/data/exporter-ledger.json` |
| `EXPORTER_POLL_SEC` | Poll interval, seconds | `15` |

**Semantics.** The DB is opened with SQLite URI `mode=ro` — the
exporter cannot write the site's tables. Per queued row: write the
payload bytes to a temp file in the inbox, fsync, `os.replace` onto
`fulfilment-<order_id>.json`, fsync the directory, *then* record
`order_id → sha256` in the ledger. The filename comes from the
**row's** `order_id` column, never from the payload; the payload
must parse and carry an `order_id` that is a strict int (no bool,
no float) equal to the row's, or the row is skipped and logged.
A crash between the file and the ledger re-exports next pass —
same name, same bytes, harmless. A changed payload (hash
mismatch) re-exports. An inbox-side fsync failure (file or
directory) *fails that row's export*: no ledger entry is
written, and the row is retried on a later pass (durability is
never recorded as established when it was not). A failure of the
**ledger** post-replace directory durability step (opening,
fsyncing and closing the directory after the replace) is the
one case where an entry can become visible without being
durable, because it happens after the atomic replace: that
export still counts as FAILED,
and the entry is held in an in-memory **suspect set** for the
life of the process. A suspect entry is trusted (skipped) only
when the skip decision sees the inbox file present with a
sha256 equal to the ledger hash — then it leaves the set; if
the file is missing or mismatched, the row is re-exported.
**Named residual of this semantics:** the suspect set is
in-memory, so an *unobserved* power loss in exactly that
window (ledger entry survives on disk, inbox file does not),
followed by a process restart, can still lose that one export
— the restarted exporter sees a normal-looking ledger entry
and skips the row. The window is bounded to the ledger
directory durability-step failure itself, and any *observed*
durability-step failure (the exporter still running) is
fully covered by the suspect mechanism above. Errors are
logged and the loop continues with capped backoff: the
backoff exponent is capped before exponentiation, the poll
interval is sanitized at startup (invalid values fall back
to 15s; huge finite values are clamped to a 3600s maximum,
so no value can make `time.sleep` overflow), and an
outermost guard catches any other exception from an
iteration (the pass, the interval wait, the backoff sleep).
A failed iteration always waits out its recovery deadline:
the handler's recovery wait is a monotonic-deadline wait
that keeps attempting small sleeps, swallowing their
failures, until the deadline passes — so no failure of the
sleep primitive itself can make the loop spin. Logging
failures inside run_loop's own machinery cannot kill it
either: startup sanitization runs inside the guarded
structure, and every log call in run_loop's machinery goes
through a never-raising wrapper. No failure count and no
bad config value can terminate the exporter. The exporter never creates the inbox
directory (a missing mount must stay a visible, logged retry —
not a silently created local folder).

**Config guard.** At startup (and on every pass) the exporter
resolves the DB path, the ledger path, and the ledger's TEMP
path (the name `save_ledger` writes through, computed in one
helper shared by the writer and the guard) with `realpath`.
If the DB path equals either ledger name, that is a
misconfiguration: proceeding could let the ledger write
replace the site DB itself (final path) or truncate it by
opening the temp name for writing. The exporter then writes
NOTHING, logs the misconfiguration loudly, and idles in the
retry loop until the configuration is fixed. Ledger temp
files are always created in the ledger's own directory.

**Named residual — the deletion race (accepted).** There is a
window from the moment the exporter reads a `queued` row to the
moment its file lands in the engine inbox. If an admin deletes
that order inside the window, the row is already read, so the
file still lands and the engine may still deliver the report for
that (paid) order. This residual is accepted by the parent as an
operational residual: the order was paid before it was deleted,
and no unpaid fulfilment, no duplicate, and no money error
arises from this race — the worst outcome is a delivered report
for a just-deleted paid order. (A second read before writing
would narrow the window, not close it; it is not claimed to.)

**Production wiring (parent's steps, Coolify).**
1. On the host, note the engine app's inbox host directory (the
   `shipaudit-engine` app's `/data/inbox` volume path under
   `/data/coolify/applications/<engine-uuid>/inbox`) — the exact
   production host path is **confirmed at wiring time by the
   parent**; this document does not assert it.
2. In the SITE app (`shipauditlab`), add a volume mount: that same
   host directory → container path `/data/engine-inbox`, and set
   env `EXPORTER_INBOX_DIR=/data/engine-inbox` on the site app.
   (The site volume already provides `SITE_DB_PATH` via
   `VF_DB_PATH=/data/vibefort.db` and the ledger's home `/data`.)
3. Redeploy the site app from the bridge tree (stop-then-start,
   one container). The entrypoint starts the exporter alongside
   the server.
4. Verify: container logs show `[exporter] starting: …` and, after
   the next paid Deep Scan, `[exporter] exported order <id> …`; the
   file `fulfilment-<id>.json` appears in the engine inbox and the
   engine's poller picks it up (its outbox `.done.json` follows).

**Trust argument (five lines).**
1. Rows in `fulfilment_requests` are created only by the certified
   paid hook, only for orders that actually paid — that table is
   the trust root.
2. The exporter exports only `status='queued'` rows, payload bytes
   verbatim; it holds no credentials and can mint nothing.
3. It opens the site DB read-only, so it cannot create, alter, or
   delete orders even if it malfunctions.
4. A duplicate or repeated file is harmless: the name is
   deterministic per order, and this bridge *relies on* the
   engine's order-keyed delivery evidence (send barrier +
   delivery evidence, certified in the engine wall) for
   idempotence — that property is relied upon here, not proven
   by this tree.
5. Worst case of an exporter failure is a delayed report, never a
   wrong one: no file, no fulfilment — and the loop retries.
