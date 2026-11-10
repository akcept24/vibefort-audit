#!/bin/sh
# ShipAudit Lab site container entrypoint.
# Starts the fulfilment bridge exporter as a background sidecar,
# then execs the ORIGINAL server command unchanged (same env, same
# args). The exporter is best-effort by design: it never blocks the
# server's start, and if it dies the site is unaffected (a missing
# export is retried by design on the next container start; the
# exporter also self-retries every pass while alive).
python3 /app/exporter.py &
exec python3 /app/server.py "$@"
