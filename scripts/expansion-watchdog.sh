#!/usr/bin/env bash
# Watches dataset-expansion.log and restarts the expander if it goes stale.
# Run: nohup bash scripts/expansion-watchdog.sh > server/logs/watchdog.log 2>&1 &

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$ROOT/server/logs/dataset-expansion.log"
EXPANDER="$ROOT/scripts/expand-dataset.py"
STALE_SECS=300   # restart if log hasn't updated in 5 minutes

log() { echo "[watchdog $(date -u '+%H:%M:%S')] $*"; }

log "Watchdog started. Stale threshold: ${STALE_SECS}s"

while true; do
    sleep 60

    # Check if expander is running
    PIDS=$(pgrep -f "expand-dataset.py" | tr '\n' ' ')

    # Get log age in seconds
    if [ -f "$LOG" ]; then
        MTIME=$(stat -c '%Y' "$LOG" 2>/dev/null || echo 0)
        NOW=$(date +%s)
        AGE=$(( NOW - MTIME ))
    else
        AGE=9999
    fi

    if [ -z "$PIDS" ]; then
        log "Expander not running — starting fresh"
        cd "$ROOT" && SENTINEL_DATAGEN=1 nohup python3 "$EXPANDER" >> "$LOG" 2>&1 &
        log "Started PID $!"
        sleep 20
    elif [ "$AGE" -gt "$STALE_SECS" ]; then
        log "Log stale (${AGE}s) — killing PIDs $PIDS and restarting"
        kill -9 $PIDS 2>/dev/null
        # Also nuke any orphan claude CLI processes from failed batches
        pkill -9 -f "claude.*haiku" 2>/dev/null
        sleep 3
        cd "$ROOT" && SENTINEL_DATAGEN=1 nohup python3 "$EXPANDER" >> "$LOG" 2>&1 &
        log "Restarted PID $!"
        sleep 20
    else
        log "OK — expander running (PIDs $PIDS), log age ${AGE}s"
    fi
done
