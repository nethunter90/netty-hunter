#!/usr/bin/env bash
# hunt-watch.sh — token-efficient hunt observer
#
# Usage:
#   ./scripts/hunt-watch.sh          # tail alerts + digest (default)
#   ./scripts/hunt-watch.sh alerts   # alerts only
#   ./scripts/hunt-watch.sh digest   # one-line status polling
#   ./scripts/hunt-watch.sh full     # full hunt-live.json (verbose)
#   ./scripts/hunt-watch.sh errors   # errors only

CONTEXT_DIR="$(dirname "$0")/../context"
MODE="${1:-alerts}"

mkdir -p "$CONTEXT_DIR"

case "$MODE" in
  alerts)
    echo "=== Hunt Alerts (token-efficient) ==="
    echo "--- last 10 stored alerts ---"
    tail -10 "$CONTEXT_DIR/alerts.jsonl" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        t = e.get('type','?').upper()
        ts = e.get('ts','')[-8:-3]
        parts = [f'[{ts}] {t}']
        if t == 'FINDING':
            parts.append(f\"{e.get('severity','?').upper()} {e.get('vulnClass','?')} @ {e.get('endpoint','?')[:60]}\")
        elif t == 'PHASE':
            parts.append(f\"iter={e.get('iteration','?')} phase={e.get('phase','?')}\")
        elif t == 'ERROR':
            parts.append(f\"{e.get('msg','?')[:100]}\")
        elif t == 'COMPLETE':
            parts.append(f\"findings={e.get('findings','?')} iters={e.get('iterations','?')} probes={e.get('probes','?')}\")
        print('  '.join(parts))
    except Exception:
        print(line.rstrip())
" 2>/dev/null || cat "$CONTEXT_DIR/alerts.jsonl" 2>/dev/null | tail -10
    echo ""
    echo "--- digest ---"
    cat "$CONTEXT_DIR/hunt-digest.txt" 2>/dev/null || echo "(no active hunt)"
    echo ""
    echo "--- live tail (Ctrl-C to stop) ---"
    tail -f "$CONTEXT_DIR/alerts.jsonl" 2>/dev/null | python3 -u -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        t = e.get('type','?').upper()
        ts = e.get('ts','')[-8:-3]
        if t == 'FINDING':
            print(f\"[\033[92m{ts}\033[0m] FOUND   {e.get('severity','?').upper()} {e.get('vulnClass','?')} @ {e.get('endpoint','?')[:70]}\")
        elif t == 'PHASE':
            print(f\"[\033[94m{ts}\033[0m] PHASE   iter={e.get('iteration','?')} -> {e.get('phase','?')}\")
        elif t == 'ERROR':
            print(f\"[\033[91m{ts}\033[0m] ERROR   {e.get('msg','?')[:100]}\")
        elif t == 'COMPLETE':
            print(f\"[\033[93m{ts}\033[0m] DONE    findings={e.get('findings','?')} iters={e.get('iterations','?')}\")
    except Exception:
        print(line.rstrip())
    sys.stdout.flush()
"
    ;;

  digest)
    echo "=== Digest polling (refresh every 3s, Ctrl-C to stop) ==="
    while true; do
      clear 2>/dev/null || printf '\033c'
      echo "=== Hunt Status ==="
      cat "$CONTEXT_DIR/hunt-digest.txt" 2>/dev/null || echo "(no active hunt)"
      echo ""
      echo "=== Last 5 Alerts ==="
      tail -5 "$CONTEXT_DIR/alerts.jsonl" 2>/dev/null
      sleep 3
    done
    ;;

  errors)
    echo "=== Error log (live) ==="
    tail -f "$CONTEXT_DIR/errors.jsonl" 2>/dev/null
    ;;

  full)
    echo "=== Full hunt state (polling) ==="
    while true; do
      clear 2>/dev/null || printf '\033c'
      cat "$CONTEXT_DIR/hunt-live.json" 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "(no active hunt)"
      sleep 5
    done
    ;;

  *)
    echo "Usage: $0 [alerts|digest|errors|full]"
    exit 1
    ;;
esac
