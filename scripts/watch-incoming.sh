#!/usr/bin/env bash
# Optional inotify watcher: when a file lands in ~/bs-dump/incoming, run ingest.
# Safe: only reads/extracts/scans; never patches or publishes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INCOMING="${BS_DUMP_ROOT:-$HOME/bs-dump}/incoming"
mkdir -p "$INCOMING"
if ! command -v inotifywait >/dev/null; then
  echo "inotifywait not installed. Install inotify-tools or run ingest.sh manually." >&2
  exit 1
fi
echo "Watching $INCOMING (Ctrl-C to stop). Auto-ingest on close_write/moved_to."
inotifywait -m -e close_write,moved_to --format '%w%f' "$INCOMING" | while read -r f; do
  case "$(echo "$f" | tr 'A-Z' 'a-z')" in
    *.cia|*.3ds|*.cci|*.cxi|*.app|*/code.bin|*.code)
      echo "[watch] ingest $f"
      # serialize
      flock -n "$INCOMING/.ingest.lock" "$ROOT/scripts/ingest.sh" "$f" \
        || echo "[watch] skipped (busy or failed): $f"
      ;;
    *)
      echo "[watch] ignore $f"
      ;;
  esac
done
