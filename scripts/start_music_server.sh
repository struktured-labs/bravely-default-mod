#!/usr/bin/env bash
# start_music_server.sh - Start the BDFFHD music conversion server
#
# This server handles MP3/WAV/OGG/FLAC -> HCA conversion for the
# BDFFHD mod web UI. The browser uploads files directly to this server
# on port 8889, bypassing Wine's HttpListener limitations with large files.
#
# Usage:
#   ./scripts/start_music_server.sh           # foreground
#   ./scripts/start_music_server.sh --bg      # background (logs to logs/)
#
# The server requires ffmpeg and PyCriCodecs (already in the project venv).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$PROJECT_DIR/logs"

cd "$PROJECT_DIR"

# Source setenv.sh if it exists
if [[ -f "$PROJECT_DIR/setenv.sh" ]]; then
    # shellcheck disable=SC1091
    source "$PROJECT_DIR/setenv.sh"
fi

if [[ "${1:-}" == "--bg" ]]; then
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/music_server.log"
    echo "Starting music conversion server in background..."
    echo "Log file: $LOG_FILE"
    nohup uv run python scripts/music_server.py > "$LOG_FILE" 2>&1 &
    echo "PID: $!"
    echo "Server should be available at http://localhost:${MUSIC_SERVER_PORT:-8889}/"
else
    exec uv run python scripts/music_server.py
fi
