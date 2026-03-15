#!/usr/bin/env bash
# Headless BDFFHD launcher — runs game on Xvfb :99 for automated testing
# Does NOT fullscreen (not needed headless) and does NOT touch the user's display
#
# Usage: ./scripts/headless_launch.sh [--no-xvfb] [--timeout SECONDS]
#   --no-xvfb    Skip Xvfb start (assume it's already running)
#   --timeout N  Seconds to wait for MelonLoader init (default: 120)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

GAME_DIR="$HOME/.steam/debian-installation/steamapps/common/BDFFHD"
COMPAT_DIR="$HOME/.steam/debian-installation/steamapps/compatdata/2833580"
PROTON_DIR="$HOME/.steam/debian-installation/steamapps/common/Proton - Experimental"
LOG_FILE="$GAME_DIR/MelonLoader/Latest.log"
DISPLAY_NUM=99
HEADLESS_DISPLAY=":${DISPLAY_NUM}"
TIMEOUT=120
START_XVFB=1

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-xvfb) START_XVFB=0; shift ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

STARTED_XVFB=0

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    # Kill game processes
    pkill -9 -f "BDFFHD.exe" 2>/dev/null || true
    pkill -9 -f "reaper.*2833580" 2>/dev/null || true
    pkill -9 -f "pressure-vessel.*2833580" 2>/dev/null || true
    pkill -9 -f "steam-launch-wrapper.*2833580" 2>/dev/null || true
    sleep 1

    # Kill wineserver for this prefix
    WINEPREFIX="$COMPAT_DIR/pfx" "$PROTON_DIR/files/bin/wineserver" -k9 2>/dev/null || true
    rm -f "$COMPAT_DIR/pfx.lock" 2>/dev/null || true

    # Kill Xvfb only if we started it
    if [[ "$STARTED_XVFB" == "1" ]]; then
        kill "$XVFB_PID" 2>/dev/null || true
        echo "Killed Xvfb (pid $XVFB_PID)"
    fi
    echo "Cleanup done."
}
trap cleanup EXIT

# --- 1. Xvfb ---
if [[ "$START_XVFB" == "1" ]]; then
    if pgrep -f "Xvfb :${DISPLAY_NUM}" >/dev/null 2>&1; then
        echo "Xvfb already running on ${HEADLESS_DISPLAY}"
    else
        echo "Starting Xvfb on ${HEADLESS_DISPLAY} (1920x1080x24)..."
        Xvfb "${HEADLESS_DISPLAY}" -screen 0 1920x1080x24 -ac +extension GLX +render -noreset &
        XVFB_PID=$!
        STARTED_XVFB=1
        sleep 2
        if ! kill -0 "$XVFB_PID" 2>/dev/null; then
            echo "ERROR: Xvfb failed to start"
            exit 1
        fi
        echo "Xvfb running (pid $XVFB_PID)"
    fi
fi

# --- 2. Kill existing game ---
echo "=== Killing existing game processes ==="
pkill -9 -f "BDFFHD.exe" 2>/dev/null || true
pkill -9 -f "reaper.*2833580" 2>/dev/null || true
pkill -9 -f "pressure-vessel.*2833580" 2>/dev/null || true
pkill -9 -f "steam-launch-wrapper.*2833580" 2>/dev/null || true
sleep 2

WINEPREFIX="$COMPAT_DIR/pfx" "$PROTON_DIR/files/bin/wineserver" -k9 2>/dev/null || true
sleep 1
rm -f "$COMPAT_DIR/pfx.lock" 2>/dev/null || true

# Verify clean
for i in 1 2 3; do
    if pgrep -f "BDFFHD" >/dev/null 2>&1; then
        echo "  Still alive, killing again..."
        pkill -9 -f "BDFFHD" 2>/dev/null || true
        sleep 2
    else
        break
    fi
done
echo "=== Clean state confirmed ==="

# --- 3. Clear old log ---
rm -f "$LOG_FILE" 2>/dev/null || true

# --- 4. Launch on headless display ---
echo "=== Launching BDFFHD on ${HEADLESS_DISPLAY} ==="
DISPLAY="${HEADLESS_DISPLAY}" xdg-open "steam://rungameid/2833580" 2>/dev/null &
disown

# Poll for launch
echo "Waiting for Steam to launch game..."
LAUNCH_TIMEOUT=30
ELAPSED=0
while ! tail -1 "$HOME/.steam/steam/logs/console-linux.txt" 2>/dev/null | grep -q "Adding process.*2833580"; do
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [[ $ELAPSED -ge $LAUNCH_TIMEOUT ]]; then
        echo "  xdg-open timed out, trying steam -applaunch..."
        DISPLAY="${HEADLESS_DISPLAY}" steam -applaunch 2833580 &
        disown
        sleep 10
        break
    fi
    printf "."
done
echo ""

# --- 5. Wait for MelonLoader ---
echo "Waiting for MelonLoader init (timeout: ${TIMEOUT}s)..."
ELAPSED=0
while ! grep -q "initialized" "$LOG_FILE" 2>/dev/null; do
    sleep 3
    ELAPSED=$((ELAPSED + 3))
    if [[ $ELAPSED -ge $TIMEOUT ]]; then
        echo "TIMEOUT: MelonLoader did not initialize in ${TIMEOUT}s"
        if [[ -f "$LOG_FILE" ]]; then
            echo "=== Last 20 lines of log ==="
            tail -20 "$LOG_FILE"
        else
            echo "No log file created — game may not have started"
        fi
        exit 1
    fi
    printf "."
done
echo ""
echo "=== MelonLoader initialized (${ELAPSED}s) ==="

# --- 6. Print mod output ---
echo ""
echo "=== BravelyMod Output ==="
grep "\[BravelyMod\]" "$LOG_FILE" 2>/dev/null | head -30 || echo "(no BravelyMod messages)"

echo ""
echo "Game is running on ${HEADLESS_DISPLAY}. PID(s):"
pgrep -af "BDFFHD" 2>/dev/null || echo "(no matching processes?)"
echo ""
echo "To take a screenshot:  DISPLAY=${HEADLESS_DISPLAY} import -window root screenshot.png"
echo "To kill:               pkill -9 -f BDFFHD.exe"
