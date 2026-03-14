#!/usr/bin/env bash
# Headless smoke test for BravelyMod
# Launches BDFFHD on a virtual display, waits for MelonLoader, checks hooks
#
# Usage: ./scripts/test_headless.sh [timeout_seconds]
# Default timeout: 90 seconds

set -euo pipefail

GAME_DIR="$HOME/.steam/debian-installation/steamapps/common/BDFFHD"
LOG_FILE="$GAME_DIR/MelonLoader/Latest.log"
TIMEOUT="${1:-90}"
DISPLAY_NUM=99
SCREENSHOT_DIR="$(dirname "$0")/../tmp/test_screenshots"

mkdir -p "$SCREENSHOT_DIR"

# Cleanup on exit
cleanup() {
    echo "Cleaning up..."
    pkill -f "BDFFHD.exe" 2>/dev/null || true
    # Don't kill Xvfb if it was already running
    if [[ "${STARTED_XVFB:-}" == "1" ]]; then
        kill "$XVFB_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# 1. Start Xvfb if not already running
if ! pgrep -f "Xvfb :${DISPLAY_NUM}" >/dev/null 2>&1; then
    echo "Starting Xvfb on :${DISPLAY_NUM}..."
    Xvfb ":${DISPLAY_NUM}" -screen 0 1920x1080x24 -ac &
    XVFB_PID=$!
    STARTED_XVFB=1
    sleep 1
else
    echo "Xvfb already running on :${DISPLAY_NUM}"
fi

# 2. Remove old log
rm -f "$LOG_FILE"

# 3. Launch game on virtual display
echo "Launching BDFFHD on :${DISPLAY_NUM}..."
DISPLAY=":${DISPLAY_NUM}" steam -applaunch 2833580 &
sleep 5

# 4. Wait for MelonLoader initialization
echo "Waiting for MelonLoader (timeout: ${TIMEOUT}s)..."
ELAPSED=0
while ! grep -q "BravelyMod" "$LOG_FILE" 2>/dev/null; do
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [[ $ELAPSED -ge $TIMEOUT ]]; then
        echo "TIMEOUT: MelonLoader did not initialize in ${TIMEOUT}s"
        if [[ -f "$LOG_FILE" ]]; then
            echo "=== Log tail ==="
            tail -20 "$LOG_FILE"
        else
            echo "No log file created"
        fi
        exit 1
    fi
    printf "."
done
echo ""
echo "MelonLoader initialized after ${ELAPSED}s"

# 5. Check mod output
echo ""
echo "=== BravelyMod Output ==="
grep "\[BravelyMod\]" "$LOG_FILE" 2>/dev/null || echo "No BravelyMod output"

# 6. Check for errors
echo ""
echo "=== Errors ==="
grep -i "error\|exception\|crash\|failed" "$LOG_FILE" 2>/dev/null \
    | grep -v "BS DEBUG\|Il2CppAssembly\|DEBUG.*Method\|DEBUG.*unsupported\|Support Module\|Il2CppInterop\|MonoMod" \
    | head -10 || echo "No errors"

# 7. Take screenshot
sleep 5
DISPLAY=":${DISPLAY_NUM}" import -window root "$SCREENSHOT_DIR/headless_$(date +%Y%m%d_%H%M%S).png" 2>/dev/null \
    && echo "Screenshot saved to $SCREENSHOT_DIR/" \
    || echo "Screenshot failed (import not available)"

# 8. Summary
echo ""
HOOKS=$(grep -c "native hook" "$LOG_FILE" 2>/dev/null || echo 0)
HARMONY=$(grep -c "Harmony:" "$LOG_FILE" 2>/dev/null || echo 0)
echo "=== Summary ==="
echo "  Native hooks: $HOOKS"
echo "  Harmony patches: $HARMONY"

if grep -q "initialized!" "$LOG_FILE" 2>/dev/null; then
    echo "  Status: PASS"
    exit 0
else
    echo "  Status: FAIL (mod did not initialize)"
    exit 1
fi
