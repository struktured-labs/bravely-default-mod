#!/usr/bin/env bash
# Deterministic BDFFHD relaunch script
# Kills everything, clears locks, waits for clean state, launches, fullscreens
set -euo pipefail

GAME_DIR="$HOME/.steam/debian-installation/steamapps/common/BDFFHD"
COMPAT_DIR="$HOME/.steam/debian-installation/steamapps/compatdata/2833580"
PROTON_DIR="$HOME/.steam/debian-installation/steamapps/common/Proton - Experimental"
LOG_FILE="$GAME_DIR/MelonLoader/Latest.log"

echo "=== Killing everything ==="
# Kill game processes
pkill -9 -f "BDFFHD.exe" 2>/dev/null || true
pkill -9 -f "reaper.*2833580" 2>/dev/null || true
pkill -9 -f "pressure-vessel.*2833580" 2>/dev/null || true
pkill -9 -f "steam-launch-wrapper.*2833580" 2>/dev/null || true
sleep 2

# Kill wineserver for this prefix (the key step)
WINEPREFIX="$COMPAT_DIR/pfx" "$PROTON_DIR/files/bin/wineserver" -k9 2>/dev/null || true
sleep 2

# Remove stale lock
rm -f "$COMPAT_DIR/pfx.lock" 2>/dev/null || true

# Verify nothing left
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
rm -f "$LOG_FILE" 2>/dev/null || true

echo "=== Launching ==="
xdg-open "steam://rungameid/2833580" 2>/dev/null &
disown

# Poll for launch (check Steam console log for "Adding process")
echo "Waiting for Steam to launch game..."
TIMEOUT=30
ELAPSED=0
while ! tail -1 "$HOME/.steam/steam/logs/console-linux.txt" 2>/dev/null | grep -q "Adding process.*2833580"; do
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [ $ELAPSED -ge $TIMEOUT ]; then
        echo "  xdg-open failed, trying steam -applaunch..."
        steam -applaunch 2833580 &
        disown
        sleep 10
        break
    fi
    printf "."
done
echo ""

# Wait for MelonLoader to initialize
echo "Waiting for MelonLoader..."
TIMEOUT=90
ELAPSED=0
while ! grep -q "initialized" "$LOG_FILE" 2>/dev/null; do
    sleep 3
    ELAPSED=$((ELAPSED + 3))
    if [ $ELAPSED -ge $TIMEOUT ]; then
        echo "TIMEOUT: MelonLoader did not initialize in ${TIMEOUT}s"
        echo "Check: pgrep -f BDFFHD"
        exit 1
    fi
    printf "."
done
echo ""
echo "=== MelonLoader initialized ==="
grep "\[BravelyMod\]" "$LOG_FILE" 2>/dev/null | head -20

# Fullscreen
echo "=== Fullscreening ==="
sleep 3
cat > /tmp/kwin_fs.js << 'EOF'
var clients = workspace.windowList();
for (var i = 0; i < clients.length; i++) {
    if (clients[i].caption === "BRAVELY DEFAULT FLYING FAIRY") clients[i].fullScreen = true;
}
EOF
qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.loadScript "/tmp/kwin_fs.js" >/dev/null 2>&1
qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.start >/dev/null 2>&1

echo "=== Done ==="
