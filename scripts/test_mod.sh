#!/usr/bin/env bash
# Comprehensive headless mod test for BravelyMod
# Starts Xvfb, restores known save state, launches game, validates mod hooks,
# takes screenshots, and reports pass/fail per feature.
#
# Usage: ./scripts/test_mod.sh [--timeout SECONDS] [--skip-save-restore] [--no-xvfb]
#   --timeout N           Seconds to wait for MelonLoader (default: 120)
#   --skip-save-restore   Don't copy save backup (use whatever's there)
#   --no-xvfb             Skip Xvfb management (assume :99 is running)
#   --keep-alive          Don't kill game/Xvfb on exit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# --- Paths ---
GAME_DIR="$HOME/.steam/debian-installation/steamapps/common/BDFFHD"
COMPAT_DIR="$HOME/.steam/debian-installation/steamapps/compatdata/2833580"
PROTON_DIR="$HOME/.steam/debian-installation/steamapps/common/Proton - Experimental"
LOG_FILE="$GAME_DIR/MelonLoader/Latest.log"
SAVE_BACKUP="$PROJECT_DIR/tmp/save_backup"
SAVE_DEST="$COMPAT_DIR/pfx/drive_c/users/steamuser/Documents/My Games/BRAVELY DEFAULT/Steam/76561198080785161"
SCREENSHOT_DIR="$PROJECT_DIR/tmp/test_screenshots"
RESULTS_DIR="$PROJECT_DIR/tmp/test_results"
DISPLAY_NUM=99
HEADLESS_DISPLAY=":${DISPLAY_NUM}"

# --- Defaults ---
TIMEOUT=120
RESTORE_SAVE=1
START_XVFB=1
KEEP_ALIVE=0

# --- Parse args ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --skip-save-restore) RESTORE_SAVE=0; shift ;;
        --no-xvfb) START_XVFB=0; shift ;;
        --keep-alive) KEEP_ALIVE=1; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

mkdir -p "$SCREENSHOT_DIR" "$RESULTS_DIR"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RESULT_FILE="$RESULTS_DIR/test_${TIMESTAMP}.txt"
STARTED_XVFB=0

# --- Tracking ---
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

result() {
    local status="$1" feature="$2" detail="${3:-}"
    local line="[$status] $feature"
    [[ -n "$detail" ]] && line="$line — $detail"
    echo "$line"
    echo "$line" >> "$RESULT_FILE"
    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac
}

# --- Cleanup ---
cleanup() {
    if [[ "$KEEP_ALIVE" == "1" ]]; then
        echo ""
        echo "=== --keep-alive: leaving game and Xvfb running ==="
        return
    fi
    echo ""
    echo "=== Cleanup ==="
    pkill -9 -f "BDFFHD.exe" 2>/dev/null || true
    pkill -9 -f "reaper.*2833580" 2>/dev/null || true
    pkill -9 -f "pressure-vessel.*2833580" 2>/dev/null || true
    pkill -9 -f "steam-launch-wrapper.*2833580" 2>/dev/null || true
    sleep 1
    WINEPREFIX="$COMPAT_DIR/pfx" "$PROTON_DIR/files/bin/wineserver" -k9 2>/dev/null || true
    rm -f "$COMPAT_DIR/pfx.lock" 2>/dev/null || true

    if [[ "$STARTED_XVFB" == "1" ]]; then
        kill "$XVFB_PID" 2>/dev/null || true
        echo "Killed Xvfb (pid $XVFB_PID)"
    fi
    echo "Cleanup done."
}
trap cleanup EXIT

echo "==========================================="
echo "  BDFFHD Mod Test — $(date)"
echo "==========================================="
echo "" > "$RESULT_FILE"

# ===================================================================
# PHASE 1: Setup
# ===================================================================
echo ""
echo "--- Phase 1: Setup ---"

# 1a. Start Xvfb
if [[ "$START_XVFB" == "1" ]]; then
    if pgrep -f "Xvfb :${DISPLAY_NUM}" >/dev/null 2>&1; then
        echo "Xvfb already running on ${HEADLESS_DISPLAY}"
    else
        echo "Starting Xvfb on ${HEADLESS_DISPLAY}..."
        Xvfb "${HEADLESS_DISPLAY}" -screen 0 1920x1080x24 -ac +extension GLX +render -noreset &
        XVFB_PID=$!
        STARTED_XVFB=1
        sleep 2
        if ! kill -0 "$XVFB_PID" 2>/dev/null; then
            echo "FATAL: Xvfb failed to start"
            exit 1
        fi
    fi
    result "PASS" "Xvfb" "running on ${HEADLESS_DISPLAY}"
else
    if pgrep -f "Xvfb :${DISPLAY_NUM}" >/dev/null 2>&1; then
        result "PASS" "Xvfb" "already running (--no-xvfb)"
    else
        result "FAIL" "Xvfb" "not running and --no-xvfb specified"
        exit 1
    fi
fi

# 1b. Restore save backup
if [[ "$RESTORE_SAVE" == "1" ]]; then
    if [[ -d "$SAVE_BACKUP" ]] && [[ -f "$SAVE_BACKUP/save0" ]]; then
        mkdir -p "$SAVE_DEST"
        cp -v "$SAVE_BACKUP"/* "$SAVE_DEST/" 2>&1 | head -10
        result "PASS" "Save restore" "copied to $SAVE_DEST"
    else
        result "FAIL" "Save restore" "backup not found at $SAVE_BACKUP"
    fi
else
    result "SKIP" "Save restore" "--skip-save-restore"
fi

# 1c. Verify mod DLL is deployed
MOD_DLL="$GAME_DIR/Mods/BravelyMod.dll"
if [[ -f "$MOD_DLL" ]]; then
    MOD_AGE=$(( $(date +%s) - $(stat -c %Y "$MOD_DLL") ))
    result "PASS" "Mod deployed" "BravelyMod.dll (age: ${MOD_AGE}s)"
else
    result "FAIL" "Mod deployed" "BravelyMod.dll not found in $GAME_DIR/Mods/"
fi

# ===================================================================
# PHASE 2: Kill & Launch
# ===================================================================
echo ""
echo "--- Phase 2: Kill & Launch ---"

# Kill everything
pkill -9 -f "BDFFHD.exe" 2>/dev/null || true
pkill -9 -f "reaper.*2833580" 2>/dev/null || true
pkill -9 -f "pressure-vessel.*2833580" 2>/dev/null || true
pkill -9 -f "steam-launch-wrapper.*2833580" 2>/dev/null || true
sleep 2
WINEPREFIX="$COMPAT_DIR/pfx" "$PROTON_DIR/files/bin/wineserver" -k9 2>/dev/null || true
sleep 1
rm -f "$COMPAT_DIR/pfx.lock" 2>/dev/null || true
rm -f "$LOG_FILE" 2>/dev/null || true

# Launch
echo "Launching BDFFHD on ${HEADLESS_DISPLAY}..."
DISPLAY="${HEADLESS_DISPLAY}" xdg-open "steam://rungameid/2833580" 2>/dev/null &
disown

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

# ===================================================================
# PHASE 3: Wait for MelonLoader
# ===================================================================
echo ""
echo "--- Phase 3: MelonLoader Init ---"

ELAPSED=0
while ! grep -q "initialized" "$LOG_FILE" 2>/dev/null; do
    sleep 3
    ELAPSED=$((ELAPSED + 3))
    if [[ $ELAPSED -ge $TIMEOUT ]]; then
        result "FAIL" "MelonLoader init" "timed out after ${TIMEOUT}s"
        if [[ -f "$LOG_FILE" ]]; then
            echo "=== Last 30 lines of log ==="
            tail -30 "$LOG_FILE"
        else
            echo "No log file created"
        fi
        # Print summary even on early exit
        echo ""
        echo "==========================================="
        echo "  EARLY EXIT — MelonLoader failed to init"
        echo "  Results: $PASS_COUNT pass, $FAIL_COUNT fail, $SKIP_COUNT skip"
        echo "  Full results: $RESULT_FILE"
        echo "==========================================="
        exit 1
    fi
    printf "."
done
echo ""
result "PASS" "MelonLoader init" "${ELAPSED}s"

# Check mods loaded count
MODS_LOADED=$(grep -oP '\d+ Mods loaded' "$LOG_FILE" 2>/dev/null | head -1 || echo "")
if [[ -n "$MODS_LOADED" ]]; then
    result "PASS" "Mods loaded" "$MODS_LOADED"
else
    result "FAIL" "Mods loaded" "no 'Mods loaded' message"
fi

# ===================================================================
# PHASE 4: Parse BravelyMod Messages
# ===================================================================
echo ""
echo "--- Phase 4: BravelyMod Hook Analysis ---"

# Collect all BravelyMod messages
BMOD_MSGS=$(grep "\[BravelyMod\]" "$LOG_FILE" 2>/dev/null || true)

if [[ -z "$BMOD_MSGS" ]]; then
    result "FAIL" "BravelyMod output" "no [BravelyMod] messages in log"
else
    MSG_COUNT=$(echo "$BMOD_MSGS" | wc -l)
    result "PASS" "BravelyMod output" "${MSG_COUNT} messages"
    echo "$BMOD_MSGS" >> "$RESULT_FILE"
fi

# Check mod initialization
if echo "$BMOD_MSGS" | grep -qi "initialized"; then
    result "PASS" "BravelyMod initialized" ""
else
    result "FAIL" "BravelyMod initialized" "no initialization message"
fi

# Check for Harmony patches attached
HARMONY_PATCHES=$(grep -i "harmony\|HarmonyPatch\|Patching" "$LOG_FILE" 2>/dev/null | grep -v "DEBUG" || true)
if [[ -n "$HARMONY_PATCHES" ]]; then
    PATCH_COUNT=$(echo "$HARMONY_PATCHES" | wc -l)
    result "PASS" "Harmony patches" "${PATCH_COUNT} patch messages"
else
    result "SKIP" "Harmony patches" "no Harmony messages (may be normal)"
fi

# Check for native hooks
NATIVE_HOOKS=$(grep -i "native hook\|NativeHook\|detour" "$LOG_FILE" 2>/dev/null || true)
if [[ -n "$NATIVE_HOOKS" ]]; then
    HOOK_COUNT=$(echo "$NATIVE_HOOKS" | wc -l)
    result "PASS" "Native hooks" "${HOOK_COUNT} hook messages"
else
    result "SKIP" "Native hooks" "no native hook messages"
fi

# --- Feature-specific checks ---
# These check for specific mod features by looking for their log signatures.
# Add new features here as they're implemented.

declare -A FEATURES=(
    ["Damage cap"]="damage.*cap\|DamageRange\|CheckDamageRange"
    ["EXP system"]="exp\|EXP\|ReviseAddEXP"
    ["BP system"]="bp.*limit\|GetLimitBP\|BP"
    ["Battle speed"]="speed\|TimeSpeed\|SetTimeSpeed"
    ["AutoBattle"]="auto.*battle\|AutoBattle\|ProcessAutoBattle"
    ["Colony"]="colony\|Colony\|FenceParameter"
    ["Config loaded"]="config\|preference\|MelonPreferences"
)

echo ""
echo "--- Feature Hooks ---"
for feature in "${!FEATURES[@]}"; do
    pattern="${FEATURES[$feature]}"
    if echo "$BMOD_MSGS" | grep -qiE "$pattern"; then
        detail=$(echo "$BMOD_MSGS" | grep -iE "$pattern" | head -1 | sed 's/.*\[BravelyMod\] //')
        result "PASS" "$feature" "$detail"
    else
        result "SKIP" "$feature" "no log evidence (may not be implemented yet)"
    fi
done

# ===================================================================
# PHASE 5: Error Detection
# ===================================================================
echo ""
echo "--- Phase 5: Error Detection ---"

# Serious errors (filter out known benign noise)
ERRORS=$(grep -iE "error|exception|crash|failed|FATAL" "$LOG_FILE" 2>/dev/null \
    | grep -v "BS DEBUG\|Il2CppAssembly\|DEBUG.*Method\|DEBUG.*unsupported\|Support Module\|Il2CppInterop\|MonoMod\|wine\|OpenXR\|SteamVR\|XR\|shader.*error\|Shader.*warning" \
    | head -20 || true)

if [[ -z "$ERRORS" ]]; then
    result "PASS" "No errors" ""
else
    ERROR_COUNT=$(echo "$ERRORS" | wc -l)
    result "FAIL" "Errors found" "${ERROR_COUNT} error lines"
    echo "$ERRORS"
    echo "" >> "$RESULT_FILE"
    echo "=== ERRORS ===" >> "$RESULT_FILE"
    echo "$ERRORS" >> "$RESULT_FILE"
fi

# HarmonyException specifically
if grep -q "HarmonyException\|HarmonyLib.*Exception" "$LOG_FILE" 2>/dev/null; then
    HEXC=$(grep "HarmonyException\|HarmonyLib.*Exception" "$LOG_FILE" | head -5)
    result "FAIL" "Harmony exception" "$(echo "$HEXC" | head -1)"
else
    result "PASS" "No Harmony exceptions" ""
fi

# MelonLoader-level errors
if grep -q "\[Error\]" "$LOG_FILE" 2>/dev/null; then
    ML_ERRORS=$(grep "\[Error\]" "$LOG_FILE" | head -5)
    ML_ERR_COUNT=$(grep -c "\[Error\]" "$LOG_FILE" 2>/dev/null || echo 0)
    result "FAIL" "MelonLoader errors" "${ML_ERR_COUNT} [Error] entries"
    echo "$ML_ERRORS"
else
    result "PASS" "No MelonLoader errors" ""
fi

# ===================================================================
# PHASE 6: Screenshot
# ===================================================================
echo ""
echo "--- Phase 6: Screenshot ---"

# Wait a bit for rendering to settle
sleep 5

SCREENSHOT_FILE="$SCREENSHOT_DIR/test_${TIMESTAMP}.png"
if command -v import >/dev/null 2>&1; then
    if DISPLAY="${HEADLESS_DISPLAY}" import -window root "$SCREENSHOT_FILE" 2>/dev/null; then
        FILESIZE=$(stat -c %s "$SCREENSHOT_FILE" 2>/dev/null || echo 0)
        if [[ "$FILESIZE" -gt 1000 ]]; then
            result "PASS" "Screenshot" "$SCREENSHOT_FILE (${FILESIZE} bytes)"
        else
            result "FAIL" "Screenshot" "file too small (${FILESIZE} bytes) — likely blank"
        fi
    else
        result "FAIL" "Screenshot" "import command failed"
    fi
else
    result "SKIP" "Screenshot" "imagemagick 'import' not installed"
fi

# ===================================================================
# PHASE 7: Summary
# ===================================================================
echo ""
echo "==========================================="
echo "  Test Results: $PASS_COUNT PASS, $FAIL_COUNT FAIL, $SKIP_COUNT SKIP"
echo "  Full results: $RESULT_FILE"
if [[ -f "$SCREENSHOT_FILE" ]]; then
    echo "  Screenshot:   $SCREENSHOT_FILE"
fi
echo "==========================================="

# Save summary
{
    echo ""
    echo "=== SUMMARY ==="
    echo "PASS: $PASS_COUNT"
    echo "FAIL: $FAIL_COUNT"
    echo "SKIP: $SKIP_COUNT"
    echo "Timestamp: $TIMESTAMP"
} >> "$RESULT_FILE"

# Exit code: fail if any FAIL results
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
else
    exit 0
fi
