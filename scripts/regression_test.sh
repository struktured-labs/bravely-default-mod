#!/usr/bin/env bash
# =============================================================================
# BravelyMod Regression Test Suite — Log-Based Hook Verification
# =============================================================================
#
# Parses a MelonLoader log to verify all BravelyMod hooks attached correctly.
# Does NOT launch the game — use test_mod.sh or run the game first.
#
# Usage:
#   ./scripts/regression_test.sh [LOG_PATH] [--web] [--tier2] [--no-color] [--verbose]
#
# Options:
#   LOG_PATH     Path to MelonLoader Latest.log (default: auto-detected)
#   --web        Also run Tier 3 web endpoint tests (delegates to regression_test_web.sh)
#   --tier2      Also run Tier 2 runtime verification checks (requires gameplay log entries)
#   --no-color   Disable colored output
#   --verbose    Print matched log lines for each test
#
# Exit codes:
#   0  All tests passed (or skipped)
#   1  One or more tests failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# --- Defaults ---
DEFAULT_LOG="$HOME/.steam/debian-installation/steamapps/common/BDFFHD/MelonLoader/Latest.log"
LOG_FILE=""
RUN_WEB=0
RUN_TIER2=0
USE_COLOR=1
VERBOSE=0

# --- Parse args ---
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --web)      RUN_WEB=1;   shift ;;
        --tier2)    RUN_TIER2=1; shift ;;
        --no-color) USE_COLOR=0; shift ;;
        --verbose)  VERBOSE=1;   shift ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)  POSITIONAL+=("$1"); shift ;;
    esac
done

if [[ ${#POSITIONAL[@]} -gt 0 ]]; then
    LOG_FILE="${POSITIONAL[0]}"
else
    LOG_FILE="$DEFAULT_LOG"
fi

# --- Color helpers ---
if [[ "$USE_COLOR" == "1" ]] && [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN='' RED='' YELLOW='' CYAN='' BOLD='' RESET=''
fi

# --- Counters ---
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL_COUNT=0
FAILED_TESTS=()

# --- Result reporting ---
result() {
    local status="$1" test_name="$2" detail="${3:-}"
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    local color=""
    local symbol=""
    case "$status" in
        PASS) color="$GREEN"; symbol="[PASS]"; PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) color="$RED";   symbol="[FAIL]"; FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_TESTS+=("$test_name") ;;
        SKIP) color="$YELLOW"; symbol="[SKIP]"; SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac
    local msg="${color}${symbol}${RESET} ${test_name}"
    [[ -n "$detail" ]] && msg="$msg — ${detail}"
    echo -e "$msg"
}

# --- Log search helper ---
# Usage: log_contains PATTERN
# Returns 0 if PATTERN found in BravelyMod log messages, 1 otherwise
log_contains() {
    grep -q "\[BravelyMod\].*$1" "$LOG_FILE" 2>/dev/null
}

# Usage: log_match PATTERN
# Prints first matching line (for detail messages)
log_match() {
    grep "\[BravelyMod\].*$1" "$LOG_FILE" 2>/dev/null | head -1 | sed 's/.*\[BravelyMod\] //'
}

# Usage: log_count PATTERN
# Returns count of matching lines
log_count() {
    grep -c "\[BravelyMod\].*$1" "$LOG_FILE" 2>/dev/null || echo "0"
}

# --- Verbose detail helper ---
verbose_detail() {
    local pattern="$1"
    if [[ "$VERBOSE" == "1" ]]; then
        local match
        match=$(log_match "$pattern")
        [[ -n "$match" ]] && echo "         -> $match"
    fi
}

# =============================================================================
# Pre-flight check
# =============================================================================
echo -e "${BOLD}==========================================${RESET}"
echo -e "${BOLD}  BravelyMod Regression Test Suite${RESET}"
echo -e "${BOLD}  $(date)${RESET}"
echo -e "${BOLD}==========================================${RESET}"
echo ""

if [[ ! -f "$LOG_FILE" ]]; then
    echo -e "${RED}ERROR: Log file not found: $LOG_FILE${RESET}"
    echo "Run the game first or specify a log path as argument."
    exit 1
fi

LOG_AGE=$(( $(date +%s) - $(stat -c %Y "$LOG_FILE") ))
LOG_AGE_MIN=$((LOG_AGE / 60))
echo -e "Log file: ${CYAN}$LOG_FILE${RESET}"
echo -e "Log age:  ${LOG_AGE_MIN} minutes (${LOG_AGE}s)"

# Check if the log is suspiciously old
if [[ $LOG_AGE -gt 86400 ]]; then
    echo -e "${YELLOW}WARNING: Log is more than 24 hours old. Results may be stale.${RESET}"
fi

# Quick check: does the log contain any BravelyMod messages at all?
BMOD_COUNT=$(grep -c "\[BravelyMod\]" "$LOG_FILE" 2>/dev/null || echo "0")
if [[ "$BMOD_COUNT" == "0" ]]; then
    echo -e "${RED}ERROR: No [BravelyMod] messages found in log. Was the mod loaded?${RESET}"
    exit 1
fi
echo -e "BravelyMod messages: ${BMOD_COUNT}"
echo ""

# =============================================================================
# TIER 1: Hook Attachment Tests (log-only, no gameplay needed)
# =============================================================================
echo -e "${BOLD}--- Tier 1: Hook Attachment Tests ---${RESET}"
echo ""

# T1.1: EXP hooks — either ReviseAddEXP or CreateResultData
if log_contains "CreateResultData hook"; then
    result "PASS" "T1.01 CreateResultData hook" "$(log_match 'CreateResultData hook')"
elif log_contains "ReviseAddEXP"; then
    result "PASS" "T1.01 EXP hook (ReviseAddEXP)" "$(log_match 'ReviseAddEXP')"
else
    # EXP hooks may be disabled — check if ExpBoostEnabled is OFF
    if log_contains "EXP boost: OFF"; then
        result "SKIP" "T1.01 EXP hook" "ExpBoostEnabled=false"
    else
        result "FAIL" "T1.01 EXP hook" "no CreateResultData or ReviseAddEXP hook found"
    fi
fi

# T1.2: ResultDisplay hook
if log_contains "ResultDisplay.*native hook"; then
    result "PASS" "T1.02 ResultDisplay hook" "$(log_match 'ResultDisplay.*native hook')"
else
    if log_contains "EXP boost: OFF"; then
        result "SKIP" "T1.02 ResultDisplay hook" "ExpBoostEnabled=false"
    else
        result "FAIL" "T1.02 ResultDisplay hook" "not found"
    fi
fi

# T1.3: SupportAbility.GetParam
if log_contains "SupportAbility.GetParam"; then
    result "PASS" "T1.03 SupportAbility.GetParam hook" "$(log_match 'SupportAbility.GetParam')"
elif log_contains "SupportCost.*hook attached"; then
    result "PASS" "T1.03 SupportCost hook" "$(log_match 'SupportCost.*hook attached')"
else
    if log_contains "Support.*: OFF"; then
        result "SKIP" "T1.03 SupportCost hook" "SupportCostModEnabled=false"
    else
        result "FAIL" "T1.03 SupportCost hook" "not found"
    fi
fi

# T1.4: BP memory patches (4/4)
if log_contains "\[BP-Patch\] Memory patches applied: 4/4"; then
    result "PASS" "T1.04 BP memory patches" "4/4 applied"
else
    # Check partial
    local_count=$(log_count "\[BP-Patch\].*patched")
    if [[ "$local_count" -gt 0 ]]; then
        result "FAIL" "T1.04 BP memory patches" "only ${local_count}/4 applied"
    elif log_contains "BP limit.*OFF"; then
        result "SKIP" "T1.04 BP memory patches" "BpModEnabled=false"
    else
        result "FAIL" "T1.04 BP memory patches" "no BP-Patch messages"
    fi
fi

# T1.5: ReadyAP hook
if log_contains "ReadyAP.*native hook"; then
    result "PASS" "T1.05 ReadyAP hook" "$(log_match 'ReadyAP.*native hook')"
else
    if log_contains "BP limit.*OFF"; then
        result "SKIP" "T1.05 ReadyAP hook" "BpModEnabled=false"
    else
        result "FAIL" "T1.05 ReadyAP hook" "not found"
    fi
fi

# T1.6: GetLimitBP hook
if log_contains "GetLimitBP.*native hook"; then
    result "PASS" "T1.06 GetLimitBP hook" "$(log_match 'GetLimitBP.*native hook')"
else
    if log_contains "BP limit.*OFF"; then
        result "SKIP" "T1.06 GetLimitBP hook" "BpModEnabled=false"
    else
        result "FAIL" "T1.06 GetLimitBP hook" "not found"
    fi
fi

# T1.7: IsBuffLimit + IsSpecialBuffLimit hooks
BUFF_OK=0
if log_contains "IsBuffLimit.*native hook"; then
    BUFF_OK=$((BUFF_OK + 1))
fi
if log_contains "IsSpecialBuffLimit.*native hook"; then
    BUFF_OK=$((BUFF_OK + 1))
fi
if [[ $BUFF_OK -eq 2 ]]; then
    result "PASS" "T1.07 Buff limit hooks" "IsBuffLimit + IsSpecialBuffLimit attached"
elif [[ $BUFF_OK -eq 1 ]]; then
    result "FAIL" "T1.07 Buff limit hooks" "only 1/2 attached"
else
    result "FAIL" "T1.07 Buff limit hooks" "neither hook found"
fi

# T1.8: GetBuffMax hook
if log_contains "GetBuffMax.*native hook"; then
    result "PASS" "T1.08 GetBuffMax hook" "$(log_match 'GetBuffMax.*native hook')"
else
    result "FAIL" "T1.08 GetBuffMax hook" "not found"
fi

# T1.9: SpeedWalk hooks (PostInitialize + MovePosition + GetMovement)
SW_OK=0
SW_DETAIL=""
for pat in "SpeedWalk.*PostInitialize" "SpeedWalk.*GetMovement" "SpeedWalk.*MovePosition"; do
    if log_contains "$pat"; then
        SW_OK=$((SW_OK + 1))
    fi
done
if [[ $SW_OK -eq 3 ]]; then
    result "PASS" "T1.09 SpeedWalk hooks" "3/3 attached"
elif [[ $SW_OK -gt 0 ]]; then
    result "FAIL" "T1.09 SpeedWalk hooks" "${SW_OK}/3 attached"
else
    if log_contains "WalkSpeed.*OFF"; then
        result "SKIP" "T1.09 SpeedWalk hooks" "WalkSpeedModEnabled=false"
    else
        result "FAIL" "T1.09 SpeedWalk hooks" "none found"
    fi
fi

# T1.10: BattleSpeed hooks (SetTimeSpeed + GetBattleSpeed)
BS_OK=0
if log_contains "BattleSpeed.*SetTimeSpeed"; then
    BS_OK=$((BS_OK + 1))
fi
if log_contains "BattleSpeed.*GetBattleSpeed"; then
    BS_OK=$((BS_OK + 1))
fi
if [[ $BS_OK -eq 2 ]]; then
    result "PASS" "T1.10 BattleSpeed hooks" "SetTimeSpeed + GetBattleSpeed attached"
elif [[ $BS_OK -eq 1 ]]; then
    result "FAIL" "T1.10 BattleSpeed hooks" "only 1/2 attached"
else
    if log_contains "Speed.*OFF"; then
        result "SKIP" "T1.10 BattleSpeed hooks" "SpeedModEnabled=false"
    else
        result "FAIL" "T1.10 BattleSpeed hooks" "not found"
    fi
fi

# T1.11: SceneSkip EventSkipLock hook
if log_contains "SceneSkip.*EventSkipLock"; then
    result "PASS" "T1.11 SceneSkip EventSkipLock" "$(log_match 'SceneSkip.*EventSkipLock')"
else
    if log_contains "Scene skip:False"; then
        result "SKIP" "T1.11 SceneSkip hook" "ForceSceneSkip=false"
    else
        result "FAIL" "T1.11 SceneSkip hook" "EventSkipLock not found"
    fi
fi

# T1.12: Colony hooks (FenceParameter.GetMinutes + PlantTask + DataAccessor variants)
COLONY_OK=0
COLONY_EXPECTED=0
for pat in "Colony.*FenceParameter.GetMinutes" "Colony.*PlantTask.GetRemainTime" "Colony.*PlantTask.Entry" "Colony.*DataAccessor.GetPlantRemainTime" "Colony.*PlantTask.Reduce"; do
    COLONY_EXPECTED=$((COLONY_EXPECTED + 1))
    if log_contains "$pat"; then
        COLONY_OK=$((COLONY_OK + 1))
    fi
done
if [[ $COLONY_OK -eq $COLONY_EXPECTED ]]; then
    result "PASS" "T1.12 Colony hooks" "${COLONY_OK}/${COLONY_EXPECTED} attached"
elif [[ $COLONY_OK -gt 0 ]]; then
    result "FAIL" "T1.12 Colony hooks" "${COLONY_OK}/${COLONY_EXPECTED} attached (partial)"
else
    if log_contains "Colony.*OFF"; then
        result "SKIP" "T1.12 Colony hooks" "ColonyModEnabled=false"
    else
        result "FAIL" "T1.12 Colony hooks" "none found"
    fi
fi

# T1.13: Music hooks (PlayBGM + SoundInterface.PlayBGM + StopBGM)
MUSIC_OK=0
for pat in "\[Music\].*BtlSoundManager.PlayBGM native" "\[Music\].*SoundInterface.PlayBGM hook" "\[Music\].*StopBGM hook"; do
    if log_contains "$pat"; then
        MUSIC_OK=$((MUSIC_OK + 1))
    fi
done
if [[ $MUSIC_OK -eq 3 ]]; then
    result "PASS" "T1.13 Music hooks" "PlayBGM + SoundInterface.PlayBGM + StopBGM attached"
elif [[ $MUSIC_OK -gt 0 ]]; then
    result "FAIL" "T1.13 Music hooks" "${MUSIC_OK}/3 attached"
else
    if log_contains "BattleBGM: OFF"; then
        result "SKIP" "T1.13 Music hooks" "CustomBattleMusicEnabled=false"
    else
        result "FAIL" "T1.13 Music hooks" "none found"
    fi
fi

# T1.14: BraveSubmenu hooks (Update + _updateShortcutKeys)
BS_MENU_OK=0
if log_contains "BraveSubmenu.*Update hook"; then
    BS_MENU_OK=$((BS_MENU_OK + 1))
fi
if log_contains "BraveSubmenu.*_updateShortcutKeys"; then
    BS_MENU_OK=$((BS_MENU_OK + 1))
fi
if [[ $BS_MENU_OK -eq 2 ]]; then
    result "PASS" "T1.14 BraveSubmenu hooks" "Update + _updateShortcutKeys attached"
elif [[ $BS_MENU_OK -eq 1 ]]; then
    result "FAIL" "T1.14 BraveSubmenu hooks" "only 1/2 attached"
else
    result "FAIL" "T1.14 BraveSubmenu hooks" "not found"
fi

# T1.15: DamageCap hook
if log_contains "DamageCap.*native hook attached"; then
    result "PASS" "T1.15 DamageCap hook" "$(log_match 'CheckDamageRange')"
else
    if log_contains "Damage cap:OFF"; then
        result "SKIP" "T1.15 DamageCap hook" "DamageCapEnabled=false"
    else
        result "FAIL" "T1.15 DamageCap hook" "not found"
    fi
fi

# T1.16: JobSwap hook
if log_contains "\[JobSwap\].*SetJOBID hook attached"; then
    result "PASS" "T1.16 JobSwap hook" "$(log_match '\[JobSwap\].*SetJOBID hook')"
else
    result "FAIL" "T1.16 JobSwap hook" "not found"
fi

# T1.17: WebConfig server started
if log_contains "\[WebConfig\] Server started"; then
    result "PASS" "T1.17 WebConfig server" "$(log_match '\[WebConfig\] Server started')"
else
    result "FAIL" "T1.17 WebConfig server" "no server start message"
fi

# T1.18: Harmony patches registered
if log_contains "Harmony:.*registered"; then
    HARMONY_DETAIL=$(log_match "Harmony:.*registered")
    result "PASS" "T1.18 Harmony patches" "$HARMONY_DETAIL"
else
    result "FAIL" "T1.18 Harmony patches" "no Harmony registration message"
fi

# T1.19: Mod initialized successfully
if log_contains "BravelyMod v.*initialized"; then
    result "PASS" "T1.19 BravelyMod initialized" "$(log_match 'BravelyMod v.*initialized')"
else
    result "FAIL" "T1.19 BravelyMod initialized" "no initialization message"
fi

# T1.20: No errors or exceptions from BravelyMod
BMOD_ERRORS=$(grep "\[BravelyMod\]" "$LOG_FILE" 2>/dev/null | grep -iE "error|exception|failed|crash" | grep -v "DEBUG" || true)
if [[ -z "$BMOD_ERRORS" ]]; then
    result "PASS" "T1.20 No BravelyMod errors" ""
else
    ERR_COUNT=$(echo "$BMOD_ERRORS" | wc -l)
    result "FAIL" "T1.20 No BravelyMod errors" "${ERR_COUNT} error(s)"
    if [[ "$VERBOSE" == "1" ]]; then
        echo "$BMOD_ERRORS" | while read -r line; do
            echo "         -> $line"
        done
    fi
fi

# T1.21: No HarmonyExceptions
if grep -q "HarmonyException\|HarmonyLib.*Exception" "$LOG_FILE" 2>/dev/null; then
    HEXC=$(grep "HarmonyException\|HarmonyLib.*Exception" "$LOG_FILE" | head -1)
    result "FAIL" "T1.21 No Harmony exceptions" "$HEXC"
else
    result "PASS" "T1.21 No Harmony exceptions" ""
fi

# =============================================================================
# TIER 2: Runtime Verification (needs gameplay log entries)
# =============================================================================
if [[ "$RUN_TIER2" == "1" ]]; then
    echo ""
    echo -e "${BOLD}--- Tier 2: Runtime Verification ---${RESET}"
    echo ""

    # T2.1: EXP multiplier active in CreateResultData
    if log_contains "\[Result\] CreateResultData.*exp"; then
        RESULT_LINE=$(log_match "\[Result\] CreateResultData")
        result "PASS" "T2.01 EXP multiplier" "$RESULT_LINE"
    else
        result "SKIP" "T2.01 EXP multiplier" "no battle result logged (need a battle)"
    fi

    # T2.2: Gold multiplier active
    if log_contains "\[Result\] CreateResultData.*gil"; then
        RESULT_LINE=$(log_match "\[Result\] CreateResultData.*gil")
        result "PASS" "T2.02 Gold multiplier" "$RESULT_LINE"
    else
        result "SKIP" "T2.02 Gold multiplier" "no battle result with gil"
    fi

    # T2.3: JP multiplier active
    if log_contains "\[Result\] CreateResultData.*jp"; then
        RESULT_LINE=$(log_match "\[Result\] CreateResultData.*jp")
        result "PASS" "T2.03 JP multiplier" "$RESULT_LINE"
    else
        result "SKIP" "T2.03 JP multiplier" "no battle result with jp"
    fi

    # T2.4: Music override intercepting in battle
    if log_contains "\[Music\] Intercepting.*bgmbtl"; then
        result "PASS" "T2.04 Battle music override" "$(log_match '\[Music\] Intercepting.*bgmbtl')"
    else
        result "SKIP" "T2.04 Battle music override" "no battle music intercept (need a battle)"
    fi

    # T2.5: BP accumulation past 3
    if log_contains "\[BP\] GetLimitBP: 3 ->"; then
        result "PASS" "T2.05 BP limit override" "$(log_match '\[BP\] GetLimitBP')"
    else
        result "SKIP" "T2.05 BP limit override" "no GetLimitBP runtime log (need a battle)"
    fi

    # T2.6: Support cost reduction
    if log_contains "\[SupportCost\].*->"; then
        SUPPORT_LINE=$(log_match "\[SupportCost\]")
        result "PASS" "T2.06 Support cost override" "$SUPPORT_LINE"
    else
        result "SKIP" "T2.06 Support cost override" "no SupportCost runtime log"
    fi

    # T2.7: Colony speed scaling
    if log_contains "\[Colony\].*FenceGetMinutes:.*->"; then
        COLONY_LINE=$(log_match "\[Colony\].*FenceGetMinutes")
        result "PASS" "T2.07 Colony speed scaling" "$COLONY_LINE"
    else
        result "SKIP" "T2.07 Colony speed scaling" "no colony runtime log"
    fi

    # T2.8: Music custom playback started
    if log_contains "\[Music\] Custom playback started"; then
        COUNT=$(log_count "\[Music\] Custom playback started")
        result "PASS" "T2.08 Custom music playback" "${COUNT} playback(s) started"
    else
        result "SKIP" "T2.08 Custom music playback" "no custom playback started"
    fi

    # T2.9: SpeedWalk always-dash
    if log_contains "SpeedWalk.*always-dash ON"; then
        result "PASS" "T2.09 Always-dash active" ""
    else
        result "SKIP" "T2.09 Always-dash active" "no always-dash message"
    fi
fi

# =============================================================================
# TIER 3: Web endpoint tests (delegated)
# =============================================================================
if [[ "$RUN_WEB" == "1" ]]; then
    echo ""
    echo -e "${BOLD}--- Tier 3: Web Endpoint Tests ---${RESET}"
    echo ""

    WEB_SCRIPT="$SCRIPT_DIR/regression_test_web.sh"
    if [[ -x "$WEB_SCRIPT" ]]; then
        # Run web tests and capture results
        set +e
        WEB_OUTPUT=$("$WEB_SCRIPT" --counts-only 2>&1)
        WEB_EXIT=$?
        set -e

        # Parse counts from web test output
        while IFS= read -r line; do
            echo -e "$line"
            if [[ "$line" =~ \[PASS\] ]]; then
                PASS_COUNT=$((PASS_COUNT + 1))
                TOTAL_COUNT=$((TOTAL_COUNT + 1))
            elif [[ "$line" =~ \[FAIL\] ]]; then
                FAIL_COUNT=$((FAIL_COUNT + 1))
                TOTAL_COUNT=$((TOTAL_COUNT + 1))
                test_name=$(echo "$line" | sed 's/.*\[FAIL\] //' | sed 's/ —.*//')
                FAILED_TESTS+=("$test_name")
            elif [[ "$line" =~ \[SKIP\] ]]; then
                SKIP_COUNT=$((SKIP_COUNT + 1))
                TOTAL_COUNT=$((TOTAL_COUNT + 1))
            fi
        done <<< "$WEB_OUTPUT"
    else
        result "SKIP" "T3.xx Web tests" "regression_test_web.sh not found or not executable"
    fi
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${BOLD}==========================================${RESET}"
if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}  ALL TESTS PASSED${RESET}"
else
    echo -e "${RED}${BOLD}  SOME TESTS FAILED${RESET}"
fi
echo -e "  ${GREEN}${PASS_COUNT}${RESET} passed, ${RED}${FAIL_COUNT}${RESET} failed, ${YELLOW}${SKIP_COUNT}${RESET} skipped (${TOTAL_COUNT} total)"

if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}  Failed tests:${RESET}"
    for t in "${FAILED_TESTS[@]}"; do
        echo -e "    ${RED}- $t${RESET}"
    done
fi

echo -e "${BOLD}==========================================${RESET}"

# Exit with failure if any test failed
if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
else
    exit 0
fi
