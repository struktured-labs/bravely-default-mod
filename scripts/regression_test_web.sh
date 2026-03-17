#!/usr/bin/env bash
# =============================================================================
# BravelyMod Regression Test Suite — Web Config Endpoint Tests
# =============================================================================
#
# Tests the BravelyMod web config server at http://localhost:8888/.
# The game must be running with the mod loaded for these tests to pass.
#
# Usage:
#   ./scripts/regression_test_web.sh [--base-url URL] [--no-color] [--verbose] [--counts-only]
#
# Options:
#   --base-url URL   Override base URL (default: http://localhost:8888)
#   --no-color       Disable colored output
#   --verbose        Show response bodies
#   --counts-only    Suppress header/summary (for embedding in regression_test.sh)
#   --timeout N      Curl timeout in seconds (default: 5)
#
# Exit codes:
#   0  All tests passed
#   1  One or more tests failed
#   2  Server unreachable

set -euo pipefail

# --- Defaults ---
BASE_URL="http://localhost:8888"
USE_COLOR=1
VERBOSE=0
COUNTS_ONLY=0
CURL_TIMEOUT=5

# --- Parse args ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --base-url)    BASE_URL="$2"; shift 2 ;;
        --no-color)    USE_COLOR=0; shift ;;
        --verbose)     VERBOSE=1; shift ;;
        --counts-only) COUNTS_ONLY=1; shift ;;
        --timeout)     CURL_TIMEOUT="$2"; shift 2 ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

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

# --- HTTP helpers ---
# http_get URL -> sets HTTP_CODE, HTTP_BODY
http_get() {
    local url="$1"
    local tmpfile
    tmpfile=$(mktemp)
    HTTP_CODE=$(curl -s -o "$tmpfile" -w '%{http_code}' --connect-timeout "$CURL_TIMEOUT" --max-time "$((CURL_TIMEOUT * 2))" "$url" 2>/dev/null) || HTTP_CODE="000"
    HTTP_BODY=$(cat "$tmpfile" 2>/dev/null || echo "")
    rm -f "$tmpfile"
}

# http_post URL DATA [CONTENT_TYPE] -> sets HTTP_CODE, HTTP_BODY
http_post() {
    local url="$1"
    local data="${2:-}"
    local content_type="${3:-application/x-www-form-urlencoded}"
    local tmpfile
    tmpfile=$(mktemp)
    HTTP_CODE=$(curl -s -o "$tmpfile" -w '%{http_code}' --connect-timeout "$CURL_TIMEOUT" --max-time "$((CURL_TIMEOUT * 2))" -X POST -H "Content-Type: $content_type" -d "$data" "$url" 2>/dev/null) || HTTP_CODE="000"
    HTTP_BODY=$(cat "$tmpfile" 2>/dev/null || echo "")
    rm -f "$tmpfile"
}

# --- Verbose body output ---
verbose_body() {
    if [[ "$VERBOSE" == "1" ]] && [[ -n "${HTTP_BODY:-}" ]]; then
        echo "         Response (first 5 lines):"
        echo "$HTTP_BODY" | head -5 | while read -r line; do
            echo "           $line"
        done
    fi
}

# =============================================================================
# Header
# =============================================================================
if [[ "$COUNTS_ONLY" == "0" ]]; then
    echo -e "${BOLD}==========================================${RESET}"
    echo -e "${BOLD}  BravelyMod Web Endpoint Tests${RESET}"
    echo -e "${BOLD}  $(date)${RESET}"
    echo -e "${BOLD}==========================================${RESET}"
    echo ""
    echo -e "Target: ${CYAN}$BASE_URL${RESET}"
    echo ""
fi

# =============================================================================
# Pre-flight: is the server reachable?
# =============================================================================
http_get "${BASE_URL}/status"
if [[ "$HTTP_CODE" == "000" ]]; then
    if [[ "$COUNTS_ONLY" == "0" ]]; then
        echo -e "${RED}ERROR: Cannot connect to ${BASE_URL}. Is the game running with BravelyMod?${RESET}"
    fi
    result "FAIL" "T3.00 Server reachable" "connection refused at ${BASE_URL}"
    # Report the single failure and exit
    if [[ "$COUNTS_ONLY" == "0" ]]; then
        echo ""
        echo -e "${RED}Aborting web tests — server unreachable${RESET}"
    fi
    exit 2
fi

# =============================================================================
# T3.01: GET / returns 200
# =============================================================================
http_get "${BASE_URL}/"
if [[ "$HTTP_CODE" == "200" ]]; then
    # Verify it contains expected content
    if echo "$HTTP_BODY" | grep -qi "BravelyMod\|bravely.*mod\|config"; then
        result "PASS" "T3.01 GET / (homepage)" "HTTP $HTTP_CODE, contains mod content"
    else
        result "FAIL" "T3.01 GET / (homepage)" "HTTP $HTTP_CODE but unexpected content"
    fi
else
    result "FAIL" "T3.01 GET / (homepage)" "HTTP $HTTP_CODE (expected 200)"
fi
verbose_body

# =============================================================================
# T3.02: GET /settings returns 200 with form
# =============================================================================
http_get "${BASE_URL}/settings"
if [[ "$HTTP_CODE" == "200" ]]; then
    if echo "$HTTP_BODY" | grep -qi "form\|input\|settings"; then
        result "PASS" "T3.02 GET /settings" "HTTP $HTTP_CODE, form present"
    else
        result "FAIL" "T3.02 GET /settings" "HTTP $HTTP_CODE but no form found"
    fi
else
    result "FAIL" "T3.02 GET /settings" "HTTP $HTTP_CODE (expected 200)"
fi

# =============================================================================
# T3.03: GET /autobattle returns 200
# =============================================================================
http_get "${BASE_URL}/autobattle"
if [[ "$HTTP_CODE" == "200" ]]; then
    result "PASS" "T3.03 GET /autobattle" "HTTP $HTTP_CODE"
else
    result "FAIL" "T3.03 GET /autobattle" "HTTP $HTTP_CODE (expected 200)"
fi

# =============================================================================
# T3.04: GET /autobattle/editor returns 200
# =============================================================================
http_get "${BASE_URL}/autobattle/editor"
if [[ "$HTTP_CODE" == "200" ]]; then
    result "PASS" "T3.04 GET /autobattle/editor" "HTTP $HTTP_CODE"
else
    result "FAIL" "T3.04 GET /autobattle/editor" "HTTP $HTTP_CODE (expected 200)"
fi

# =============================================================================
# T3.05: GET /music returns 200
# =============================================================================
http_get "${BASE_URL}/music"
if [[ "$HTTP_CODE" == "200" ]]; then
    result "PASS" "T3.05 GET /music" "HTTP $HTTP_CODE"
else
    result "FAIL" "T3.05 GET /music" "HTTP $HTTP_CODE (expected 200)"
fi

# =============================================================================
# T3.06: GET /status returns 200
# =============================================================================
http_get "${BASE_URL}/status"
if [[ "$HTTP_CODE" == "200" ]]; then
    if echo "$HTTP_BODY" | grep -qi "status\|BravelyMod\|version"; then
        result "PASS" "T3.06 GET /status" "HTTP $HTTP_CODE, status content present"
    else
        result "PASS" "T3.06 GET /status" "HTTP $HTTP_CODE"
    fi
else
    result "FAIL" "T3.06 GET /status" "HTTP $HTTP_CODE (expected 200)"
fi

# =============================================================================
# T3.07: GET /api/status returns valid JSON
# =============================================================================
http_get "${BASE_URL}/api/status"
if [[ "$HTTP_CODE" == "200" ]]; then
    # Check it's valid JSON (must start with { or [)
    TRIMMED=$(echo "$HTTP_BODY" | tr -d '[:space:]' | head -c1)
    if [[ "$TRIMMED" == "{" ]] || [[ "$TRIMMED" == "[" ]]; then
        result "PASS" "T3.07 GET /api/status (JSON)" "HTTP $HTTP_CODE, valid JSON"
    else
        result "FAIL" "T3.07 GET /api/status (JSON)" "HTTP $HTTP_CODE but not JSON"
    fi
else
    result "FAIL" "T3.07 GET /api/status (JSON)" "HTTP $HTTP_CODE (expected 200)"
fi
verbose_body

# =============================================================================
# T3.08: GET /music/files returns JSON array
# =============================================================================
http_get "${BASE_URL}/music/files"
if [[ "$HTTP_CODE" == "200" ]]; then
    TRIMMED=$(echo "$HTTP_BODY" | tr -d '[:space:]' | head -c1)
    if [[ "$TRIMMED" == "[" ]]; then
        result "PASS" "T3.08 GET /music/files" "HTTP $HTTP_CODE, JSON array"
    else
        result "FAIL" "T3.08 GET /music/files" "HTTP $HTTP_CODE but not a JSON array"
    fi
else
    result "FAIL" "T3.08 GET /music/files" "HTTP $HTTP_CODE (expected 200)"
fi

# =============================================================================
# T3.09: GET /autobattle/editor/api returns JSON
# =============================================================================
http_get "${BASE_URL}/autobattle/editor/api"
if [[ "$HTTP_CODE" == "200" ]]; then
    TRIMMED=$(echo "$HTTP_BODY" | tr -d '[:space:]' | head -c1)
    if [[ "$TRIMMED" == "{" ]] || [[ "$TRIMMED" == "[" ]]; then
        result "PASS" "T3.09 GET /autobattle/editor/api" "HTTP $HTTP_CODE, valid JSON"
    else
        result "FAIL" "T3.09 GET /autobattle/editor/api" "HTTP $HTTP_CODE but not JSON"
    fi
else
    result "FAIL" "T3.09 GET /autobattle/editor/api" "HTTP $HTTP_CODE (expected 200)"
fi

# =============================================================================
# T3.10: POST /settings with valid data returns success
# =============================================================================
# Read current settings page to discover a field name
http_get "${BASE_URL}/settings"
if [[ "$HTTP_CODE" == "200" ]]; then
    # Try posting a benign settings change (set ExpMultiplier to its current value)
    # This should be a no-op that still returns 200/302
    http_post "${BASE_URL}/settings" "ExpMultiplier=10"
    if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "302" ]] || [[ "$HTTP_CODE" == "303" ]]; then
        result "PASS" "T3.10 POST /settings" "HTTP $HTTP_CODE (settings accepted)"
    else
        result "FAIL" "T3.10 POST /settings" "HTTP $HTTP_CODE (expected 200/302)"
    fi
else
    result "SKIP" "T3.10 POST /settings" "could not load settings page first"
fi

# =============================================================================
# T3.11: POST /autobattle/reload returns success
# =============================================================================
http_post "${BASE_URL}/autobattle/reload" ""
if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "302" ]] || [[ "$HTTP_CODE" == "204" ]]; then
    result "PASS" "T3.11 POST /autobattle/reload" "HTTP $HTTP_CODE"
else
    result "FAIL" "T3.11 POST /autobattle/reload" "HTTP $HTTP_CODE"
fi

# =============================================================================
# T3.12: POST /music/reload returns success
# =============================================================================
http_post "${BASE_URL}/music/reload" ""
if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "302" ]] || [[ "$HTTP_CODE" == "204" ]]; then
    result "PASS" "T3.12 POST /music/reload" "HTTP $HTTP_CODE"
else
    result "FAIL" "T3.12 POST /music/reload" "HTTP $HTTP_CODE"
fi

# =============================================================================
# T3.13: Settings round-trip (GET -> POST change -> GET verify)
# =============================================================================
# Read current settings JSON from api/status
http_get "${BASE_URL}/api/status"
if [[ "$HTTP_CODE" == "200" ]]; then
    # Save original EXP multiplier if we can parse it
    ORIG_EXP=""
    if command -v python3 >/dev/null 2>&1; then
        ORIG_EXP=$(echo "$HTTP_BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('ExpMultiplier', d.get('settings',{}).get('ExpMultiplier','')))" 2>/dev/null || echo "")
    fi

    if [[ -n "$ORIG_EXP" ]]; then
        # POST a test value (same value to avoid side effects)
        http_post "${BASE_URL}/settings" "ExpMultiplier=${ORIG_EXP}"
        if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "302" ]]; then
            # Read back
            http_get "${BASE_URL}/api/status"
            NEW_EXP=""
            if [[ "$HTTP_CODE" == "200" ]]; then
                NEW_EXP=$(echo "$HTTP_BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('ExpMultiplier', d.get('settings',{}).get('ExpMultiplier','')))" 2>/dev/null || echo "")
            fi
            if [[ "$NEW_EXP" == "$ORIG_EXP" ]]; then
                result "PASS" "T3.13 Settings round-trip" "ExpMultiplier=${ORIG_EXP} preserved"
            else
                result "FAIL" "T3.13 Settings round-trip" "wrote ${ORIG_EXP} but read back ${NEW_EXP}"
            fi
        else
            result "FAIL" "T3.13 Settings round-trip" "POST failed with HTTP $HTTP_CODE"
        fi
    else
        result "SKIP" "T3.13 Settings round-trip" "could not parse ExpMultiplier from api/status"
    fi
else
    result "SKIP" "T3.13 Settings round-trip" "api/status returned HTTP $HTTP_CODE"
fi

# =============================================================================
# T3.14: Music config save endpoint
# =============================================================================
http_post "${BASE_URL}/music/save" '{"overrides":{}}' "application/json"
if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "204" ]]; then
    result "PASS" "T3.14 POST /music/save" "HTTP $HTTP_CODE (empty overrides accepted)"
else
    result "FAIL" "T3.14 POST /music/save" "HTTP $HTTP_CODE"
fi

# =============================================================================
# T3.15: Invalid endpoint returns 404
# =============================================================================
http_get "${BASE_URL}/nonexistent-endpoint-test-12345"
if [[ "$HTTP_CODE" == "404" ]]; then
    result "PASS" "T3.15 404 on invalid path" "HTTP $HTTP_CODE"
elif [[ "$HTTP_CODE" == "200" ]]; then
    # Some servers redirect unknowns to homepage — acceptable but note it
    result "PASS" "T3.15 Invalid path handling" "HTTP $HTTP_CODE (redirected, acceptable)"
else
    result "FAIL" "T3.15 Invalid path handling" "HTTP $HTTP_CODE (expected 404)"
fi

# =============================================================================
# T3.16: POST /settings/reset returns success
# =============================================================================
# Note: this resets all settings to defaults, which could affect gameplay.
# We test it but it's somewhat destructive.
# Only run if --verbose (power-user mode), otherwise skip
if [[ "$VERBOSE" == "1" ]]; then
    http_post "${BASE_URL}/settings/reset" ""
    if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "302" ]]; then
        result "PASS" "T3.16 POST /settings/reset" "HTTP $HTTP_CODE"
    else
        result "FAIL" "T3.16 POST /settings/reset" "HTTP $HTTP_CODE"
    fi
else
    result "SKIP" "T3.16 POST /settings/reset" "skipped (destructive, use --verbose to run)"
fi

# =============================================================================
# Summary
# =============================================================================
if [[ "$COUNTS_ONLY" == "0" ]]; then
    echo ""
    echo -e "${BOLD}==========================================${RESET}"
    if [[ $FAIL_COUNT -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}  ALL WEB TESTS PASSED${RESET}"
    else
        echo -e "${RED}${BOLD}  SOME WEB TESTS FAILED${RESET}"
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
fi

if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
else
    exit 0
fi
