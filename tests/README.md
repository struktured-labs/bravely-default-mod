# BravelyMod Regression Test Suite

Automated tests for BravelyMod, the MelonLoader mod for Bravely Default: Flying Fairy HD.

## Quick Start

```bash
# Tier 1 only (log-based, fastest):
./scripts/regression_test.sh

# Tier 1 + Tier 2 (runtime checks, needs gameplay):
./scripts/regression_test.sh --tier2

# Tier 1 + Tier 3 (web endpoints, game must be running):
./scripts/regression_test.sh --web

# All tiers:
./scripts/regression_test.sh --tier2 --web

# Web tests standalone:
./scripts/regression_test_web.sh

# Custom log path:
./scripts/regression_test.sh /path/to/Latest.log

# Full integration test (launches game headless, then runs hooks):
./scripts/test_mod.sh
```

## Test Tiers

### Tier 1: Hook Attachment (log-only, no gameplay needed)

These tests parse the MelonLoader log to confirm every native hook and Harmony patch
attached successfully on startup. They run instantly and require no game interaction.

**Prerequisites:** A `MelonLoader/Latest.log` from a recent game launch.

| Test | What it checks |
|------|---------------|
| T1.01 | CreateResultData or ReviseAddEXP hook attached |
| T1.02 | ResultDisplay native hook attached |
| T1.03 | SupportAbility.GetParam / SupportCost hook attached |
| T1.04 | BP memory patches applied (4/4 byte patches) |
| T1.05 | ReadyAP native hook attached |
| T1.06 | GetLimitBP native hook attached |
| T1.07 | IsBuffLimit + IsSpecialBuffLimit hooks (2 hooks) |
| T1.08 | GetBuffMax native hook attached |
| T1.09 | SpeedWalk hooks (PostInitialize + MovePosition + GetMovement) |
| T1.10 | BattleSpeed hooks (SetTimeSpeed + GetBattleSpeed) |
| T1.11 | SceneSkip EventSkipLock hook attached |
| T1.12 | Colony hooks (FenceParameter + PlantTask + DataAccessor, 5 hooks) |
| T1.13 | Music hooks (PlayBGM + SoundInterface.PlayBGM + StopBGM) |
| T1.14 | BraveSubmenu hooks (Update + _updateShortcutKeys) |
| T1.15 | DamageCap CheckDamageRange hook attached |
| T1.16 | JobSwap SetJOBID hook attached |
| T1.17 | WebConfig server started on port 8888 |
| T1.18 | Harmony patches registered (5/5) |
| T1.19 | BravelyMod initialization message present |
| T1.20 | No BravelyMod error/exception messages |
| T1.21 | No HarmonyExceptions in the full log |

Tests are marked **SKIP** (not FAIL) when the corresponding feature is disabled
in `MelonPreferences.cfg` (e.g., `EXP boost: OFF` means T1.01/T1.02 are skipped).

### Tier 2: Runtime Verification (needs gameplay log entries)

These tests check that hooks are not just attached but actually firing during
gameplay. They require a log from a session where the player entered a battle,
opened menus, or visited the colony screen.

**Prerequisites:** Enable with `--tier2`. Needs gameplay activity in the log.

| Test | What it checks |
|------|---------------|
| T2.01 | EXP multiplier active (CreateResultData shows multiplied values) |
| T2.02 | Gold multiplier active (gil values in result data) |
| T2.03 | JP multiplier active (jp values in result data) |
| T2.04 | Battle music override intercepting bgmbtl cues |
| T2.05 | BP limit override active (GetLimitBP: 3 -> 9) |
| T2.06 | Support cost reduction applied (cost -> 1) |
| T2.07 | Colony speed scaling active (FenceGetMinutes division) |
| T2.08 | Custom music playback started |
| T2.09 | Always-dash mode active |

Tests are marked **SKIP** (not FAIL) when the relevant gameplay hasn't occurred.

### Tier 3: Web Endpoint Tests (game must be running)

These test the HTTP config server that BravelyMod runs on port 8888.
The game must be running with the mod loaded.

**Prerequisites:** Enable with `--web` or run `regression_test_web.sh` standalone.

| Test | What it checks |
|------|---------------|
| T3.00 | Server reachable at localhost:8888 |
| T3.01 | GET / returns 200 with mod content |
| T3.02 | GET /settings returns 200 with form elements |
| T3.03 | GET /autobattle returns 200 |
| T3.04 | GET /autobattle/editor returns 200 |
| T3.05 | GET /music returns 200 |
| T3.06 | GET /status returns 200 |
| T3.07 | GET /api/status returns valid JSON |
| T3.08 | GET /music/files returns JSON array |
| T3.09 | GET /autobattle/editor/api returns JSON |
| T3.10 | POST /settings accepts a form submission |
| T3.11 | POST /autobattle/reload succeeds |
| T3.12 | POST /music/reload succeeds |
| T3.13 | Settings round-trip (GET -> POST -> GET verify) |
| T3.14 | POST /music/save accepts empty overrides |
| T3.15 | Invalid path returns 404 (or redirects) |
| T3.16 | POST /settings/reset (skipped by default, use --verbose) |

## Adding New Tests

### Adding a Tier 1 test (hook attachment)

1. Open `scripts/regression_test.sh`
2. Find the Tier 1 section (below `--- Tier 1: Hook Attachment Tests ---`)
3. Add a new block following the pattern:

```bash
# T1.XX: Description
if log_contains "YourHookName.*native hook"; then
    result "PASS" "T1.XX YourHookName hook" "$(log_match 'YourHookName.*native hook')"
else
    if log_contains "FeatureToggle.*OFF"; then
        result "SKIP" "T1.XX YourHookName hook" "FeatureEnabled=false"
    else
        result "FAIL" "T1.XX YourHookName hook" "not found"
    fi
fi
```

The `log_contains` helper searches `[BravelyMod]` messages for a pattern.
The `log_match` helper returns the first matching line for use as detail text.

### Adding a Tier 2 test (runtime verification)

Same pattern but placed in the `--tier2` section. Use `SKIP` instead of `FAIL`
when the relevant gameplay hasn't occurred (the test can't prove a negative).

### Adding a Tier 3 test (web endpoint)

1. Open `scripts/regression_test_web.sh`
2. Add a new block:

```bash
# T3.XX: Description
http_get "${BASE_URL}/your-endpoint"
if [[ "$HTTP_CODE" == "200" ]]; then
    result "PASS" "T3.XX GET /your-endpoint" "HTTP $HTTP_CODE"
else
    result "FAIL" "T3.XX GET /your-endpoint" "HTTP $HTTP_CODE"
fi
```

The `http_get` and `http_post` helpers set `HTTP_CODE` and `HTTP_BODY`.

### Test naming convention

- Test IDs: `T{tier}.{number}` (e.g., T1.01, T2.05, T3.12)
- Zero-padded numbers within each tier
- Include the hook/feature name in the test name for grep-ability

## Output Format

Tests produce color-coded output:
- Green `[PASS]` — test passed
- Red `[FAIL]` — test failed (regression detected)
- Yellow `[SKIP]` — test skipped (feature disabled or no data available)

The summary shows: `X passed, Y failed, Z skipped (N total)`

Exit code is 0 if no failures, 1 if any test failed.

## CI Integration

The log-based tests (Tier 1) can run in CI after capturing a log from a test launch:

```bash
# In CI pipeline:
./scripts/test_mod.sh --timeout 180        # launches game, captures log
./scripts/regression_test.sh --no-color    # parses the captured log
```

For full integration testing with web endpoints:
```bash
./scripts/test_mod.sh --keep-alive         # keep game running
./scripts/regression_test.sh --web --tier2 --no-color
```

## Relationship to test_mod.sh

`test_mod.sh` is a full integration test that launches the game headless via
Xvfb, waits for MelonLoader to initialize, and runs basic hook checks.

`regression_test.sh` is more granular and can run against any existing log file
without launching the game. It is designed to complement `test_mod.sh`:

1. `test_mod.sh` launches and captures the log
2. `regression_test.sh` runs detailed verification on that log
3. `regression_test_web.sh` tests the live web config server
