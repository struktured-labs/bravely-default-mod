# Bravely Default (3DS) – 999,999 Damage/Heal Cap Patch v1.0.0

By struktured labs.

## What it does
This patch raises Bravely Default's hard damage and healing cap from 9,999 to 999,999.
It covers physical damage, HP healing, and (because the cap is shared) MP-based attacks
and heals. It changes 19 gameplay/UI constants in `code.bin` from 9999 to 999999.
The battle damage and heal popups display six-digit values.

## Target
- Game: Bravely Default, North America (USA), title ID `00040000000FC500` (CTR-P-BTRE), base game
- Applies to the decompressed base `code.bin`:
  - Size: 5,709,824 bytes
  - SHA-256: `ddc6653fd94fcd509dc509ca125dc6d7997cc8573cce65d8c7018349bd1486cb`
  - SHA-1: `46610934dab8b41a8baddb2a6fc572a052589a12`
  - MD5: `7ad9a81b7d9e88d2faabed512f99285f`
- Patch: `bd_999k_limit_minimal.ips`, SHA-256 `b014be42fc85ddfb44c739ce7147f68a97320c7cee86d3a44e2211f7cf1cbbd9`

No game data is included. Users need their own legally dumped copy of the game.

## Install: 3DS with Luma3DS
1. Hold SELECT while powering on to open the Luma3DS config, enable **"Enable game patching"**, and save.
2. Copy `bd_999k_limit_minimal.ips` to `SD:/luma/titles/00040000000FC500/code.ips`, renaming it to `code.ips`.
3. Launch the game. To uninstall, delete the file.

## Install: Citra / Azahar
1. Right-click the game and choose **Open Mods Location** (this opens `load/mods/00040000000FC500/`).
2. Place the patch at `load/mods/00040000000FC500/exefs/code.ips` (create `exefs` if needed, rename to `code.ips`).
3. Restart the game.

## Known issues
- The HP readout in menus caps at 99,999, even when actual HP is higher.
- Large HP values are truncated in the battle HUD (for example, 500,000 shows as "0000").
- 5-digit MP values are cut off in the menu (for example, "8888/").
- Only the base USA game has been tested. Updates, other regions, and Bravely Second are untested.

These are display-only limits. The underlying values and the damage and heal popups are correct.

## Note on DateTime sites
The same 9999 constant appears at 101 other sites, which are the year 9999 in the engine's
"max date" (9999-12-31) and its range check. Those sites are deliberately left untouched,
because patching them corrupts the max date (it wraps to about year 575) and could break timers
and timestamps (SP sleep timer, StreetPass/SpotPass, Norende).

## Testing
The patch was tested on Azahar with a chapter 5 save. HP was raised with memory cheats
to reach values that big. Minus Strike dealt 499,000 damage and an Elixir healed 500,000 HP.
Unpatched, the same setup showed 9,999 for both.

## Credits
struktured labs (https://github.com/struktured-labs/bravely-default-mod).
