# Bravely Default (3DS) – 999,999 Damage/Heal Cap Patch v1.1.0 (max HP/MP unchanged)

By struktured labs.

## What it changes, and what it doesn't
- **Changes:** raises the battle damage cap and the healing cap from 9,999 to 999,999, and lets
  the battle damage/heal popups show six-digit numbers.
- **Does not change:** max HP and max MP. Max MP stays capped at 9,999 and max HP stays at the
  game's own cap of 99,999, exactly as in the unmodified game. v1.0.0 raised the max MP cap
  (and current MP) to 999,999; v1.1.0 no longer does.

The patch edits 15 constants in `code.bin` (9999 → 999999).

## Target
- Game: Bravely Default, North America (USA), title ID `00040000000FC500` (CTR-P-BTRE), base game
- Applies to the decompressed base `code.bin`:
  - Size: 5,709,824 bytes
  - SHA-256: `ddc6653fd94fcd509dc509ca125dc6d7997cc8573cce65d8c7018349bd1486cb`
  - SHA-1: `46610934dab8b41a8baddb2a6fc572a052589a12`
  - MD5: `7ad9a81b7d9e88d2faabed512f99285f`
- Patch: `bd_999k_limit_v1.1.0.ips`, SHA-256 `05e52b2ea9df968e5884375fa739af8fe74395e4efc589cec76539cde740c985`
- Patched `code.bin` SHA-256: `37469ce2bf297ac95656a07431cef653c845b2c4b9be41dc94624169d7448767`

No game data is included. Users need their own legally dumped copy of the game.

## Install: 3DS with Luma3DS
1. Hold SELECT while powering on to open the Luma3DS config, enable **"Enable game patching"**, and save.
2. Copy `luma/titles/00040000000FC500/code.ips` from this zip to `SD:/luma/titles/00040000000FC500/code.ips`
   (or copy `bd_999k_limit_v1.1.0.ips` there and rename it to `code.ips`). Replace any older version.
3. Launch the game. To uninstall, delete the file.

## Install: Citra / Azahar
1. Right-click the game and choose **Open Mods Location** (this opens `load/mods/00040000000FC500/`).
2. Copy `load/mods/00040000000FC500/exefs/code.ips` from this zip into the emulator's `load/mods/` folder,
   so the patch ends up at `load/mods/00040000000FC500/exefs/code.ips`.
3. Restart the game. Do not load an emulator save state made with an older version: save states
   contain the game code too, so they bring the old patch back. Load your normal in-game save instead.

## Known issues
- Only the base USA game has been tested. Updates, other regions, and Bravely Second are untested.

## Changelog
### v1.1.0
- Max MP is no longer raised: reverted the 4 MP sites (max MP getter, max MP with MP-Up modifiers,
  current MP getter, equipment-screen MP preview) back to 9,999.
- Damage cap, heal cap and damage/heal popup sites are unchanged (still 999,999).
- Removed the v1.0.0 known issues about large HP/MP readouts; they came from HP/MP values beyond
  the game's normal caps, which v1.1.0 no longer allows for MP and never changed for HP.
### v1.0.0
- First release: 19 sites raised from 9,999 to 999,999.

## Note on DateTime sites
The same 9999 constant appears at 101 other sites, which are the year 9999 in the engine's
"max date" (9999-12-31) and its range check. Those sites are deliberately left untouched,
because patching them corrupts the max date and could break timers and timestamps.

## Testing
Tested 2026-10-30 on Azahar (headless, private X display) with the decompressed USA base game,
a fresh boot with only v1.1.0 installed at `load/mods/00040000000FC500/exefs/code.ips`, and a
normal in-game save (Lv 96 party, Chapter 6). Values were pushed past the vanilla caps with
memory cheats so the caps could be seen.

- Static check (Ghidra 11.2.1 headless and Capstone on the patched `code.bin`): all 15 edits replace
  9999 literals in damage/heal code. The max HP getter, HP-bonus clamp and current HP getter
  still use 99,999. The max MP getter, max MP with MP-Up modifiers, current MP getter and
  equipment-screen MP preview still use 9,999.
- Damage over 9,999: PASS. Ringabel's Minus Strike (Dark Knight) dealt **500,000** to a Kobold.
- Healing over 9,999: PASS. An Elixir restored **600,000** HP in battle.
- MP cap: PASS. With base MP forced to 60,000 and current MP to 50,000, the field menu shows
  Tiz's MP clamped to **9,999**.
- Max HP cap: PASS. With base HP forced to 500,000 and current HP to 450,000, the field menu
  shows **99,999/99,999**. This is the vanilla cap.

## Credits
struktured labs (https://github.com/struktured-labs/bravely-default-mod).
