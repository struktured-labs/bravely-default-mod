# Bravely Second: End Layer — 999k damage-cap pipeline

Pipeline for raising the 9,999 damage/heal cap to 999,999 on the **3DS** game
*Bravely Second: End Layer* (not Bravely Default 2). Mirrors the Bravely Default
approach on branch `release/999k-3ds`: scan decompressed `code.bin` for
literal-pool `0x270F` (9999), classify by referencing function, skip DateTime
"year 9999" sites, then (after review) patch to `0x0F423F` (999,999) and export IPS.

**This branch is scan-ready scaffolding.** Do not generate patches until a dump
lands and sites are reviewed.

## Title IDs

| Region | Title ID | Preference |
|--------|----------|------------|
| USA | `000400000017BA00` | **preferred** |
| EUR | `000400000017BB00` | |
| JPN | `00040000000DC800` | |

Install later at:

- Console: `SD:/luma/titles/<TID>/code.ips`
- Azahar: `load/mods/<TID>/exefs/code.ips` (test profile `~/bd999k-test/azh` is BD; BS will need its own profile/save)

## Accepted dump inputs

Place files in `~/bs-dump/incoming/` (outside the repo; gitignored conceptually).

1. **GodMode9 decrypted `.cia` / `.3ds` / `.cxi`** of the game (recommended).
2. **Already-extracted decompressed `code.bin`** (ExeFS `.code`), via GodMode9
   NCCH "Extract .code" or by copying `exefs/.code` after mounting. Pass
   `--tid 000400000017BA00` (or EUR/JPN) because raw `code.bin` has no TID.

### Recommended: dump on 3DS with GodMode9

Sources verified against [3ds.hacks.guide — Dumping Titles and Game Cartridges](https://3ds.hacks.guide/dumping-titles-and-game-cartridges.html)
and [wiki.hacks.guide mirror](https://wiki.hacks.guide/wiki/3DS:Dump_titles_and_game_cartridges).
GodMode9 upstream README also documents cart dump / Build CIA (standard CIAs are
decrypted by default).

#### A) Cartridge → decrypted `.3ds` (simplest for carts)

1. Insert the Bravely Second cartridge.
2. Hold **START** and power on → GodMode9.
3. Open **`[C:] GAMECART`**.
4. Press **A** on `*.trim.3ds`.
5. Path variants (both appear in guides — prefer the decrypt option when present):
   - **Verified (wiki.hacks.guide):** `NCSD image options…` → **`Decrypt file (0:/gm9/out)`**.
   - **Also documented (3ds.hacks.guide):** **`Copy to 0:/gm9/out`** (trimmed dump; may still need decrypt depending on cart crypto — if ingest fails on crypto, re-dump with Decrypt).
6. Output: `0:/gm9/out/*.3ds`.

#### B) Cartridge → `.cia`

1. Same as A through selecting `*.trim.3ds`.
2. `NCSD image options…` → **`Build CIA from file`**.
3. Output: `0:/gm9/out/*.cia` (standard CIA = decrypted per GodMode9 README).

#### C) Installed eShop / digital title → `.cia`

1. Hold **START**, power on → GodMode9.
2. Press **HOME** → **Title manager**.
3. **`[A:] SD CARD`** (user titles) or NAND for system (not needed here).
4. Select **Bravely Second: End Layer**.
5. **Manage Title…** → **`Build CIA (standard)`**.
6. Output: `0:/gm9/out/*.cia`.

#### D) Optional: decompressed `.code` only (advanced)

1. From a dumped/mounted NCCH/CXI: **NCCH image options…** → **`Extract .code`**
   (writes decompressed code under `0:/gm9/out/`).
2. **Unverified edge case:** extracting `.code` directly from a *mounted cartridge*
   image has historically failed in GodMode9 ([issue #346](https://github.com/d0k3/GodMode9/issues/346));
   prefer Build CIA / Decrypt `.3ds`, then extract on PC via `ingest.sh`, or Extract
   `.code` from the installed title's `.app`.

### Copy dump to blackmage

- SD card reader, or
- **ftpd** (FTP) over LAN from the 3DS Homebrew Launcher → drop into
  `~/bs-dump/incoming/` on blackmage.

### Luma "dump code" note

**Not a clean ExeFS `code.bin` route.** Rosalina (Luma) can dump process memory
from **Process List → RAM viewer** to `/luma/dumps/memory/`. That is a runtime
memory image, not the GodMode9/ctrtool decompressed ExeFS `.code`. Prefer
GodMode9 dump + `ingest.sh`. Flagged as **not recommended / unverified for this pipeline**.

## One command after the dump lands

```bash
~/projects/bs-999k/scripts/ingest.sh ~/bs-dump/incoming/<file>
```

Examples:

```bash
# USA cart dump
~/projects/bs-999k/scripts/ingest.sh ~/bs-dump/incoming/BravelySecond.3ds

# Raw code.bin (must pass TID)
~/projects/bs-999k/scripts/ingest.sh --tid 000400000017BA00 ~/bs-dump/incoming/code.bin
```

### What ingest does

1. Detect file type (`.cia` / `.3ds` / `.cxi` / `code.bin`).
2. Extract **decompressed** `code.bin` (`ctrtool` / `3dstool`).
3. Record SHA-256 + title ID; verify TID ∈ {USA, EUR, JPN}.
4. Copy to `build/<region>/code.bin`.
5. Run **Ghidra 11.2.1 headless** scan for referenced `0x270F` literal-pool sites
   (`bin/ghidra-scan.sh` → `ghidra_scripts/scan_999k_sites.py`).
6. **STOP.** Writes `build/<region>/scan/sites_candidates.{json,md}` for review.
   **No patch, no IPS.**

Optional watcher (not enabled by default):

```bash
# foreground
~/projects/bs-999k/scripts/watch-incoming.sh

# or enable systemd --user path unit (inert until enabled)
systemctl --user enable --now bs-999k-ingest.path
```

## After sites are reviewed (future — not automated yet)

1. Classify candidates (damage/heal/UI vs DateTime year-9999 vs counters).
2. Patch selected sites `0x270F` → `0x0F423F` (adapt BD `999k-limit-patch.py`).
3. Export IPS (`bin/create_ips.py` pattern from BD).
4. Install IPS paths above.
5. **Headless Azahar test** under private Xvfb only
   (`WAYLAND_DISPLAY` / `XAUTHORITY` / `DBUS_SESSION_BUS_ADDRESS` unset,
   `QT_QPA_PLATFORM=xcb`). Needs a Bravely Second save with endgame stats or
   cheats — **do not** open GUI on Carmelo's blackmage display; do not touch OBS.

## Tooling on blackmage

| Tool | Location / version |
|------|--------------------|
| Ghidra | `~/ghidra/ghidra_11.2.1_PUBLIC` + `analyzeHeadless` |
| Java | OpenJDK 21 |
| ctrtool | `~/.local/bin/ctrtool` → v1.2.1 |
| 3dstool | `~/.local/bin/3dstool` → 1.2.6 |
| makerom | `~/.local/bin/makerom` → v0.18.5 |
| Python venv | `~/.venvs/bs999k` (capstone, pyctr) |

## Repo layout

- Branch: `bs/999k-3ds`
- Worktree: `~/projects/bs-999k`
- Dump staging: `~/bs-dump/incoming`
- Do not commit dumps / `code.bin` / `.cia` / `.3ds`
