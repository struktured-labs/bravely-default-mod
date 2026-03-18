# Bravely Default Mod Toolkit

Comprehensive modding toolkit for **Bravely Default** — covering both the 3DS original (ROM patching) and the **Flying Fairy HD** Steam remaster (runtime hooks).

## BDFFHD — BravelyMod (Steam Remaster)

A MelonLoader mod for Bravely Default: Flying Fairy HD with 18 native hooks, a web config UI, and custom music support. Works on Linux (Proton) and Windows.

### Features

| Feature | Description |
|---------|-------------|
| **EXP/JP/Gold Multiplier** | Configurable multipliers (default 10x/1000x/100x) |
| **Damage Cap Removal** | Raise cap from 9,999 to 999,999 |
| **BP System Overhaul** | BP limit 9, +2 BP/turn, brave from any submenu with sound+aura |
| **Battle Speed** | Configurable multiplier on top of in-game speed (default 4x) |
| **Monster/Boss Scaling** | Per-stat multipliers for HP, ATK, DEF, MATK, MDEF, SPD, rewards — separate for monsters and bosses |
| **Colony Speed** | Accelerate Norende fence/plant build times (default 10x) |
| **Walk Speed** | Skip Trotter built-in — configurable dash multiplier |
| **Scene Skip** | Force scene skip always available |
| **Support Cost** | Override support ability equip cost (default 1 slot) |
| **Buff Limit Removal** | Remove buff stack limits |
| **Custom Battle Music** | Replace any BGM cue with custom HCA audio files |
| **Web Config UI** | Live settings editor at localhost:8888 with dark theme |

### Requirements

- **Steam app ID:** 2833580
- **MelonLoader** v0.7.2+ (auto-generates IL2CPP proxy assemblies)
- **Steam launch options:** `WINEDLLOVERRIDES="version=n,b" %command%` (Linux/Proton)

### Build & Deploy

```bash
dotnet build BravelyMod/   # builds and auto-deploys to game Mods/ folder
```

### Configuration

All settings persist to `UserData/MelonPreferences.cfg` and can be edited live via the web UI at `http://localhost:8888`.

Pages: Dashboard, AutoBattle Editor, Music Overrides, Settings, Enemy Scaling, Mod Status.

### Architecture

The mod uses **native hooks** via `NativeHook<T>` with pinned delegates and unsafe pointers — Harmony patches don't intercept on Unity 6 IL2CPP. Each feature is a self-contained patch in `BravelyMod/Patches/`:

```
BravelyMod/
├── Core.cs                          # MelonMod entry, config, patch registration
├── Patches/
│   ├── NativeBPPatch.cs             # BP limit + VirtualProtect memory patches
│   ├── NativeBraveSubmenuPatch.cs   # Brave from any menu depth with sound
│   ├── NativeBattleSpeedPatch.cs    # Battle speed multiplier
│   ├── NativeMonsterScalingPatch.cs # Per-stat monster/boss scaling
│   ├── NativeColonyPatch.cs         # Colony build speed (5 hooks)
│   ├── NativeDamageCapPatch.cs      # Damage cap override
│   ├── NativeMusicPatch.cs          # Custom HCA music via CriAtomExPlayer
│   ├── NativeResultDisplayPatch.cs  # EXP/JP/Gold multiplication
│   └── ...                          # 18 native patches total
├── AutoBattle/
│   ├── RuleEngine.cs                # DSL engine for autobattle rules
│   └── ProfileConfig.cs             # YAML config + DSL parser
└── WebConfig/
    └── ConfigServer.cs              # Web UI on localhost:8888
```

---

## Bravely Default 3DS — ROM Patching

Automated patch generation for the original 3DS game, including the 999k damage limit mod and crowd data editing.

### Features

- **999k Damage Limit Patch**: Increases the damage cap from 9,999 to 999,999
- **IPS Patch Generation**: Creates distributable IPS patches from ROM modifications
- **Crowd Data Editor**: Extract and modify game data via spreadsheets
- **Automated Build Pipeline**: Simple make commands to generate patches
- **Docker Support**: Containerized Ghidra for reproducible builds

### Quick Start

#### Prerequisites

- A legally obtained Bravely Default CIA file
- [Pixi](https://prefix.dev/docs/pixi/overview) (recommended), Conda/Micromamba, or Docker

#### Setup

```bash
git clone git@github.com:struktured-labs/bravely-default-mod.git
cd bravely-default-mod
make setup
make pixi-install
```

Place your CIA file in `cias/`, then:

```bash
make patch-workflow cia_file=cias/bravely-default.cia
```

This extracts the CIA, applies Ghidra patches, and generates `build/patches/bd_999k_limit.ips`.

#### Apply an IPS Patch

```bash
make apply-patch
# Or manually:
python3 scripts/apply_ips_patch.py --patch build/patches/bd_999k_limit.ips --input path/to/code.bin --backup
```

### Crowd Data Editing

```bash
make crowd-unpack    # Extract to spreadsheets
# Edit build/crowd-dev-unpacked/
make crowd-pack      # Pack back
```

### Ghidra Scripts

- `ghidra_scripts/999k-limit-patch.py` — Damage cap patch
- `ghidra_scripts/find_empty_addresses.py` — Find empty memory regions
- `ghidra_scripts/import_il2cpp_labels.py` — Import IL2CPP labels into Ghidra

---

## Python Toolkit — Arcanist

The `arcanist` package provides CLI tools for game data:

```bash
uv run btbf info <file.btb2>     # Inspect BTBF container
uv run btbf dump <file.btb2>     # Decompress and dump
uv run btbf dump-all <directory>  # Batch dump
```

BTBF files (`.btb2`, `.tbl2`) use Brotli compression. The toolkit handles decompression and table parsing.

---

## Project Structure

```
.
├── BravelyMod/         # BDFFHD MelonLoader mod (C#, .NET 6)
├── arcanist/           # Python tools for ROM/data modification
│   ├── btbf/          # BTBF parser + crypto
│   └── patches/       # 3DS code patches
├── ghidra_scripts/     # Ghidra headless scripts
├── scripts/            # Build, test, and conversion scripts
├── data/               # RE notes, schemas, IL2CPP dump
└── Makefile            # 3DS build automation
```

## Credits

- Built by [struktured labs](https://github.com/struktured-labs)
- Uses MelonLoader, Ghidra, and CriWare tools
- Made with love for the Bravely Default community
