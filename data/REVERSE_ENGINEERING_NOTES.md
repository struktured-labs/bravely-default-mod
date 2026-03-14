# Bravely Default: Flying Fairy HD — Reverse Engineering Notes

## Game Info
- **Steam Title:** BDFFHD (Bravely Default: Flying Fairy HD)
- **Install:** `~/.steam/debian-installation/steamapps/common/BDFFHD/`
- **Engine:** Unity (IL2CPP compiled), PE64 x86-64
- **Binary:** `GameAssembly.dll` (361MB)
- **IL2CPP Metadata:** `BDFFHD_Data/il2cpp_data/Metadata/global-metadata.dat`

## Data Format: BTBF

All game data tables use a proprietary **BTBF** binary container format.

### Header (0x30 bytes, little-endian)
| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 | Magic: `BTBF` |
| 0x04 | 4 | Total file size |
| 0x08 | 4 | Data section offset (always 0x30) |
| 0x0C | 4 | Data section size (`row_size * num_rows`) |
| 0x10 | 4 | Label table offset |
| 0x14 | 4 | Label table size |
| 0x18 | 4 | String data offset |
| 0x1C | 4 | String data size |
| 0x20 | 4 | Row size (bytes per record) |
| 0x24 | 4 | Number of rows |

- Data rows are fixed-size, starting at offset 0x30
- Label table contains null-separated ASCII identifiers (model names, animation names, etc.)
- String data contains null-terminated **UTF-16LE** text (names, descriptions)
- String fields in rows are byte offsets into the string data section

### File Extensions
| Extension | Count | Content |
|-----------|-------|---------|
| `.btb` | 237 | Primary data tables |
| `.spb` | 87 | Shop/price tables |
| `.txb` | 75 | Text/dialog tables |
| `.btb2` | 42 | Encrypted copies (magic `00 01 53 53`) |
| `.trb` | 36 | Treasure chest tables |
| `.mtb` | 19 | Menu/graphic text tables |
| `.tbl` | 14 | Miscellaneous tables |
| `.subtitles` | 12 | Cutscene subtitle timing |

### Localization
- `Common/` = Japanese base data
- `Common_en/` = English overrides (same BTBF format, often larger)
- Other locales: `Common_cn/`, `Common_de/`, `Common_es/`, `Common_fr/`, `Common_it/`, `Common_kr/`, `Common_tw/`
- Game loads locale-specific first, falls back to `Common/`

## Key Data Tables

### `Common_en/Paramater/`
| File | Rows | Description |
|------|------|-------------|
| `ItemTable.btb` | 597 | All items and equipment |
| `CommandAbility.btb` | ? | Job command abilities |
| `SupportAbility.btb` | 166 | Passive support abilities |
| `JobTable.btb` | ? | Job definitions (24 jobs) |
| `JobTable00-23.btb` | 1 each | Per-job stat tables |
| `PcTable.btb` | ? | Player character data |
| `PcLevelTable001-004.btb` | ? | Level-up stat curves |
| `MapTable.btb` | ? | Map definitions |
| `SpecialTable.btb` | ? | Special move data |

### `Common_en/Battle/`
| File | Rows | Fields | Description |
|------|------|--------|-------------|
| `MonsterData.btb` | 485 | 113 | All enemy stats, rewards, AI refs |
| `MonsterParty.btb` | ? | ? | Enemy party compositions |
| `AIData.btb` | ? | ? | Enemy AI behavior scripts |
| `EncountTable.btb` | ? | ? | Encounter rates by area |
| `StatusTable.btb` | ? | ? | Status formulas |
| `AttrTable.btb` | ? | ? | Element relationships |
| `DrugCombine.btb` | ? | ? | Item mixing recipes |

### `Common_en/Shop/`
87 `.spb` files by town code (TW_10 through TW_22). Each town has:
`_Equip`, `_Item`, `_Magic`, `_Inn`, `_Master` sub-files.

## MonsterData.btb Field Map

Row size: 452 bytes (113 uint32 fields)

| Field | Orc (early) | Adventurer (late) | Likely Purpose |
|-------|-------------|-------------------|----------------|
| 000 | 50100 | — | Monster ID |
| 001 | "Orc" | — | Name (string) |
| 002 | 98 | — | String offset (label ref) |
| 003 | 7 | — | Level? |
| 021 | 80 | 530,000 | **HP** |
| 022 | 30 | 9,999 | **MP** |
| 023 | 60 | 600 | **EXP reward** (TBD - testing) |
| 024 | 7 | 100 | **Gil reward** (TBD - testing) |
| 025 | 9 | 150 | **Job EXP** (TBD - testing) |
| 026 | 0/28 | — | INT? |
| 027 | 12 | — | ATK/STR? |
| 028-030 | 9 each | — | DEF/MATK/MDEF? |
| 031 | 90 | — | Speed/AGI? |
| 033 | 11 | — | Level? |
| 035 | 3100 | — | AI script ref? |
| 057-058 | 999 | — | Steal item IDs? |
| 075-090 | 212-227 | — | Element resistances? |
| 091 | 6 | — | Drop table ref? |

**Status: fields 023-025 10x modded for testing. Originals backed up.**

## IL2CPP Dump — Key Classes and Constants

### Damage System

**`BTLDEF`** — Central battle definitions
| Constant | Value | Description |
|----------|-------|-------------|
| `DAMAGE_HP_MAX` | 9,999 | Normal damage cap |
| `SBDAMAGE_HP_MAX` | 99,999 | Super Brave damage cap |
| `DAMAGE_MP_MAX` | 999 | MP damage cap |
| `DAMAGE_BP_MAX` | 4 | BP damage cap |
| `CHARA_HP_MAX` | 99,999 | Character HP cap |

**`BtlDrawDamageCtrl.MAX_DAMAGE`** = 999,999 (display cap)

**`BtlActionCalc$$CheckDamageRange`** @ `0x18076a040`
- Normal: `Min(damage, 9999)`
- With boss/param_4: `Min(damage, 99999)`
- With ability 0x5E: `Min(damage, 999999)`
- Hit count: `Min(hits, 4)`

**`BtlActionCalc$$CalcPhysicsDamage`** @ `0x1807680a0`
```
damage = (abilityPower + ATK - defMult * DEF) * random * hits * elemResist * critMod * enhanceMod
```

### Stat Caps (CharacterState)
| Stat | Max |
|------|-----|
| HP | 99,999 |
| MP | 9,999 |
| STR/VIT/INT/MND/AGI/DEX | 999 |
| ATK/DEF/MATK/MDEF/ACC/DOD | 999 |
| Critical Rate | 999 |
| Action Speed | 999 |

### EXP/Gil System

**`BtlResultCtrl`** — Post-battle reward distribution
| Constant | Value |
|----------|-------|
| `MAX_TOTAL_EXP` | 9,999,999 |
| `MAX_EXP_GAIN` (per battle) | 999,999 |
| `MAX_TOTAL_JEXP` | 99,999 |
| `MAX_JEXP_GAIN` | 999 |
| `MAX_GIL_GAIN` | 999,999 |
| `MAX_BONUS_EXP` | 99,999 |
| `MAX_BONUS_JEXP` | 999 |
| `MAX_BONUS_GIL` | 99,999 |

**`PartyState.GIL_MAX`** = 9,999,999

Key methods:
- `ReviseAddEXP(exp, bonusexp)` @ `0x180475BB0` — caps per-battle EXP to 999,999
- `ReviseAddJEXP(jexp, bonusjexp)` @ `0x180475E80`
- `CountupCharaExp(charaindex)` @ `0x180475030` — caps total EXP to 9,999,999
- Ability 0x54 = 1.5x EXP multiplier (Growth Egg)

### BP (Brave Points) System

| Constant | Value |
|----------|-------|
| `BP_MAX` | 3 |
| `BP_MIN` | -4 |
| `SP_MAX` | 3 |
| `SP_MIN` | -9 |

**`gfc$$GetLimitBP`** @ `0x1805B9620`
- Returns 4 with ability 0x39 active
- Returns 3 otherwise

**`BtlHelper.CommandCtrl`** — Per-character BP state
- `m_bp` at offset 0x18
- `GetBP()` @ `0x18044FCD0`
- `SetBP(int)` @ `0x180459B80`

**`AbilityBpCalculator$$CalcAbilityBp`** @ `0x1804D5F90`
- Ability 0x5A2 adds +1 BP cost
- Ability 0x5A5 adds +1 BP cost for specific command types

### AutoBattle

**`BtlCommandRecorder`** — Autobattle record/playback
- `m_isAutoBattle` at offset 0x30 (bool)
- `MAX_RECORDS` = 4
- `ToggleAutoBattle()` @ `0x1804E19A0` — simple bool flip
- `PlaybackRecords(layout, commandsIndex)` @ `0x1804DED10` — replays recorded commands
- Falls back to basic attack (target=99) when command unavailable

**`BtlLayoutCtrl$$ProcessAutoBattle`** @ `0x180593810`
- Checks if autobattle is on, fades UI, calls `PlaybackRecords`

### Battle Speed

**`BtlFunction`** — Battle orchestrator
- `m_timeSpeed` at offset 0x128 (float)
- `SetTimeSpeed(float)` @ `0x18044B0B0`
- `GetTimeSpeed()` @ `0x18044AE10`

### Colony / Norende Village

**`ColonyData`** — Save data
| Constant | Value |
|----------|-------|
| `COLONYDATA_POPULATIONMAX` | 999 |
| `COLONYDATA_POPULATIONDEFAULT` | 1 |
| `COLONYDATA_WORKINGTIMEMIN` | 1 |
| `COLONYDATA_OBJECTLEVEL_LIMIT` | 10 |
| `COLONYDATA_OBJECTLEVEL_LIMITOVER` | 11 |

- `FenceParameter.GetMinutes()` @ `0x1804BEB40` — build time calculation
- `ColonyMainMap.DebugReduceAllTask(int minMinutes)` @ `0x1804A60B0`
- `ColonyMainMap.DebugStartAllTask()` @ `0x1804A63E0`

## Ghidra Project

- **Location:** `tmp/ghidra_projects/bdffhd`
- **Binary:** GameAssembly.dll imported as x86:LE:64:default
- **Analysis:** Full auto-analysis (18,430 seconds)
- **IL2CPP labels:** 201,681 methods, 17,267 strings, 12,271 metadata, 23,974 metadata methods, 108,680 functions
- **Size:** 2.2GB on disk

## Modding Approaches

### 1. Table Mods (BTBF edits) — Easy
Modify `StreamingAssets/Common_en/` files directly. Unity reads them at runtime.
- Item stats, shop prices, monster rewards, ability costs, etc.
- Use `btbf` CLI tool for dump/edit/repack
- Backup originals as `.btb.original`

### 2. Code Mods (DLL patching) — Medium
Patch `GameAssembly.dll` to change compiled constants and logic.
- Damage caps, stat caps, EXP multipliers
- BP limits, battle speed
- Need to patch at `System_Math__Min` call sites (constants inlined)

### 3. AutoBattle Enhancement — Hard
Replace simple command replay with rule-based system.
- Hook `PlaybackRecords` to inject smarter logic
- Reference: cowardly-irregular project's 2D rule grid system
- Would need significant code injection or DLL proxy approach

## Audio/Video Formats
- `.acb` / `.acf` — CRI middleware audio (ADX2)
- Movie files in `StreamingAssets/Movie/`
- Voice: `VOICE_en.acb`, `VOICE_ja.acb`
- BGM: `BDIO_BGM.acb`
- SE: `BDIO_SE.acb`
