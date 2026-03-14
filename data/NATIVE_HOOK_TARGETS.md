# Native Hook Targets for BDFFHD

All addresses are VA. IL2CPP native calling convention: `(IntPtr instance, params..., IntPtr methodInfo)` for instance methods, `(params..., IntPtr methodInfo)` for static.

## BP System
| Function | VA | Signature |
|---|---|---|
| `BtlCharaManager.AddBPByTeam` | `0x1809AE060` | `void(nint instance, int _team, nint methodInfo)` |
| `BtlChara.SetBP` | `0x18099F1B0` | `int(nint instance, int bp, nint methodInfo)` |
| `BtlChara.GetBP` | `0x18099C480` | `int(nint instance, nint methodInfo)` |
| `BtlChara.GetAddStartBP` | `0x18063CE70` | `int(nint instance, nint methodInfo)` |
| `gfc.GetLimitBP` | `0x1805B9620` | `int(nint pChr, nint methodInfo)` — static |

## Buff/Status Limits
| Function | VA | Signature |
|---|---|---|
| `BtlDataManager.GetBuffMax` | `0x1809B64B0` | `float(nint instance, int buffType, nint methodInfo)` |
| `BtlDataManager.GetBuffMin` | `0x1809B6520` | `float(nint instance, int buffType, nint methodInfo)` |
| `BtlStatusManager.IsBuffLimit` | `0x180484660` | `bool(nint instance, int buffType, nint methodInfo)` |
| `BtlStatusManager.IsSpecialBuffLimit` | `0x1804849D0` | `bool(nint instance, int buffType, nint methodInfo)` |

## Enemy Stats (BtlMonsterData fields, data table)
- `hpMax` (0x84), `attack` (0x8C), `deffence` (0x90), `magicAttack` (0x94), `magicDeffence` (0x98)
- `agility` (0x9C), `actSpeed` (0xB4), `criticalRate` (0xB8)

## Encounter Rate
| Function | VA | Signature |
|---|---|---|
| `ConfigData_tr.Difficulty.GetEncountRate` | `0x18044FCD0` | `int(nint instance, nint methodInfo)` |
| `GameData.SetEncountMonster` | `0x1804FE560` | toggles encounters on/off |

## AutoBattle
| Function | VA | Signature |
|---|---|---|
| `BtlLayoutCtrl.ProcessAutoBattle` | `0x180593810` | `void(nint instance, int commandIndex, nint methodInfo)` |
| `BtlCommandRecorder.PlaybackRecords` | `0x1804DED10` | `void(nint instance, nint pBtlLayoutCtrl, int commandsIndex, nint methodInfo)` |
| `BtlCommandRecorder.SendCommand` | `0x1804E0EB0` | `void(nint instance, int charaIndex, nint command, byte isRemoveBp, byte changeSerial, nint methodInfo)` |
| `BtlAIManager.MakeAllPlayerAICommand` | `0x180949170` | `void(nint instance, nint methodInfo)` — existing AI for players |

## CommandInfo struct (offset from IL2CPP object base)
- `commandType` (0x28): NONE=0, FIGHT=1, MAGIC=2, ABILITY=3, ITEM=4, GUARD=5, ESCAPE=6
- `commandSubType` (0x2C), `commandSubIndex` (0x30)
- `targetType` (0x34), `targetIdxList` (0x38)
- `charaIdx` (0x14), `ownerindex` (0x10)
