using System.Collections.Generic;
using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Skip to Boss: when entering a dungeon, warp directly to the boss room.
/// Also suppresses random encounters while active.
///
/// Hooks:
///   AMX_SetMapId (0x1807120C0) — detect dungeon entry by map_id, redirect to boss
///   AMX_JudgeEncount (0x180706A0) — suppress random encounters when skip active
///
/// Uses ChangeFunction.LoadRequest pattern to trigger scene transitions.
/// Map data from MapTable.btb + dungeon_boss_map.json.
/// </summary>
public static unsafe class NativeSkipToBossPatch
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SetMapId(nint instance, nint amxParams, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_JudgeEncount(nint instance, nint amxParams, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_GetGameData(nint methodInfo);

    private static NativeHook<d_SetMapId> _setMapIdHook;
    private static d_SetMapId _pinnedSetMapId;

    private static NativeHook<d_JudgeEncount> _judgeEncountHook;
    private static d_JudgeEncount _pinnedJudgeEncount;

    private static d_GetGameData _getGameData;
    private static nint _getGameData_mi;

    private static bool _skipActive; // true while warping to boss room
    private static int _logCount;
    private const int MaxLogs = 20;

    private const long RVA_SET_MAP_ID = 0x7120C0;
    private const long RVA_JUDGE_ENCOUNT = 0x7106A0;
    private const long RVA_GET_GAME_DATA = 0x45B500;

    public static void Apply()
    {
        Log("Applying skip-to-boss hooks");

        // Resolve GetGameData via RVA (reflection fails for Hikari)
        try
        {
            var proc = System.Diagnostics.Process.GetCurrentProcess();
            foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
            {
                if (mod.ModuleName != null &&
                    mod.ModuleName.Equals("GameAssembly.dll", System.StringComparison.OrdinalIgnoreCase))
                {
                    nint baseAddr = mod.BaseAddress;
                    _getGameData = Marshal.GetDelegateForFunctionPointer<d_GetGameData>(baseAddr + (nint)RVA_GET_GAME_DATA);
                    Log($"GetGameData resolved via RVA");

                    // Hook AMX_SetMapId
                    _pinnedSetMapId = SetMapId_Hook;
                    _setMapIdHook = new NativeHook<d_SetMapId>(baseAddr + (nint)RVA_SET_MAP_ID,
                        Marshal.GetFunctionPointerForDelegate(_pinnedSetMapId));
                    _setMapIdHook.Attach();
                    Log($"AMX_SetMapId hooked @ 0x{baseAddr + (nint)RVA_SET_MAP_ID:X}");

                    // Hook AMX_JudgeEncount
                    _pinnedJudgeEncount = JudgeEncount_Hook;
                    _judgeEncountHook = new NativeHook<d_JudgeEncount>(baseAddr + (nint)RVA_JUDGE_ENCOUNT,
                        Marshal.GetFunctionPointerForDelegate(_pinnedJudgeEncount));
                    _judgeEncountHook.Attach();
                    Log($"AMX_JudgeEncount hooked @ 0x{baseAddr + (nint)RVA_JUDGE_ENCOUNT:X}");

                    break;
                }
            }
        }
        catch (System.Exception ex) { Warn($"Hook failed: {ex.Message}"); }

        Log($"Skip-to-boss ready ({_dungeonBossMap.Count} dungeons mapped)");
    }

    private static void SetMapId_Hook(nint instance, nint amxParams, nint methodInfo)
    {
        // Let original set the map ID first
        try { _setMapIdHook.Trampoline(instance, amxParams, methodInfo); } catch { return; }

        if (!Core.SkipToBossEnabled.Value) return;

        try
        {
            // Read the map_id that was just set (GameData+0x4C)
            if (_getGameData == null) return;
            nint gameData = _getGameData(_getGameData_mi);
            if (gameData == 0) return;

            int mapId = *(int*)(gameData + 0x4C);

            // Check if this map_id is a dungeon entry
            if (_dungeonBossMap.TryGetValue(mapId, out var boss))
            {
                // Redirect: set map_id to boss room
                *(int*)(gameData + 0x4C) = boss.bossMapId;
                _skipActive = true;

                _logCount++;
                if (_logCount <= MaxLogs)
                    Log($"Skip to boss: map {mapId} -> {boss.bossMapId}");
            }
            else if (_skipActive && !_dungeonBossMap.ContainsKey(mapId))
            {
                // Exited dungeon, deactivate encounter suppression
                _skipActive = false;
            }
        }
        catch (System.Exception ex)
        {
            _logCount++;
            if (_logCount <= 5) Warn($"SetMapId error: {ex.Message}");
        }
    }

    private static int JudgeEncount_Hook(nint instance, nint amxParams, nint methodInfo)
    {
        // Suppress encounters when skip-to-boss is active
        if (_skipActive && Core.SkipToBossEnabled.Value)
            return 0; // no encounter

        try { return _judgeEncountHook.Trampoline(instance, amxParams, methodInfo); }
        catch { return 0; }
    }

    private static void Log(string msg) => Melon<Core>.Logger.Msg($"[SkipBoss] {msg}");
    private static void Warn(string msg) => Melon<Core>.Logger.Warning($"[SkipBoss] {msg}");

    // entry_map_id -> (boss_map_id, boss_scene_path)
    private static readonly Dictionary<int, (int bossMapId, string bossScene)> _dungeonBossMap = new()
    {
        [33] = (35, "Script/Scene/ND_10_RavineRoad/Scene/M0010_Scene.amx"), // ND_10 Norende Ravine
        [37] = (39, "Script/Scene/ND_11_FortOfBlackMage/Scene/M0036_Scene.amx"), // ND_11 Ruins of Centro Keep
        [40] = (43, "Script/Scene/ND_12_KnightResidence/Scene/M0047_Scene.amx"), // ND_12 Lontano Villa
        [44] = (46, "Script/Scene/ND_13_WindTemple/Scene/M0110_Scene.amx"), // ND_13 Temple of Wind
        [47] = (50, "Script/Scene/ND_14_PriestessCave/Scene/M0121_Scene.amx"), // ND_14 Vestment Cave
        [51] = (53, "Script/Scene/ND_15_ThiefAgitatingPoint/Scene/M1117_Scene.amx"), // ND_15 Harena Ruins
        [55] = (56, "Script/Scene/ND_16_BigClockTower/Scene/M1122_Scene.amx"), // ND_16 Grand Mill Works
        [57] = (59, "Script/Scene/ND_17_MiasmForest/Scene/M0145_Scene.amx"), // ND_17 Miasma Woods
        [60] = (62, "Script/Scene/ND_18_RavineRoad2/Scene/M0218_Scene.amx"), // ND_18 Mount Fragmentum
        [63] = (63, "Script/Scene/ND_19_WaterTemple/Scene/M0236_Scene.amx"), // ND_19 Temple of Water
        [64] = (66, "Script/Scene/ND_20_SecretVillage_North/Scene/M1232_Scene.amx"), // ND_20 Witherwood
        [68] = (70, "Script/Scene/ND_21_FlowerGarden/Scene/M1218_Scene.amx"), // ND_21 Florem Gardens
        [72] = (75, "Script/Scene/ND_22_SecretVillage_West/Scene/M0230_Scene.amx"), // ND_22 Twilight Ruins
        [77] = (78, "Script/Scene/ND_23_OrihalconMine/Scene/M0338_Scene.amx"), // ND_23 Mythril Mines
        [79] = (83, "Script/Scene/ND_24_Volcano/Scene/M0356_Scene.amx"), // ND_24 Underflow
        [84] = (84, "Script/Scene/ND_25_FireTemple/Scene/M0363_Scene.amx"), // ND_25 Temple of Fire
        [85] = (90, "Script/Scene/ND_26_SwordGroupHidingPlaceDungeon/Scene/M0316_Scene.amx"), // ND_26 Starkfort Interior
        [91] = (93, "Script/Scene/ND_27_FormerBattlefield/Scene/M0327_Scene.amx"), // ND_27 Grapp Keep
        [94] = (97, "Script/Scene/ND_28_PowerReactor/Scene/M0388_Scene.amx"), // ND_28 Engine Room
        [98] = (104, "Script/Scene/ND_29_JAsHeadquarters/Scene/M0440_Scene.amx"), // ND_29 Eternian Central Command
        [108] = (112, "Script/Scene/ND_30_SoilTemple/Scene/M0443_Scene.amx"), // ND_30 Everlast Tower
        [113] = (120, "Script/Scene/ND_31_VampireCastle/Scene/M1424_Scene.amx"), // ND_31 Vampire Castle
        [121] = (128, "Script/Scene/ND_32_LastDungeon/ND_3207/Airy_0000.amx"), // ND_32 Dark Aurora
        [129] = (138, "Script/Scene/ND_33_ExtraDungeon/Scene/M1951_Scene.amx"), // ND_33 Dimension's Hasp
    };
}
