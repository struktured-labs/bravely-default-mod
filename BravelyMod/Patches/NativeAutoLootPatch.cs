using System.Collections.Generic;
using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Auto-loot: when entering an area, instantly adds all treasure items to inventory.
/// Hooks TownFunction.AMX_SceneChange to detect area transitions, then looks up the
/// area's treasure table and calls PartyState.AddItem/AddPQ for each entry.
///
/// Treasure data is embedded from the parsed .trb files (36 areas, 386 entries).
/// Game flags for chests are NOT set (visual chests remain), but items are in inventory.
///
/// Key addresses (Ghidra):
///   PartyState.AddItem      @ 0x18066B8E0  (partyState, itemId, count, methodInfo)
///   PartyState.AddPQ        @ 0x18066BE50  (partyState, amount, methodInfo)
///   Hikari.GetGameData      @ 0x18045B500  () -> GameData singleton
///   GameData.PartyState     @ +0x20
///   GameData.SceneInfo      @ +0x100
///   SceneInfo.SceneName     @ +0x10
///   TownFunction.AMX_SceneChange @ 0x18070C9D0
/// </summary>
public static unsafe class NativeAutoLootPatch
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SceneChange(nint instance, nint amxParams, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddItem(nint instance, int itemId, int count, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddPQ(nint instance, int amount, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_GetGameData(nint methodInfo);

    // LAYOUTDEF.SetGameFlag(int flagIndex, bool value, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SetGameFlag(int flagIndex, byte value, nint methodInfo);

    // MB_MapName.CheckMap(this) -> bool — shows area name popup on entry
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_CheckMap(nint instance, nint methodInfo);

    private static NativeHook<d_SceneChange> _sceneChangeHook;
    private static d_SceneChange _pinnedSceneChange;

    private static NativeHook<d_CheckMap> _checkMapHook;
    private static d_CheckMap _pinnedCheckMap;

    private static d_AddItem _addItem;
    private static nint _addItem_mi;
    private static d_AddPQ _addPQ;
    private static nint _addPQ_mi;
    private static d_SetGameFlag _setGameFlag;
    private static nint _setGameFlag_mi;
    private static d_GetGameData _getGameData;
    private static nint _getGameData_mi;

    private static readonly HashSet<string> _lootedAreas = new();
    private static string _pendingLootMessage;
    private static int _pendingLootFrames; // countdown frames to show the message
    private static int _logCount;
    private const int MaxLogs = 30;

    // RVAs for fallback resolution
    private const long RVA_SCENE_CHANGE = 0x70C9D0;
    private const long RVA_ADD_ITEM = 0x66B8E0;
    private const long RVA_ADD_PQ = 0x66BE50;

    public static void Apply()
    {
        Log("Applying auto-loot hooks");

        // Resolve PartyState.AddItem
        Resolve<d_AddItem>(typeof(Il2Cpp.PartyState),
            "NativeMethodInfoPtr_AddItem_Public_Void_Int32_Int32_0",
            out _addItem, out _addItem_mi, "PartyState.AddItem");

        // Resolve PartyState.AddPQ
        Resolve<d_AddPQ>(typeof(Il2Cpp.PartyState),
            "NativeMethodInfoPtr_AddPQ_Public_Void_Int32_0",
            out _addPQ, out _addPQ_mi, "PartyState.AddPQ");

        // Resolve LAYOUTDEF.SetGameFlag for marking chests as opened
        Resolve<d_SetGameFlag>(typeof(Il2Cpp.LAYOUTDEF),
            "NativeMethodInfoPtr_SetGameFlag_Public_Static_Void_Int32_Boolean_0",
            out _setGameFlag, out _setGameFlag_mi, "LAYOUTDEF.SetGameFlag");

        // Resolve Hikari.GetGameData — try multiple field name patterns
        Resolve<d_GetGameData>(typeof(Il2Cpp.Hikari),
            "NativeMethodInfoPtr_GetGameData_Public_Static_GameData_0",
            out _getGameData, out _getGameData_mi, "Hikari.GetGameData");
        if (_getGameData == null)
            Resolve<d_GetGameData>(typeof(Il2Cpp.Hikari),
                "NativeMethodInfoPtr_get_GameData_Public_Static_GameData_0",
                out _getGameData, out _getGameData_mi, "Hikari.get_GameData");
        if (_getGameData == null)
        {
            // RVA fallback: Hikari$$GetGameData @ 0x18045B500
            const long RVA_GET_GAME_DATA = 0x45B500;
            try
            {
                var proc = System.Diagnostics.Process.GetCurrentProcess();
                foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
                {
                    if (mod.ModuleName != null &&
                        mod.ModuleName.Equals("GameAssembly.dll", System.StringComparison.OrdinalIgnoreCase))
                    {
                        nint addr = mod.BaseAddress + (nint)RVA_GET_GAME_DATA;
                        _getGameData = Marshal.GetDelegateForFunctionPointer<d_GetGameData>(addr);
                        Log($"Hikari.GetGameData resolved via RVA @ 0x{addr:X}");
                        break;
                    }
                }
            }
            catch (System.Exception ex) { Log($"Hikari.GetGameData RVA failed: {ex.Message}"); }
        }

        // Hook AMX_SceneChange
        try
        {
            var type = typeof(Il2Cpp.TownFunction);
            var field = type.GetField("NativeMethodInfoPtr_AMX_SceneChange_Private_Void_IntPtr_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field != null)
            {
                var mi = (nint)field.GetValue(null);
                if (mi != 0)
                {
                    var native = *(nint*)mi;
                    _pinnedSceneChange = SceneChange_Hook;
                    _sceneChangeHook = new NativeHook<d_SceneChange>(native,
                        Marshal.GetFunctionPointerForDelegate(_pinnedSceneChange));
                    _sceneChangeHook.Attach();
                    Log($"AMX_SceneChange hooked @ 0x{native:X}");
                }
            }
            else
            {
                // RVA fallback
                var proc = System.Diagnostics.Process.GetCurrentProcess();
                foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
                {
                    if (mod.ModuleName != null &&
                        mod.ModuleName.Equals("GameAssembly.dll", System.StringComparison.OrdinalIgnoreCase))
                    {
                        nint addr = mod.BaseAddress + (nint)RVA_SCENE_CHANGE;
                        _pinnedSceneChange = SceneChange_Hook;
                        _sceneChangeHook = new NativeHook<d_SceneChange>(addr,
                            Marshal.GetFunctionPointerForDelegate(_pinnedSceneChange));
                        _sceneChangeHook.Attach();
                        Log($"AMX_SceneChange hooked via RVA @ 0x{addr:X}");
                        break;
                    }
                }
            }
        }
        catch (System.Exception ex) { Warn($"SceneChange hook failed: {ex.Message}"); }

        // Hook MB_MapName.CheckMap to append loot notification to area name popup
        try
        {
            var mapNameType = typeof(Il2Cpp.MB_MapName);
            var cmField = mapNameType.GetField("NativeMethodInfoPtr_CheckMap_Public_Boolean_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (cmField != null)
            {
                var cmMi = (nint)cmField.GetValue(null);
                if (cmMi != 0)
                {
                    var cmNative = *(nint*)cmMi;
                    _pinnedCheckMap = CheckMap_Hook;
                    _checkMapHook = new NativeHook<d_CheckMap>(cmNative,
                        Marshal.GetFunctionPointerForDelegate(_pinnedCheckMap));
                    _checkMapHook.Attach();
                    Log($"MB_MapName.CheckMap hooked @ 0x{cmNative:X}");
                }
            }
        }
        catch (System.Exception ex) { Log($"CheckMap hook failed: {ex.Message}"); }

        Log($"Auto-loot ready ({_treasures.Count} areas)");
    }

    private static void SceneChange_Hook(nint instance, nint amxParams, nint methodInfo)
    {
        // Let the scene change happen first
        try { _sceneChangeHook.Trampoline(instance, amxParams, methodInfo); } catch { return; }

        if (!Core.AutoLootEnabled.Value) return;

        try
        {
            // Get current scene name from GameData.SceneInfo
            if (_getGameData == null) return;
            nint gameData = _getGameData(_getGameData_mi);
            if (gameData == 0) return;

            nint sceneInfo = *(nint*)(gameData + 0x100);
            if (sceneInfo == 0) return;

            nint sceneNamePtr = *(nint*)(sceneInfo + 0x10);
            if (sceneNamePtr == 0) return;

            // Read IL2CPP string: length at +0x10, chars at +0x14 (UTF-16)
            int len = *(int*)(sceneNamePtr + 0x10);
            if (len <= 0 || len > 200) return;
            string sceneName = new string((char*)(sceneNamePtr + 0x14), 0, len);

            // Extract area prefix from scene name (e.g., "ND_1001" -> "ND_10")
            string area = ExtractAreaPrefix(sceneName);
            if (area == null) return;

            // Only loot each area once per session
            if (_lootedAreas.Contains(area)) return;

            if (!_treasures.TryGetValue(area, out var items)) return;

            // Get PartyState
            nint partyState = *(nint*)(gameData + 0x20);
            if (partyState == 0) return;

            int itemCount = 0, gilTotal = 0;
            foreach (var (itemId, qty) in items)
            {
                try
                {
                    if (itemId > 0 && _addItem != null)
                    {
                        _addItem(partyState, itemId, qty, _addItem_mi);
                        itemCount++;
                    }
                    else if (itemId == 0 && qty > 0 && _addPQ != null)
                    {
                        _addPQ(partyState, qty, _addPQ_mi);
                        gilTotal += qty;
                    }
                }
                catch { }
            }

            // Mark chests as opened via game flags (dungeon areas only)
            int flagsSet = 0;
            if (_setGameFlag != null && _chestFlags.TryGetValue(area, out var flags))
            {
                foreach (int flagIdx in flags)
                {
                    try { _setGameFlag(flagIdx, 1, _setGameFlag_mi); flagsSet++; }
                    catch { }
                }
            }

            _lootedAreas.Add(area);

            // Set pending message for map name popup (allow ~120 frames for CheckMap to pick it up)
            string msg = gilTotal > 0
                ? $"Looted {itemCount} items + {gilTotal} PQ!"
                : $"Looted {itemCount} items!";
            _pendingLootMessage = msg;
            _pendingLootFrames = 120;

            _logCount++;
            if (_logCount <= MaxLogs)
                Log($"Looted {area}: {itemCount} items, {gilTotal} PQ, {flagsSet} chests opened (scene: {sceneName})");
        }
        catch (System.Exception ex)
        {
            _logCount++;
            if (_logCount <= 5) Warn($"Auto-loot error: {ex.Message}");
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SetText(nint instance, nint text, nint methodInfo);

    private static byte CheckMap_Hook(nint instance, nint methodInfo)
    {
        byte result = 0;
        try { result = _checkMapHook.Trampoline(instance, methodInfo); } catch { return 0; }

        // Decrement frame counter; apply text when CheckMap fires with a pending message
        if (_pendingLootMessage != null && _pendingLootFrames > 0)
        {
            _pendingLootFrames--;

            // Only apply when CheckMap returns true (map name popup is showing)
            if (result != 0)
            {
                try
                {
                    nint unit = *(nint*)(instance + 0x20);
                    if (unit != 0)
                    {
                        nint vtable = *(nint*)unit;
                        nint fn = *(nint*)(vtable + 0x558);
                        nint mi = *(nint*)(vtable + 0x560);
                        if (fn != 0)
                        {
                            nint str = Il2CppInterop.Runtime.IL2CPP.ManagedStringToIl2Cpp(_pendingLootMessage);
                            var setText = Marshal.GetDelegateForFunctionPointer<d_SetText>(fn);
                            setText(unit, str, mi);
                            Log($"Notification shown: {_pendingLootMessage}");
                        }
                    }
                }
                catch (System.Exception ex)
                {
                    _logCount++;
                    if (_logCount <= 5) Log($"CheckMap text failed: {ex.Message}");
                }
                _pendingLootMessage = null;
                _pendingLootFrames = 0;
            }
        }
        else if (_pendingLootFrames <= 0 && _pendingLootMessage != null)
        {
            Log($"Notification expired (CheckMap didn't fire in time): {_pendingLootMessage}");
            _pendingLootMessage = null;
        }

        return result;
    }

    private static string ExtractAreaPrefix(string sceneName)
    {
        // Scene names like "ND_1001", "TW_1001", "EV_1001" -> "ND_10", "TW_10", "EV_10"
        // Also "ND_1102" -> "ND_11", "ND_2001" -> "ND_20"
        if (sceneName == null || sceneName.Length < 5) return null;

        // Try common prefixes
        foreach (var prefix in new[] { "ND_", "TW_", "EV_" })
        {
            int idx = sceneName.IndexOf(prefix, System.StringComparison.Ordinal);
            if (idx >= 0 && sceneName.Length >= idx + 5)
            {
                // Extract the numeric part after prefix
                string numPart = sceneName.Substring(idx + 3);
                // Take first 2 digits for area (e.g., "1001" -> "10", "2501" -> "25")
                if (numPart.Length >= 2 && char.IsDigit(numPart[0]) && char.IsDigit(numPart[1]))
                    return prefix.TrimEnd('_') + "_" + numPart.Substring(0, 2);
            }
        }
        return null;
    }

    private static void Resolve<T>(System.Type type, string fieldName, out T fn, out nint mi, string label) where T : System.Delegate
    {
        fn = default; mi = 0;
        try
        {
            var field = type.GetField(fieldName,
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Log($"{label}: field not found"); return; }
            mi = (nint)field.GetValue(null);
            if (mi == 0) { Log($"{label}: null MI"); return; }
            fn = Marshal.GetDelegateForFunctionPointer<T>(*(nint*)mi);
            Log($"{label} resolved");
        }
        catch (System.Exception ex) { Log($"{label}: {ex.Message}"); }
    }

    private static void Log(string msg) => Melon<Core>.Logger.Msg($"[AutoLoot] {msg}");
    private static void Warn(string msg) => Melon<Core>.Logger.Warning($"[AutoLoot] {msg}");

    // ── Embedded treasure data (from .trb files) ──────────────────
    // (itemId, quantity) — itemId=0 means gil (quantity = PQ amount)

    private static readonly Dictionary<string, (int itemId, int qty)[]> _treasures = new()
    {
        ["EV_10"] = new (int,int)[] { (10001, 1), (30401, 1), (20001, 1), (0, 500) },
        ["EV_15"] = new (int,int)[] { (0, 2000), (10102, 1) },
        ["ND_10"] = new (int,int)[] { (40000, 1), (0, 200), (90017, 1), (90001, 1) },
        ["ND_11"] = new (int,int)[] { (30127, 1), (40000, 1), (10501, 1), (40007, 1), (40006, 1), (40003, 1), (10800, 1) },
        ["ND_12"] = new (int,int)[] { (40001, 1), (40002, 1), (10200, 1), (30128, 1), (40000, 1), (0, 400), (40003, 1), (20008, 1) },
        ["ND_13"] = new (int,int)[] { (30119, 1), (10504, 1), (40004, 1), (40011, 1), (40009, 1), (40001, 1), (10302, 1), (30131, 1) },
        ["ND_14"] = new (int,int)[] { (40009, 1), (40003, 1), (0, 500), (30419, 1), (40004, 1), (30123, 1), (40006, 1), (0, 1000), (40014, 1), (40001, 1) },
        ["ND_15"] = new (int,int)[] { (0, 1), (30129, 1), (40006, 1), (30126, 1), (0, 1500), (10601, 1), (30005, 1), (40001, 1), (10512, 1), (10507, 1) },
        ["ND_16"] = new (int,int)[] { (40001, 1), (40010, 1), (40004, 1), (30130, 1), (10807, 1), (10404, 1), (40009, 1), (40003, 1) },
        ["ND_17"] = new (int,int)[] { (40004, 1), (10106, 1), (40003, 1), (40010, 1), (10003, 1), (0, 2000), (30130, 1), (40011, 1), (40001, 1), (40009, 1), (40004, 1) },
        ["ND_18"] = new (int,int)[] { (10508, 1), (40004, 1), (0, 1000), (0, 500), (40009, 1), (40001, 1), (10700, 1) },
        ["ND_19"] = new (int,int)[] { (40003, 1), (40009, 1), (40004, 1), (40001, 1), (30117, 1), (40010, 1), (30132, 1) },
        ["ND_20"] = new (int,int)[] { (40004, 1), (40003, 1), (0, 500), (10010, 1), (10605, 1), (40014, 1), (0, 1000), (40010, 1), (10209, 1), (40001, 1), (40009, 1) },
        ["ND_21"] = new (int,int)[] { (40010, 1), (40009, 1), (0, 500), (10100, 1), (0, 1000), (40001, 1), (30209, 1), (40021, 1), (40004, 1), (40011, 1) },
        ["ND_22"] = new (int,int)[] { (40004, 1), (40009, 1), (40001, 1), (0, 500), (40019, 1), (0, 1000), (30112, 1), (40001, 1), (10600, 1), (10608, 1), (40010, 1), (30122, 1), (40011, 1), (30134, 1) },
        ["ND_23"] = new (int,int)[] { (40023, 1), (40010, 1), (0, 1000), (40011, 1), (30006, 1) },
        ["ND_24"] = new (int,int)[] { (0, 1000), (40015, 1), (30306, 1), (40016, 1), (0, 2000), (30133, 1), (40010, 1), (30116, 1), (40011, 1), (10410, 1), (10105, 1), (10606, 1) },
        ["ND_25"] = new (int,int)[] { (20007, 1), (10007, 1), (40010, 1), (40011, 1), (40012, 1) },
        ["ND_26"] = new (int,int)[] { (0, 500), (40009, 1), (0, 1000), (10008, 1), (40029, 1), (30117, 1), (40036, 1), (10706, 1), (30134, 1), (40010, 1), (30133, 1), (10511, 1), (40011, 1), (30104, 1) },
        ["ND_27"] = new (int,int)[] { (40010, 1), (30507, 1), (40011, 1), (10201, 1), (40015, 1), (0, 2000), (40029, 1), (30132, 1), (40012, 1) },
        ["ND_28"] = new (int,int)[] { (40017, 1), (0, 1000), (0, 2000), (10107, 1), (40011, 1), (40025, 1), (30410, 1), (10208, 1), (10705, 1), (40029, 1), (10311, 1), (40018, 1), (30124, 1), (40013, 1) },
        ["ND_29"] = new (int,int)[] { (30121, 1), (40010, 1), (40036, 1), (40019, 1), (40029, 1), (0, 3000), (40010, 1), (0, 5000), (40027, 1), (10012, 1), (40020, 1), (40025, 1), (40028, 1), (40011, 1), (10013, 1), (10804, 1), (10509, 1), (10205, 1), (40026, 1), (40012, 1) },
        ["ND_30"] = new (int,int)[] { (40011, 1), (40023, 1), (10603, 1), (10011, 1), (40011, 1), (40010, 1), (10703, 1), (10308, 1), (40012, 1), (40025, 1), (20009, 1), (40036, 1), (30120, 1), (40024, 1), (40027, 1) },
        ["ND_31"] = new (int,int)[] { (10805, 1), (40036, 1), (30133, 1), (10009, 1), (30113, 1), (30125, 1), (30109, 1), (30115, 1), (30105, 1), (30111, 1), (30218, 1), (40013, 1), (10306, 1) },
        ["ND_32"] = new (int,int)[] { (30133, 1), (40013, 1), (30107, 1), (30218, 1), (30125, 1), (30106, 1), (40013, 1), (30219, 1), (30208, 1), (20011, 1), (10306, 1), (30410, 1), (10009, 1), (30421, 1) },
        ["ND_33"] = new (int,int)[] { (40013, 1), (10209, 1), (10513, 1), (10407, 1), (40013, 1), (30421, 1), (10109, 1), (10106, 1), (10308, 1), (10404, 1), (10305, 1), (30410, 1), (10608, 1), (10512, 1), (10610, 1), (30507, 1), (30006, 1), (30306, 1), (10708, 1), (30219, 1), (30419, 1), (10808, 1), (10013, 1), (20011, 1), (30410, 1), (10210, 1), (10706, 1), (10805, 1), (10014, 1) },
        ["TW_10"] = new (int,int)[] { (10001, 1), (0, 1000), (20001, 3), (0, 50), (40002, 1), (40003, 1), (40000, 1), (0, 100), (40000, 1), (40005, 1), (30105, 1) },
        ["TW_11"] = new (int,int)[] { (40001, 1), (40009, 1), (40003, 1), (40025, 1), (40014, 1) },
        ["TW_12"] = new (int,int)[] { (30131, 1), (40017, 1), (30423, 1) },
        ["TW_13"] = new (int,int)[] { (40001, 1), (40015, 1), (40028, 1), (30126, 1), (40016, 1), (40021, 1), (40009, 1) },
        ["TW_14"] = new (int,int)[] { (40017, 1), (30116, 1), (40029, 1), (40010, 1), (40019, 1), (0, 1000), (40011, 1) },
        ["TW_16"] = new (int,int)[] { (40012, 1), (10511, 1), (30142, 1) },
        ["TW_17"] = new (int,int)[] { (40023, 1), (40026, 1) },
        ["TW_18"] = new (int,int)[] { (40012, 1), (40018, 1), (30132, 1) },
        ["TW_19"] = new (int,int)[] { (30117, 1), (40027, 1) },
        ["TW_20"] = new (int,int)[] { (40017, 1), (30116, 1), (40029, 1), (40010, 1), (40019, 1), (0, 1000), (40011, 1), (90017, 1) },
    };

    // ── Chest opened flags (dungeon areas only) ──────────────────
    // Game flags 3001-3251, sequential per area. SetGameFlag(idx, true) marks chest as opened.

    private static readonly Dictionary<string, int[]> _chestFlags = new()
    {
        ["ND_10"] = new int[] { 3001, 3002 },
        ["ND_11"] = new int[] { 3003, 3004, 3005, 3006, 3007, 3008 },
        ["ND_12"] = new int[] { 3009, 3010, 3011, 3012, 3013, 3014, 3015, 3016 },
        ["ND_13"] = new int[] { 3017, 3018, 3019, 3020, 3021, 3022, 3023 },
        ["ND_14"] = new int[] { 3024, 3025, 3026, 3027, 3028, 3029, 3030, 3031, 3032, 3033 },
        ["ND_15"] = new int[] { 3034, 3035, 3036, 3037, 3038, 3039, 3040, 3041, 3042 },
        ["ND_16"] = new int[] { 3043, 3044, 3045, 3046, 3047, 3048, 3049, 3050 },
        ["ND_17"] = new int[] { 3051, 3052, 3053, 3054, 3055, 3056, 3057, 3058, 3059, 3060, 3061 },
        ["ND_18"] = new int[] { 3062, 3063, 3064, 3065, 3066, 3067, 3068 },
        ["ND_19"] = new int[] { 3069, 3070, 3071, 3072, 3073, 3074 },
        ["ND_20"] = new int[] { 3075, 3076, 3077, 3078, 3079, 3080, 3081, 3082, 3083, 3084, 3085 },
        ["ND_21"] = new int[] { 3086, 3087, 3088, 3089, 3090, 3091, 3092, 3093, 3094, 3095 },
        ["ND_22"] = new int[] { 3096, 3097, 3098, 3099, 3100, 3101, 3102, 3103, 3104, 3105, 3106, 3107, 3108 },
        ["ND_23"] = new int[] { 3109, 3110, 3111, 3112, 3113 },
        ["ND_24"] = new int[] { 3114, 3115, 3116, 3117, 3118, 3119, 3120, 3121, 3122, 3123, 3124, 3125 },
        ["ND_25"] = new int[] { 3126, 3127, 3128, 3129 },
        ["ND_26"] = new int[] { 3130, 3131, 3132, 3133, 3134, 3135, 3136, 3137, 3138, 3139, 3140, 3141, 3142 },
        ["ND_27"] = new int[] { 3143, 3144, 3145, 3146, 3147, 3148, 3149, 3150 },
        ["ND_28"] = new int[] { 3151, 3152, 3153, 3154, 3155, 3156, 3157, 3158, 3159, 3160, 3161, 3162, 3163 },
        ["ND_29"] = new int[] { 3164, 3165, 3166, 3167, 3168, 3169, 3170, 3171, 3172, 3173, 3174, 3175, 3176, 3177, 3178, 3179, 3180, 3181, 3182 },
        ["ND_30"] = new int[] { 3183, 3184, 3185, 3186, 3187, 3188, 3189, 3190, 3191, 3192, 3193, 3194, 3195, 3196 },
        ["ND_31"] = new int[] { 3197, 3198, 3199, 3200, 3201, 3202, 3203, 3204, 3205, 3206, 3207, 3208 },
        ["ND_32"] = new int[] { 3209, 3210, 3211, 3212, 3213, 3214, 3215, 3216, 3217, 3218, 3219, 3220, 3221, 3222 },
        ["ND_33"] = new int[] { 3223, 3224, 3225, 3226, 3227, 3228, 3229, 3230, 3231, 3232, 3233, 3234, 3235, 3236, 3237, 3238, 3239, 3240, 3241, 3242, 3243, 3244, 3245, 3246, 3247, 3248, 3249, 3250, 3251 },
    };
}
