using System.Collections.Generic;
using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;
using MelonLoader.Utils;
using BravelyMod.AutoBattle;
using Il2CppInterop.Runtime;

namespace BravelyMod.Patches;

/// <summary>
/// Autobattle with conditional rules (Approach A: inject into repeat storage).
///
/// Instead of calling SendCommand/AddAttackCommand directly (which caused -99 BP),
/// we write CommandInfo objects into BtlCommandRecorder's repeat storage vectors,
/// then call the original ProcessAutoBattle trampoline. PlaybackRecords handles
/// ALL BP/AP accounting, cost calculation, target validation, and UI updates.
///
/// Flow:
///   1. Evaluate RuleEngine for each character
///   2. Clear repeat storage vectors for each character
///   3. Push our CommandInfo objects into the vectors
///   4. Call original ProcessAutoBattle (which calls PlaybackRecords → EndWaitTurnPhase)
/// </summary>
public static unsafe class NativeAutoBattlePatch
{
    // void ProcessAutoBattle(BtlLayoutCtrl* this, int commandIndex, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_ProcessAutoBattle(nint instance, int commandIndex, nint methodInfo);

    // void CommandInfo..ctor(CommandInfo* this, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_CommandInfoCtor(nint thisPtr, nint methodInfo);

    // void CommandInfo.Clear(CommandInfo* this, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_CommandInfoClear(nint thisPtr, nint methodInfo);

    // nint Hikari.GetGameData(MethodInfo*) — static
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_GetGameData(nint methodInfo);

    // void STLVector.clear(nint vector, nint methodInfo)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_VectorClear(nint vector, nint methodInfo);

    // void STLVector.push_back(nint vector, nint item, nint methodInfo)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_VectorPushBack(nint vector, nint item, nint methodInfo);

    private static NativeHook<d_ProcessAutoBattle> _processHook;
    private static d_ProcessAutoBattle _pinnedProcess;

    private static nint _commandInfoCtorPtr, _commandInfoCtorMi;
    private static nint _commandInfoClearPtr, _commandInfoClearMi;
    private static nint _commandInfoClass;

    private static d_GetGameData _getGameData;
    private static nint _getGameData_mi;

    // CanAutoPlay hook — bypass empty-tactic check so our rules can fire
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_CanAutoPlay(int playingCommand, nint methodInfo);

    private static NativeHook<d_CanAutoPlay> _canAutoPlayHook;
    private static d_CanAutoPlay _pinnedCanAutoPlay;

    // TacticsNameListImpl.get_Item hook — show our profile names
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_GetTacticsName(nint instance, int index, nint methodInfo);

    private static NativeHook<d_GetTacticsName> _getTacticsNameHook;
    private static d_GetTacticsName _pinnedGetTacticsName;

    // SetAutoPanel hook — show rule descriptions as command plates
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SetAutoPanel(nint instance, int panelIndex, nint methodInfo);

    private static NativeHook<d_SetAutoPanel> _setAutoPanelHook;
    private static d_SetAutoPanel _pinnedSetAutoPanel;

    // AutoWindowAddCommandPlate(instance, charaIdx, abilityName, iconName, isValid, methodInfo)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddCommandPlate(nint instance, int charaIdx, nint abilityName, nint iconName, byte isValid, nint methodInfo);

    private static d_AddCommandPlate _addCommandPlate;
    private static nint _addCommandPlate_mi;

    // AutoPanelClear(instance, methodInfo)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AutoPanelClear(nint instance, nint methodInfo);

    private static d_AutoPanelClear _autoPanelClear;
    private static nint _autoPanelClear_mi;

    // STLVector<CommandInfo> method info pointers (for clear/push_back)
    private static nint _vectorClearMi;
    private static nint _vectorPushBackMi;
    private static d_VectorClear _vectorClear;
    private static d_VectorPushBack _vectorPushBack;

    // CommandInfo field offsets
    private const int OFF_OWNER_INDEX = 0x10;
    private const int OFF_CHARA_IDX = 0x14;
    private const int OFF_COMMAND_TYPE = 0x28;
    private const int OFF_COMMAND_SUB_TYPE = 0x2C;
    private const int OFF_TARGET_TYPE = 0x34;
    private const int OFF_TARGET_IDX_LIST = 0x38;
    private const int OFF_AP_COST = 0x60;
    private const int OFF_IS_TARGET_ENEMY = 0x68;

    // Command types
    private const int CMD_FIGHT = 1;
    private const int CMD_MAGIC = 2;
    private const int CMD_ABILITY = 3;
    private const int CMD_ITEM = 4;
    private const int CMD_GUARD = 5;

    // BtlCommandRecorder offsets
    private const int OFF_RECORDER_VECTORS = 0x20; // managed array of STLVector<CommandInfo>
    private const int OFF_RECORDER_FLAGS = 0x28;    // managed byte[] flags
    private const int OFF_RECORDER_MODE = 0x34;     // int: -1=repeat, >=0=recorded set index

    // RVAs
    private const long RVA_GET_GAME_DATA = 0x45B500;
    private const long RVA_VECTOR_CLEAR = 0; // resolved from BackupCommand's method refs
    private const long RVA_VECTOR_PUSH_BACK = 0;

    private static readonly RuleEngine _ruleEngine = new();
    private static int _logCount;
    private const int MaxLogs = 40;

    public static string ConfigPath =>
        System.IO.Path.Combine(MelonEnvironment.UserDataDirectory, "BravelyMod_AutoBattle.yaml");

    public static RuleEngine RuleEngine => _ruleEngine;

    public static void Apply()
    {
        ProfileConfig.LoadInto(ConfigPath, _ruleEngine);

        // Hook ProcessAutoBattle
        try
        {
            var field = typeof(Il2Cpp.BtlLayoutCtrl).GetField(
                "NativeMethodInfoPtr_ProcessAutoBattle_Public_Void_Int32_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Warn("ProcessAutoBattle field not found"); return; }
            var mi = (nint)field.GetValue(null);
            if (mi == 0) { Warn("ProcessAutoBattle MI null"); return; }
            var native = *(nint*)mi;
            _pinnedProcess = ProcessAutoBattle_Hook;
            _processHook = new NativeHook<d_ProcessAutoBattle>(native,
                Marshal.GetFunctionPointerForDelegate(_pinnedProcess));
            _processHook.Attach();
            Log($"ProcessAutoBattle hooked @ 0x{native:X}");
        }
        catch (System.Exception ex) { Warn($"Hook failed: {ex.Message}"); return; }

        // Resolve CommandInfo helpers
        ResolveMethod(typeof(Il2Cpp.BtlCommandManager.CommandInfo),
            "NativeMethodInfoPtr__ctor_Public_Void_0",
            out _commandInfoCtorPtr, out _commandInfoCtorMi, "CommandInfo.ctor");
        ResolveMethod(typeof(Il2Cpp.BtlCommandManager.CommandInfo),
            "NativeMethodInfoPtr_Clear_Public_Void_0",
            out _commandInfoClearPtr, out _commandInfoClearMi, "CommandInfo.Clear");
        try
        {
            _commandInfoClass = Il2CppClassPointerStore<Il2Cpp.BtlCommandManager.CommandInfo>.NativeClassPtr;
            if (_commandInfoClass != 0) Log($"CommandInfo class @ 0x{_commandInfoClass:X}");
        }
        catch { }

        // Resolve GetGameData via RVA
        try
        {
            var proc = System.Diagnostics.Process.GetCurrentProcess();
            foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
            {
                if (mod.ModuleName != null &&
                    mod.ModuleName.Equals("GameAssembly.dll", System.StringComparison.OrdinalIgnoreCase))
                {
                    _getGameData = Marshal.GetDelegateForFunctionPointer<d_GetGameData>(
                        mod.BaseAddress + (nint)RVA_GET_GAME_DATA);
                    Log("GetGameData resolved via RVA");
                    break;
                }
            }
        }
        catch (System.Exception ex) { Warn($"GetGameData failed: {ex.Message}"); }

        // Resolve STLVector<CommandInfo> clear/push_back method infos
        // These are referenced by BackupCommand. We resolve them from the CppUtil type.
        ResolveCppUtilVectorMethods();

        // Hook CanAutoPlay — bypass empty tactic check so our rules fire
        try
        {
            var canAutoField = typeof(Il2Cpp.BtlGUIAutoWindow).GetField(
                "NativeMethodInfoPtr_CanAutoPlay_Public_Static_Boolean_Int32_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (canAutoField != null)
            {
                var canAutoMi = (nint)canAutoField.GetValue(null);
                if (canAutoMi != 0)
                {
                    var canAutoNative = *(nint*)canAutoMi;
                    _pinnedCanAutoPlay = CanAutoPlay_Hook;
                    _canAutoPlayHook = new NativeHook<d_CanAutoPlay>(canAutoNative,
                        Marshal.GetFunctionPointerForDelegate(_pinnedCanAutoPlay));
                    _canAutoPlayHook.Attach();
                    Log($"CanAutoPlay hooked @ 0x{canAutoNative:X}");
                }
            }
            else Log("CanAutoPlay field not found");
        }
        catch (System.Exception ex) { Log($"CanAutoPlay hook failed: {ex.Message}"); }

        // Hook TacticsNameListImpl.get_Item — show profile names in tactics UI
        try
        {
            var nameType = typeof(Il2Cpp.BtlCommandRecorder).GetNestedType("TacticsNameListImpl");
            if (nameType != null)
            {
                var nameField = nameType.GetField(
                    "NativeMethodInfoPtr_get_Item_Public_String_Int32_0",
                    System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
                if (nameField != null)
                {
                    var nameMi = (nint)nameField.GetValue(null);
                    if (nameMi != 0)
                    {
                        var nameNative = *(nint*)nameMi;
                        _pinnedGetTacticsName = GetTacticsName_Hook;
                        _getTacticsNameHook = new NativeHook<d_GetTacticsName>(nameNative,
                            Marshal.GetFunctionPointerForDelegate(_pinnedGetTacticsName));
                        _getTacticsNameHook.Attach();
                        Log($"TacticsNameList.get_Item hooked @ 0x{nameNative:X}");
                    }
                }
            }
            else Log("TacticsNameListImpl type not found");
        }
        catch (System.Exception ex) { Log($"TacticsName hook failed: {ex.Message}"); }

        // Hook SetAutoPanel — replace command plates with rule descriptions
        try
        {
            ResolveMethod(typeof(Il2Cpp.BtlGUIAutoWindow),
                "NativeMethodInfoPtr_SetAutoPanel_Public_Void_Int32_0",
                out var sapPtr, out var sapMi, "SetAutoPanel");
            if (sapPtr != 0)
            {
                _pinnedSetAutoPanel = SetAutoPanel_Hook;
                _setAutoPanelHook = new NativeHook<d_SetAutoPanel>(sapPtr,
                    Marshal.GetFunctionPointerForDelegate(_pinnedSetAutoPanel));
                _setAutoPanelHook.Attach();
                Log($"SetAutoPanel hooked @ 0x{sapPtr:X}");
            }
        }
        catch (System.Exception ex) { Log($"SetAutoPanel hook failed: {ex.Message}"); }

        // Resolve AutoWindowAddCommandPlate (5-arg overload with string name + icon)
        ResolveMethod(typeof(Il2Cpp.BtlGUIAutoWindow),
            "NativeMethodInfoPtr_AutoWindowAddCommandPlate_Public_Void_Int32_String_String_Boolean_0",
            out var acpPtr, out _addCommandPlate_mi, "AddCommandPlate");
        if (acpPtr != 0)
            _addCommandPlate = Marshal.GetDelegateForFunctionPointer<d_AddCommandPlate>(acpPtr);

        // Resolve AutoPanelClear
        ResolveMethod(typeof(Il2Cpp.BtlGUIAutoWindow),
            "NativeMethodInfoPtr_AutoPanelClear_Public_Void_0",
            out var apcPtr, out _autoPanelClear_mi, "AutoPanelClear");
        if (apcPtr != 0)
            _autoPanelClear = Marshal.GetDelegateForFunctionPointer<d_AutoPanelClear>(apcPtr);

        Log("AutoBattle (Approach A) ready");
    }

    private static void ResolveCppUtilVectorMethods()
    {
        try
        {
            // Find CppUtil.STLVector`1 generic type, then make it with CommandInfo
            var cppUtilType = typeof(Il2Cpp.BtlCommandManager).Assembly.GetType("Il2Cpp.CppUtil");
            System.Type vecType = null;

            if (cppUtilType != null)
            {
                foreach (var nested in cppUtilType.GetNestedTypes(
                    System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic))
                {
                    if (nested.Name.StartsWith("STLVector") && nested.IsGenericTypeDefinition)
                    {
                        Log($"Found generic: {nested.FullName}");
                        vecType = nested.MakeGenericType(typeof(Il2Cpp.BtlCommandManager.CommandInfo));
                        Log($"Instantiated: {vecType.FullName}");
                        break;
                    }
                }
            }

            if (vecType == null)
            {
                Log("STLVector<CommandInfo> type not found");
                return;
            }

            // Search ALL fields for clear and push_back NativeMethodInfoPtrs
            var fields = vecType.GetFields(
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public);
            foreach (var f in fields)
            {
                if (f.Name.Contains("clear") && f.Name.Contains("NativeMethodInfoPtr"))
                {
                    _vectorClearMi = (nint)f.GetValue(null);
                    if (_vectorClearMi != 0)
                    {
                        _vectorClear = Marshal.GetDelegateForFunctionPointer<d_VectorClear>(*(nint*)_vectorClearMi);
                        Log($"STLVector.clear resolved via {f.Name}");
                    }
                }
                else if (f.Name.Contains("push_back") && f.Name.Contains("NativeMethodInfoPtr"))
                {
                    _vectorPushBackMi = (nint)f.GetValue(null);
                    if (_vectorPushBackMi != 0)
                    {
                        _vectorPushBack = Marshal.GetDelegateForFunctionPointer<d_VectorPushBack>(*(nint*)_vectorPushBackMi);
                        Log($"STLVector.push_back resolved via {f.Name}");
                    }
                }
            }
        }
        catch (System.Exception ex) { Log($"STLVector resolve: {ex.Message}"); }

        // RVA fallback for generic shared implementations
        if (_vectorClear == null || _vectorPushBack == null)
        {
            Log("Trying RVA fallback for STLVector methods");
            try
            {
                var proc = System.Diagnostics.Process.GetCurrentProcess();
                foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
                {
                    if (mod.ModuleName != null &&
                        mod.ModuleName.Equals("GameAssembly.dll", System.StringComparison.OrdinalIgnoreCase))
                    {
                        nint baseAddr = mod.BaseAddress;
                        if (_vectorClear == null)
                        {
                            // CppUtil.STLVector<object>.clear @ 0x180EA5850
                            _vectorClear = Marshal.GetDelegateForFunctionPointer<d_VectorClear>(
                                baseAddr + (nint)0xEA5850);
                            Log("STLVector.clear resolved via RVA");
                        }
                        if (_vectorPushBack == null)
                        {
                            // CppUtil.STLVector<object>.push_back @ 0x180EA6C40
                            _vectorPushBack = Marshal.GetDelegateForFunctionPointer<d_VectorPushBack>(
                                baseAddr + (nint)0xEA6C40);
                            Log("STLVector.push_back resolved via RVA");
                        }
                        break;
                    }
                }
            }
            catch (System.Exception ex) { Log($"STLVector RVA fallback: {ex.Message}"); }
        }

        if (_vectorClear == null || _vectorPushBack == null)
            Log("STLVector methods STILL not resolved — will fall back to vanilla repeat");
    }

    // ── Main hook ────────────────────────────────────────────────

    private static void ProcessAutoBattle_Hook(nint instance, int commandIndex, nint methodInfo)
    {
        try
        {
            // Always have the trampoline as our safety net
            if (_vectorClear == null || _vectorPushBack == null || _commandInfoClass == 0)
            {
                _processHook.Trampoline(instance, commandIndex, methodInfo);
                return;
            }

            // Read battle state
            var battleState = BattleState.ReadBattleState(instance);
            if (battleState == null)
            {
                _processHook.Trampoline(instance, commandIndex, methodInfo);
                return;
            }

            // Get the recorder
            nint recorder = GetRecorder();
            if (recorder == 0)
            {
                _processHook.Trampoline(instance, commandIndex, methodInfo);
                return;
            }

            var battle = battleState.Value;
            bool injected = false;

            // Inject commands into repeat storage for each character
            for (int i = 0; i < battle.Players.Length && i < 4; i++)
            {
                var player = battle.Players[i];
                if (player.IsDead) continue;

                var actions = _ruleEngine.EvaluateForCharacter(i, battle);
                if (actions == null || actions.Count == 0) continue;

                // player.Index IS the array index (0-3 for players)
                int arrayIdx = player.Index;
                if (arrayIdx < 0 || arrayIdx >= 4) continue;

                // Get the STLVector for this character from recorder+0x20
                nint vectorArray = *(nint*)(recorder + OFF_RECORDER_VECTORS);
                if (vectorArray == 0) continue;
                if (arrayIdx >= *(int*)(vectorArray + 0x18)) continue; // bounds check
                nint vector = *(nint*)(vectorArray + 0x20 + arrayIdx * 8);
                if (vector == 0) continue;

                // Clear existing commands in this vector
                _vectorClear(vector, _vectorClearMi);

                // Push our commands
                foreach (var action in actions)
                {
                    nint cmd = AllocCommandInfo();
                    if (cmd == 0) break;

                    FillCommandInfo(cmd, arrayIdx, action);
                    _vectorPushBack(vector, cmd, _vectorPushBackMi);
                }

                // Clear the flag at recorder+0x28 so PlaybackRecords uses our commands
                nint flagArray = *(nint*)(recorder + OFF_RECORDER_FLAGS);
                if (flagArray != 0 && arrayIdx < *(int*)(flagArray + 0x18))
                    *(byte*)(flagArray + 0x20 + arrayIdx) = 0;

                injected = true;
                _logCount++;
                if (_logCount <= MaxLogs)
                    Log($"Player {i} (idx={arrayIdx}): {actions.Count} commands injected");
            }

            // Set repeat mode so PlaybackRecords reads from our vectors
            if (injected)
                *(int*)(recorder + OFF_RECORDER_MODE) = -1;

            // ALWAYS call trampoline — it runs PlaybackRecords + EndWaitTurnPhase
            _processHook.Trampoline(instance, commandIndex, methodInfo);
        }
        catch (System.Exception ex)
        {
            _logCount++;
            if (_logCount <= 10) Warn($"Hook error: {ex.Message}");
            try { _processHook.Trampoline(instance, commandIndex, methodInfo); } catch { }
        }
    }

    // ── CommandInfo building ──────────────────────────────────────

    private static nint AllocCommandInfo()
    {
        if (_commandInfoClass == 0 || _commandInfoCtorPtr == 0) return 0;
        try
        {
            nint obj = IL2CPP.il2cpp_object_new(_commandInfoClass);
            if (obj == 0) return 0;
            var ctor = (delegate* unmanaged[Cdecl]<nint, nint, void>)_commandInfoCtorPtr;
            ctor(obj, _commandInfoCtorMi);
            return obj;
        }
        catch { return 0; }
    }

    private static void FillCommandInfo(nint cmd, int charaArrayIdx, ResolvedAction action)
    {
        // Clear first
        if (_commandInfoClearPtr != 0)
        {
            var clear = (delegate* unmanaged[Cdecl]<nint, nint, void>)_commandInfoClearPtr;
            clear(cmd, _commandInfoClearMi);
        }

        *(int*)(cmd + OFF_OWNER_INDEX) = charaArrayIdx;
        *(int*)(cmd + OFF_CHARA_IDX) = charaArrayIdx;
        *(int*)(cmd + OFF_AP_COST) = 1; // ALWAYS 1 for normal commands

        switch (action.Type)
        {
            case ActionType.Attack:
                *(int*)(cmd + OFF_COMMAND_TYPE) = CMD_FIGHT;
                *(int*)(cmd + OFF_TARGET_TYPE) = 1; // single target
                *(byte*)(cmd + OFF_IS_TARGET_ENEMY) = action.IsTargetEnemy ? (byte)1 : (byte)0;
                SetTarget(cmd, action.TargetIndex);
                break;

            case ActionType.Ability:
                *(int*)(cmd + OFF_COMMAND_TYPE) = CMD_MAGIC; // PlaybackRecords validates and may convert
                *(int*)(cmd + OFF_COMMAND_SUB_TYPE) = action.AbilityId;
                *(byte*)(cmd + OFF_IS_TARGET_ENEMY) = action.IsTargetEnemy ? (byte)1 : (byte)0;
                *(int*)(cmd + OFF_TARGET_TYPE) = action.IsTargetEnemy ? 1 : 1; // single target
                SetTarget(cmd, action.TargetIndex);
                break;

            case ActionType.Guard:
                *(int*)(cmd + OFF_COMMAND_TYPE) = CMD_GUARD;
                *(int*)(cmd + OFF_TARGET_TYPE) = 1;
                *(byte*)(cmd + OFF_IS_TARGET_ENEMY) = 0;
                SetTarget(cmd, charaArrayIdx);
                break;

            case ActionType.Item:
                *(int*)(cmd + OFF_COMMAND_TYPE) = CMD_ITEM;
                *(int*)(cmd + OFF_COMMAND_SUB_TYPE) = action.ItemId;
                *(byte*)(cmd + OFF_IS_TARGET_ENEMY) = action.IsTargetEnemy ? (byte)1 : (byte)0;
                *(int*)(cmd + OFF_TARGET_TYPE) = 1;
                SetTarget(cmd, action.TargetIndex);
                break;

            default:
                // Default to attack weakest
                *(int*)(cmd + OFF_COMMAND_TYPE) = CMD_FIGHT;
                *(int*)(cmd + OFF_TARGET_TYPE) = 1;
                *(byte*)(cmd + OFF_IS_TARGET_ENEMY) = 1;
                SetTarget(cmd, action.TargetIndex);
                break;
        }
    }

    private static void SetTarget(nint cmd, int targetIndex)
    {
        nint idxList = *(nint*)(cmd + OFF_TARGET_IDX_LIST);
        if (idxList != 0)
        {
            *(int*)(idxList + 0x18) = 1; // num = 1
            nint array = *(nint*)(idxList + 0x10);
            if (array != 0)
                *(int*)(array + 0x20) = targetIndex; // elements[0]
        }
    }

    // ── Helpers ───────────────────────────────────────────────────

    private static nint GetRecorder()
    {
        if (_getGameData == null) return 0;
        try
        {
            nint gameData = _getGameData(_getGameData_mi);
            if (gameData == 0) return 0;
            return *(nint*)(gameData + 0xE8);
        }
        catch { return 0; }
    }

    private static void ResolveMethod(System.Type type, string fieldName,
        out nint funcPtr, out nint miPtr, string label)
    {
        funcPtr = 0; miPtr = 0;
        try
        {
            var field = type.GetField(fieldName,
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Log($"{label}: field not found"); return; }
            miPtr = (nint)field.GetValue(null);
            if (miPtr == 0) { Log($"{label}: null MI"); return; }
            funcPtr = *(nint*)miPtr;
            Log($"{label} resolved @ 0x{funcPtr:X}");
        }
        catch (System.Exception ex) { Log($"{label}: {ex.Message}"); }
    }

    // ── SetAutoPanel hook — show rules as command plates ────────────

    private static void SetAutoPanel_Hook(nint instance, int panelIndex, nint methodInfo)
    {
        // Try to show our rules; fall back to original if anything fails
        if (_addCommandPlate == null || _autoPanelClear == null)
        {
            try { _setAutoPanelHook.Trampoline(instance, panelIndex, methodInfo); } catch { }
            return;
        }

        try
        {
            // Store the panel index on the instance (+0xC0)
            *(int*)(instance + 0xC0) = panelIndex;

            // Clear existing plates
            _autoPanelClear(instance, _autoPanelClear_mi);

            // Determine which profile to show
            // panelIndex: -1 = repeat/active profile, 0-3 = tactic slots
            int profileIdx = panelIndex < 0 ? _ruleEngine.ActiveProfileIndex : panelIndex;

            RuleProfile profile = null;
            if (profileIdx >= 0 && profileIdx < _ruleEngine.ProfileNames.Count)
            {
                string name = _ruleEngine.ProfileNames[profileIdx];
                _ruleEngine.AllProfiles.TryGetValue(name, out profile);
            }
            profile ??= _ruleEngine.DefaultProfile;

            if (profile == null || profile.Rules.Count == 0)
            {
                // Show "No rules" for empty profiles
                nint emptyStr = Il2CppInterop.Runtime.IL2CPP.ManagedStringToIl2Cpp("(no rules)");
                nint iconStr = Il2CppInterop.Runtime.IL2CPP.ManagedStringToIl2Cpp("");
                for (int c = 0; c < 4; c++)
                    _addCommandPlate(instance, c, emptyStr, iconStr, 1, _addCommandPlate_mi);
                return;
            }

            // Show up to 4 rules as plates (one per character row)
            int ruleCount = System.Math.Min(profile.Rules.Count, 4);
            for (int i = 0; i < ruleCount; i++)
            {
                string ruleText = profile.Rules[i].ToShortString();
                nint nameStr = Il2CppInterop.Runtime.IL2CPP.ManagedStringToIl2Cpp(ruleText);
                nint iconStr = Il2CppInterop.Runtime.IL2CPP.ManagedStringToIl2Cpp("");
                _addCommandPlate(instance, i, nameStr, iconStr, 1, _addCommandPlate_mi);
            }

            _logCount++;
            if (_logCount <= MaxLogs)
                Log($"SetAutoPanel({panelIndex}): showing {ruleCount} rules from '{profile.Name}'");
        }
        catch (System.Exception ex)
        {
            _logCount++;
            if (_logCount <= 5) Log($"SetAutoPanel error: {ex.Message}");
            // Fall back to original
            try { _setAutoPanelHook.Trampoline(instance, panelIndex, methodInfo); } catch { }
        }
    }

    // ── CanAutoPlay hook — always return true so ProcessAutoBattle fires ──

    private static byte CanAutoPlay_Hook(int playingCommand, nint methodInfo)
    {
        // Always return true — our ProcessAutoBattle hook handles the logic
        // The original checks if recorded commands are still valid, but we
        // inject our own commands so it doesn't matter
        _logCount++;
        if (_logCount <= MaxLogs) Log($"CanAutoPlay({playingCommand}) -> true (forced)");
        return 1;
    }

    // ── TacticsNameList hook — show profile names in tactics UI ──────

    private static nint GetTacticsName_Hook(nint instance, int index, nint methodInfo)
    {
        try
        {
            // Map tactic index to our profile names
            if (index >= 0 && index < _ruleEngine.ProfileNames.Count)
            {
                string name = _ruleEngine.ProfileNames[index];
                return Il2CppInterop.Runtime.IL2CPP.ManagedStringToIl2Cpp(name);
            }
        }
        catch { }

        // Fall back to original
        try { return _getTacticsNameHook.Trampoline(instance, index, methodInfo); }
        catch { return 0; }
    }

    private static void Log(string msg) => Melon<Core>.Logger.Msg($"[AutoBattle] {msg}");
    private static void Warn(string msg) => Melon<Core>.Logger.Warning($"[AutoBattle] {msg}");
}
