using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;
using MelonLoader.Utils;
using BravelyMod.AutoBattle;
using Il2CppInterop.Runtime;

namespace BravelyMod.Patches;

/// <summary>
/// Native hook on BtlLayoutCtrl.ProcessAutoBattle.
/// Replaces the simple record-playback with the conditional rule engine.
/// Supports Attack, Ability/Magic, Guard, and Item commands via SendCommand.
/// Falls back to original behavior if rule evaluation fails.
/// </summary>
public static unsafe class NativeAutoBattlePatch
{
    // void ProcessAutoBattle(BtlLayoutCtrl* this, int commandIndex, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_ProcessAutoBattle(nint instance, int commandIndex, nint methodInfo);

    // void AddAttackCommand(BtlCommandRecorder* this, BtlLayoutCtrl* layout, int charaIndex, int targetIndex, bool isTargetEnemy, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddAttackCommand(nint recorderThis, nint btlLayoutCtrl, int charaIndex, int targetIndex, byte isTargetEnemy, nint methodInfo);

    // void SendCommand(BtlCommandRecorder* this, BtlLayoutCtrl* layout, int charaIndex, CommandInfo* command, bool IsRemoveBp, bool ChangeSerial, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SendCommand(nint recorderThis, nint btlLayoutCtrl, int charaIndex, nint commandInfo, byte isRemoveBp, byte changeSerial, nint methodInfo);

    // Hikari* get_GameData(MethodInfo*) — static, returns GameData singleton
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_GetGameData(nint methodInfo);

    // void CommandInfo..ctor(CommandInfo* this, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_CommandInfoCtor(nint thisPtr, nint methodInfo);

    // void CommandInfo.Clear(CommandInfo* this, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_CommandInfoClear(nint thisPtr, nint methodInfo);

    private static NativeHook<d_ProcessAutoBattle> _processHook;
    private static d_ProcessAutoBattle _pinnedProcess;

    // Cached function pointer for AddAttackCommand (instance method on BtlCommandRecorder)
    private static nint _addAttackCommandPtr;
    private static nint _addAttackCommandMethodInfo;

    // Cached function pointer for SendCommand (instance method on BtlCommandRecorder)
    private static nint _sendCommandPtr;
    private static nint _sendCommandMethodInfo;

    // Cached function pointer for Hikari.get_GameData (static)
    private static nint _getGameDataPtr;
    private static nint _getGameDataMethodInfo;

    // Cached function pointer for CommandInfo..ctor (instance)
    private static nint _commandInfoCtorPtr;
    private static nint _commandInfoCtorMethodInfo;

    // Cached function pointer for CommandInfo.Clear (instance)
    private static nint _commandInfoClearPtr;
    private static nint _commandInfoClearMethodInfo;

    // IL2CPP class pointer for CommandInfo (for object allocation)
    private static nint _commandInfoClass;

    // ── CommandInfo field offsets (from il2cpp dump) ──────────────
    private const int OFF_CMD_OWNERINDEX     = 0x10;
    private const int OFF_CMD_CHARAIDX       = 0x14;
    private const int OFF_CMD_SERIALNUMBER   = 0x18;
    private const int OFF_CMD_APTYPE         = 0x1C;
    private const int OFF_CMD_COMMANDTYPE    = 0x28;
    private const int OFF_CMD_COMMANDSUBTYPE = 0x2C;
    private const int OFF_CMD_COMMANDSUBINDEX = 0x30;
    private const int OFF_CMD_TARGETTYPE     = 0x34;
    private const int OFF_CMD_TARGETIDXLIST  = 0x38;
    private const int OFF_CMD_APCOST         = 0x60;
    private const int OFF_CMD_ISTARGETENEMY  = 0x68;

    // ── BtlCommandManager command type constants ─────────────────
    private const int COMMAND_TYPE_NONE    = 0;
    private const int COMMAND_TYPE_FIGHT   = 1;
    private const int COMMAND_TYPE_MAGIC   = 2;
    private const int COMMAND_TYPE_ABILITY = 3;
    private const int COMMAND_TYPE_ITEM    = 4;
    private const int COMMAND_TYPE_GUARD   = 5;

    // ── BTLDEF.CommandTargetType ─────────────────────────────────
    private const int CMD_TARGET_ENEMY      = 0;
    private const int CMD_TARGET_FRIEND     = 1;
    private const int CMD_TARGET_ENEMY_ALL  = 2;
    private const int CMD_TARGET_FRIEND_ALL = 3;

    // ── GameData -> BtlCommandRecorder offset ────────────────────
    private const int OFF_GAMEDATA_RECORDER = 0xE8;

    // ── BtlCharaIdxList field offsets ────────────────────────────
    private const int OFF_IDXLIST_ARRAY = 0x10;
    private const int OFF_IDXLIST_NUM   = 0x18;
    private const int OFF_ARRAY_DATA    = 0x20;

    private static readonly RuleEngine _ruleEngine = new();

    private static int _logCount = 0;
    private const int MaxLogLines = 40;

    /// <summary>
    /// Config file location — next to MelonPreferences.cfg in UserData/.
    /// </summary>
    public static string ConfigPath =>
        Path.Combine(MelonEnvironment.UserDataDirectory, "BravelyMod_AutoBattle.yaml");

    /// <summary>
    /// Access the rule engine for external configuration.
    /// </summary>
    public static RuleEngine RuleEngine => _ruleEngine;

    public static void Apply()
    {
        // Load profiles from config (creates default file if missing)
        ProfileConfig.LoadInto(ConfigPath, _ruleEngine);

        HookProcessAutoBattle();
        ResolveAddAttackCommand();
        ResolveSendCommand();
        ResolveCommandInfoHelpers();
        ResolveGetGameData();
    }

    // ── Hook setup ───────────────────────────────────────────────

    private static void HookProcessAutoBattle()
    {
        try
        {
            var field = typeof(Il2Cpp.BtlLayoutCtrl).GetField(
                "NativeMethodInfoPtr_ProcessAutoBattle_Public_Void_Int32_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null)
            {
                Melon<Core>.Logger.Warning("[AutoBattle] ProcessAutoBattle field not found");
                return;
            }

            var mi = (nint)field.GetValue(null);
            if (mi == 0)
            {
                Melon<Core>.Logger.Warning("[AutoBattle] ProcessAutoBattle method info ptr is null");
                return;
            }

            var native = *(nint*)mi;
            Melon<Core>.Logger.Msg($"[AutoBattle] ProcessAutoBattle native @ 0x{native:X}");

            _pinnedProcess = ProcessAutoBattle_Hook;
            var hookPtr = Marshal.GetFunctionPointerForDelegate(_pinnedProcess);
            _processHook = new NativeHook<d_ProcessAutoBattle>(native, hookPtr);
            _processHook.Attach();
            Melon<Core>.Logger.Msg("[AutoBattle] ProcessAutoBattle hook attached!");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"[AutoBattle] ProcessAutoBattle hook failed: {ex.Message}");
        }
    }

    private static void ResolveAddAttackCommand()
    {
        ResolveNativeMethod(
            typeof(Il2Cpp.BtlCommandRecorder),
            "NativeMethodInfoPtr_AddAttackCommand_Public_Void_BtlLayoutCtrl_Int32_Int32_Boolean_0",
            "AddAttackCommand",
            out _addAttackCommandPtr, out _addAttackCommandMethodInfo);
    }

    private static void ResolveSendCommand()
    {
        ResolveNativeMethod(
            typeof(Il2Cpp.BtlCommandRecorder),
            "NativeMethodInfoPtr_SendCommand_Public_Void_BtlLayoutCtrl_Int32_CommandInfo_Boolean_Boolean_0",
            "SendCommand",
            out _sendCommandPtr, out _sendCommandMethodInfo);
    }

    private static void ResolveCommandInfoHelpers()
    {
        // Resolve CommandInfo default .ctor
        ResolveNativeMethod(
            typeof(Il2Cpp.BtlCommandManager.CommandInfo),
            "NativeMethodInfoPtr__ctor_Public_Void_0",
            "CommandInfo.ctor",
            out _commandInfoCtorPtr, out _commandInfoCtorMethodInfo);

        // Resolve CommandInfo.Clear
        ResolveNativeMethod(
            typeof(Il2Cpp.BtlCommandManager.CommandInfo),
            "NativeMethodInfoPtr_Clear_Public_Void_0",
            "CommandInfo.Clear",
            out _commandInfoClearPtr, out _commandInfoClearMethodInfo);

        // Get the IL2CPP class pointer for CommandInfo (for il2cpp_object_new)
        try
        {
            _commandInfoClass = Il2CppClassPointerStore<Il2Cpp.BtlCommandManager.CommandInfo>.NativeClassPtr;
            if (_commandInfoClass != 0)
                Melon<Core>.Logger.Msg($"[AutoBattle] CommandInfo IL2CPP class @ 0x{_commandInfoClass:X}");
            else
                Melon<Core>.Logger.Warning("[AutoBattle] CommandInfo IL2CPP class pointer is null");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"[AutoBattle] CommandInfo class resolve failed: {ex.Message}");
        }
    }

    private static void ResolveGetGameData()
    {
        ResolveNativeMethod(
            typeof(Il2Cpp.Hikari),
            "NativeMethodInfoPtr_get_GameData_Public_Static_get_Hikari_0",
            "Hikari.get_GameData",
            out _getGameDataPtr, out _getGameDataMethodInfo);
    }

    /// <summary>
    /// Helper to resolve a NativeMethodInfoPtr field and extract the native function pointer.
    /// </summary>
    private static void ResolveNativeMethod(System.Type type, string fieldName, string label,
        out nint funcPtr, out nint methodInfoPtr)
    {
        funcPtr = 0;
        methodInfoPtr = 0;
        try
        {
            var field = type.GetField(fieldName,
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null)
            {
                Melon<Core>.Logger.Warning($"[AutoBattle] {label}: field '{fieldName}' not found");
                return;
            }

            var mi = (nint)field.GetValue(null);
            if (mi == 0)
            {
                Melon<Core>.Logger.Warning($"[AutoBattle] {label}: method info ptr is null");
                return;
            }

            funcPtr = *(nint*)mi;
            methodInfoPtr = mi;
            Melon<Core>.Logger.Msg($"[AutoBattle] {label} resolved @ 0x{funcPtr:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"[AutoBattle] {label} resolve failed: {ex.Message}");
        }
    }

    // ── BtlCommandRecorder instance retrieval ────────────────────

    /// <summary>
    /// Gets the BtlCommandRecorder instance from the GameData singleton.
    /// Chain: Hikari.get_GameData() -> GameData.m_CommandRecorder (offset 0xE8)
    /// </summary>
    private static nint GetCommandRecorder()
    {
        if (_getGameDataPtr == 0) return 0;

        try
        {
            var fn = (delegate* unmanaged[Cdecl]<nint, nint>)_getGameDataPtr;
            nint gameData = fn(_getGameDataMethodInfo);
            if (gameData == 0) return 0;

            nint recorder = *(nint*)(gameData + OFF_GAMEDATA_RECORDER);
            return recorder;
        }
        catch
        {
            return 0;
        }
    }

    // ── CommandInfo IL2CPP object creation ────────────────────────

    /// <summary>
    /// Allocate a new CommandInfo IL2CPP object and call its default constructor.
    /// The constructor initializes sub-objects (BtlCharaIdxList, etc.).
    /// </summary>
    private static nint AllocateCommandInfo()
    {
        if (_commandInfoClass == 0 || _commandInfoCtorPtr == 0) return 0;

        try
        {
            // Allocate the IL2CPP object
            nint obj = IL2CPP.il2cpp_object_new(_commandInfoClass);
            if (obj == 0) return 0;

            // Call the default constructor to initialize sub-objects
            var ctor = (delegate* unmanaged[Cdecl]<nint, nint, void>)_commandInfoCtorPtr;
            ctor(obj, _commandInfoCtorMethodInfo);

            return obj;
        }
        catch (System.Exception ex)
        {
            if (_logCount < MaxLogLines)
            {
                Melon<Core>.Logger.Warning($"[AutoBattle] CommandInfo allocation failed: {ex.Message}");
                _logCount++;
            }
            return 0;
        }
    }

    /// <summary>
    /// Clear a CommandInfo object (reset all fields to defaults).
    /// </summary>
    private static void ClearCommandInfo(nint cmdInfo)
    {
        if (cmdInfo == 0 || _commandInfoClearPtr == 0) return;

        var fn = (delegate* unmanaged[Cdecl]<nint, nint, void>)_commandInfoClearPtr;
        fn(cmdInfo, _commandInfoClearMethodInfo);
    }

    /// <summary>
    /// Set up a CommandInfo for an ability/magic command.
    /// </summary>
    private static void SetupAbilityCommand(nint cmdInfo, int charaIndex, int commandType,
        int abilitySubType, int targetIndex, bool isTargetEnemy)
    {
        // Clear first to reset all fields
        ClearCommandInfo(cmdInfo);

        // Set the command fields
        *(int*)(cmdInfo + OFF_CMD_OWNERINDEX)     = charaIndex;
        *(int*)(cmdInfo + OFF_CMD_CHARAIDX)       = charaIndex;
        *(int*)(cmdInfo + OFF_CMD_COMMANDTYPE)    = commandType;
        *(int*)(cmdInfo + OFF_CMD_COMMANDSUBTYPE) = abilitySubType;
        *(int*)(cmdInfo + OFF_CMD_COMMANDSUBINDEX) = 0;
        *(byte*)(cmdInfo + OFF_CMD_ISTARGETENEMY) = isTargetEnemy ? (byte)1 : (byte)0;

        // Set target type based on targeting
        int targetType = isTargetEnemy ? CMD_TARGET_ENEMY : CMD_TARGET_FRIEND;
        *(int*)(cmdInfo + OFF_CMD_TARGETTYPE) = targetType;

        // Set the target in the BtlCharaIdxList
        nint idxList = *(nint*)(cmdInfo + OFF_CMD_TARGETIDXLIST);
        if (idxList != 0)
        {
            // Set num = 1
            *(int*)(idxList + OFF_IDXLIST_NUM) = 1;

            // Set idxList[0] = targetIndex
            nint array = *(nint*)(idxList + OFF_IDXLIST_ARRAY);
            if (array != 0)
            {
                *(int*)(array + OFF_ARRAY_DATA) = targetIndex;
            }
        }
    }

    /// <summary>
    /// Set up a CommandInfo for a guard command.
    /// </summary>
    private static void SetupGuardCommand(nint cmdInfo, int charaIndex)
    {
        ClearCommandInfo(cmdInfo);

        *(int*)(cmdInfo + OFF_CMD_OWNERINDEX)     = charaIndex;
        *(int*)(cmdInfo + OFF_CMD_CHARAIDX)       = charaIndex;
        *(int*)(cmdInfo + OFF_CMD_COMMANDTYPE)    = COMMAND_TYPE_GUARD;
        *(int*)(cmdInfo + OFF_CMD_COMMANDSUBTYPE) = 0;
        *(int*)(cmdInfo + OFF_CMD_COMMANDSUBINDEX) = 0;
        *(byte*)(cmdInfo + OFF_CMD_ISTARGETENEMY) = 0;
        *(int*)(cmdInfo + OFF_CMD_TARGETTYPE)     = CMD_TARGET_FRIEND;

        // Target self
        nint idxList = *(nint*)(cmdInfo + OFF_CMD_TARGETIDXLIST);
        if (idxList != 0)
        {
            *(int*)(idxList + OFF_IDXLIST_NUM) = 1;
            nint array = *(nint*)(idxList + OFF_IDXLIST_ARRAY);
            if (array != 0)
                *(int*)(array + OFF_ARRAY_DATA) = charaIndex;
        }
    }

    /// <summary>
    /// Set up a CommandInfo for an item command.
    /// </summary>
    private static void SetupItemCommand(nint cmdInfo, int charaIndex, int itemId,
        int targetIndex, bool isTargetEnemy)
    {
        ClearCommandInfo(cmdInfo);

        *(int*)(cmdInfo + OFF_CMD_OWNERINDEX)     = charaIndex;
        *(int*)(cmdInfo + OFF_CMD_CHARAIDX)       = charaIndex;
        *(int*)(cmdInfo + OFF_CMD_COMMANDTYPE)    = COMMAND_TYPE_ITEM;
        *(int*)(cmdInfo + OFF_CMD_COMMANDSUBTYPE) = itemId;
        *(int*)(cmdInfo + OFF_CMD_COMMANDSUBINDEX) = 0;
        *(byte*)(cmdInfo + OFF_CMD_ISTARGETENEMY) = isTargetEnemy ? (byte)1 : (byte)0;

        int targetType = isTargetEnemy ? CMD_TARGET_ENEMY : CMD_TARGET_FRIEND;
        *(int*)(cmdInfo + OFF_CMD_TARGETTYPE) = targetType;

        nint idxList = *(nint*)(cmdInfo + OFF_CMD_TARGETIDXLIST);
        if (idxList != 0)
        {
            *(int*)(idxList + OFF_IDXLIST_NUM) = 1;
            nint array = *(nint*)(idxList + OFF_IDXLIST_ARRAY);
            if (array != 0)
                *(int*)(array + OFF_ARRAY_DATA) = targetIndex;
        }
    }

    // ── Main hook ────────────────────────────────────────────────

    private static void ProcessAutoBattle_Hook(nint instance, int commandIndex, nint methodInfo)
    {
        try
        {
            // Read battle state from pointers
            var battleState = BattleState.ReadBattleState(instance);
            if (battleState == null)
            {
                if (_logCount < MaxLogLines)
                {
                    Melon<Core>.Logger.Warning("[AutoBattle] Could not read battle state, falling back to original");
                    _logCount++;
                }
                _processHook.Trampoline(instance, commandIndex, methodInfo);
                return;
            }

            var battle = battleState.Value;
            bool anyRuleApplied = false;

            // Get the BtlCommandRecorder instance for SendCommand calls
            nint recorder = GetCommandRecorder();

            // Check if SendCommand infrastructure is available
            bool hasSendCommand = (_sendCommandPtr != 0 && recorder != 0 && _commandInfoClass != 0 && _commandInfoCtorPtr != 0);

            // Evaluate rules for each living player character
            for (int i = 0; i < battle.Players.Length; i++)
            {
                var player = battle.Players[i];
                if (player.IsDead) continue;

                var resolvedActions = _ruleEngine.EvaluateForCharacter(i, battle);
                if (resolvedActions == null || resolvedActions.Count == 0) continue;

                // Submit each action in the matched rule
                foreach (var action in resolvedActions)
                {
                    switch (action.Type)
                    {
                        case ActionType.Attack:
                            if (SubmitAttackCommand(instance, recorder, player.Index, action.TargetIndex, action.IsTargetEnemy))
                            {
                                anyRuleApplied = true;
                                LogAction(player.Index, $"Attack target {action.TargetIndex} (enemy={action.IsTargetEnemy})");
                            }
                            break;

                        case ActionType.Ability:
                            if (hasSendCommand)
                            {
                                nint cmdInfo = AllocateCommandInfo();
                                if (cmdInfo != 0)
                                {
                                    // The game uses commandType MAGIC(2) for white/black/time magic,
                                    // ABILITY(3) for job-specific abilities.
                                    // The abilityId from the DSL is the commandSubType (ability table index).
                                    int cmdType = COMMAND_TYPE_MAGIC;
                                    SetupAbilityCommand(cmdInfo, player.Index, cmdType, action.AbilityId,
                                        action.TargetIndex, action.IsTargetEnemy);

                                    if (CallSendCommand(recorder, instance, player.Index, cmdInfo))
                                    {
                                        anyRuleApplied = true;
                                        LogAction(player.Index,
                                            $"Ability #{action.AbilityId} (type={cmdType}) -> target {action.TargetIndex} (enemy={action.IsTargetEnemy})");
                                    }
                                    else
                                    {
                                        FallbackAttack(instance, recorder, player, action, battle, ref anyRuleApplied,
                                            $"Ability #{action.AbilityId} SendCommand failed");
                                    }
                                }
                                else
                                {
                                    FallbackAttack(instance, recorder, player, action, battle, ref anyRuleApplied,
                                        $"Ability #{action.AbilityId} (CommandInfo alloc failed)");
                                }
                            }
                            else
                            {
                                FallbackAttack(instance, recorder, player, action, battle, ref anyRuleApplied,
                                    $"Ability #{action.AbilityId} (no SendCommand)");
                            }
                            break;

                        case ActionType.Guard:
                            if (hasSendCommand)
                            {
                                nint guardCmd = AllocateCommandInfo();
                                if (guardCmd != 0)
                                {
                                    SetupGuardCommand(guardCmd, player.Index);

                                    if (CallSendCommand(recorder, instance, player.Index, guardCmd))
                                    {
                                        anyRuleApplied = true;
                                        LogAction(player.Index, "Guard");
                                    }
                                    else
                                    {
                                        LogAction(player.Index, "Guard SendCommand failed, skipping");
                                    }
                                }
                                else
                                {
                                    LogAction(player.Index, "Guard (CommandInfo alloc failed, skipping)");
                                }
                            }
                            else
                            {
                                LogAction(player.Index, "Guard (no SendCommand available, skipping)");
                            }
                            break;

                        case ActionType.Item:
                            if (hasSendCommand)
                            {
                                nint itemCmd = AllocateCommandInfo();
                                if (itemCmd != 0)
                                {
                                    SetupItemCommand(itemCmd, player.Index, action.ItemId,
                                        action.TargetIndex, action.IsTargetEnemy);

                                    if (CallSendCommand(recorder, instance, player.Index, itemCmd))
                                    {
                                        anyRuleApplied = true;
                                        LogAction(player.Index,
                                            $"Item #{action.ItemId} -> target {action.TargetIndex} (enemy={action.IsTargetEnemy})");
                                    }
                                    else
                                    {
                                        FallbackAttack(instance, recorder, player, action, battle, ref anyRuleApplied,
                                            $"Item #{action.ItemId} SendCommand failed");
                                    }
                                }
                                else
                                {
                                    FallbackAttack(instance, recorder, player, action, battle, ref anyRuleApplied,
                                        $"Item #{action.ItemId} (CommandInfo alloc failed)");
                                }
                            }
                            else
                            {
                                FallbackAttack(instance, recorder, player, action, battle, ref anyRuleApplied,
                                    $"Item #{action.ItemId} (no SendCommand)");
                            }
                            break;

                        case ActionType.Default:
                            LogAction(player.Index, "Default (original behavior)");
                            break;
                    }
                }
            }

            // If no rules applied for any character, fall back to original behavior
            if (!anyRuleApplied)
            {
                _processHook.Trampoline(instance, commandIndex, methodInfo);
            }
        }
        catch (System.Exception ex)
        {
            if (_logCount < MaxLogLines)
            {
                Melon<Core>.Logger.Warning($"[AutoBattle] Hook exception: {ex.Message}");
                _logCount++;
            }
            // Always fall back to original on error
            try { _processHook.Trampoline(instance, commandIndex, methodInfo); } catch { }
        }
    }

    // ── Command submission helpers ───────────────────────────────

    /// <summary>
    /// Submit an attack command. Uses AddAttackCommand with the proper BtlCommandRecorder instance.
    /// </summary>
    private static bool SubmitAttackCommand(nint btlLayoutCtrl, nint recorder, int charaIndex, int targetIndex, bool isTargetEnemy)
    {
        if (_addAttackCommandPtr == 0) return false;

        try
        {
            // AddAttackCommand is an instance method on BtlCommandRecorder:
            // void AddAttackCommand(BtlCommandRecorder* this, BtlLayoutCtrl*, int charaIndex, int targetIndex, bool isTargetEnemy, MethodInfo*)
            var fn = (delegate* unmanaged[Cdecl]<nint, nint, int, int, byte, nint, void>)_addAttackCommandPtr;

            // Use the recorder if available, otherwise pass btlLayoutCtrl as this (legacy behavior)
            nint thisPtr = (recorder != 0) ? recorder : btlLayoutCtrl;
            fn(thisPtr, btlLayoutCtrl, charaIndex, targetIndex, isTargetEnemy ? (byte)1 : (byte)0, _addAttackCommandMethodInfo);
            return true;
        }
        catch (System.Exception ex)
        {
            if (_logCount < MaxLogLines)
            {
                Melon<Core>.Logger.Warning($"[AutoBattle] AddAttackCommand failed: {ex.Message}");
                _logCount++;
            }
            return false;
        }
    }

    /// <summary>
    /// Submit a command via SendCommand (for ability/guard/item).
    /// </summary>
    private static bool CallSendCommand(nint recorder, nint btlLayoutCtrl, int charaIndex, nint commandInfo)
    {
        if (_sendCommandPtr == 0 || recorder == 0 || commandInfo == 0) return false;

        try
        {
            // void SendCommand(BtlCommandRecorder* this, BtlLayoutCtrl*, int charaIndex, CommandInfo*, bool IsRemoveBp, bool ChangeSerial, MethodInfo*)
            var fn = (delegate* unmanaged[Cdecl]<nint, nint, int, nint, byte, byte, nint, void>)_sendCommandPtr;
            fn(recorder, btlLayoutCtrl, charaIndex, commandInfo, 0, 0, _sendCommandMethodInfo);
            return true;
        }
        catch (System.Exception ex)
        {
            if (_logCount < MaxLogLines)
            {
                Melon<Core>.Logger.Warning($"[AutoBattle] SendCommand failed: {ex.Message}");
                _logCount++;
            }
            return false;
        }
    }

    /// <summary>
    /// Fall back to attack when ability/item/guard submission is not available or fails.
    /// </summary>
    private static void FallbackAttack(nint btlLayoutCtrl, nint recorder, CharacterSnapshot player,
        ResolvedAction action, BattleSnapshot battle, ref bool anyRuleApplied, string reason)
    {
        int fallbackTarget = action.IsTargetEnemy ? action.TargetIndex : FindWeakestEnemyIndex(battle);
        if (fallbackTarget >= 0 && SubmitAttackCommand(btlLayoutCtrl, recorder, player.Index, fallbackTarget, true))
        {
            anyRuleApplied = true;
            LogAction(player.Index, $"{reason}, fallback: Attack target {fallbackTarget}");
        }
    }

    /// <summary>
    /// Log an autobattle action (rate-limited).
    /// </summary>
    private static void LogAction(int playerIndex, string message)
    {
        if (_logCount < MaxLogLines)
        {
            Melon<Core>.Logger.Msg($"[AutoBattle] Player {playerIndex} -> {message}");
            _logCount++;
        }
    }

    // ── Legacy compatibility ─────────────────────────────────────

    /// <summary>
    /// Legacy AddAttackCommand call for backwards compatibility.
    /// Kept as fallback if the new 6-arg calling convention causes issues.
    /// </summary>
    private static void CallAddAttackCommand(nint btlLayoutCtrl, int charaIndex, int targetIndex, bool isTargetEnemy)
    {
        // Call native function pointer directly with proper 6-arg convention
        nint recorder = GetCommandRecorder();
        nint thisPtr = (recorder != 0) ? recorder : btlLayoutCtrl;
        var fn = (delegate* unmanaged[Cdecl]<nint, nint, int, int, byte, nint, void>)_addAttackCommandPtr;
        fn(thisPtr, btlLayoutCtrl, charaIndex, targetIndex, isTargetEnemy ? (byte)1 : (byte)0, _addAttackCommandMethodInfo);
    }

    private static int FindWeakestEnemyIndex(BattleSnapshot battle)
    {
        int bestIdx = -1;
        int bestHp = int.MaxValue;
        foreach (var e in battle.Enemies)
        {
            if (e.IsDead) continue;
            if (e.Hp < bestHp)
            {
                bestHp = e.Hp;
                bestIdx = e.Index;
            }
        }
        return bestIdx;
    }
}
