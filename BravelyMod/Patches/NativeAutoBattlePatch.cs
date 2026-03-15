using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;
using MelonLoader.Utils;
using BravelyMod.AutoBattle;

namespace BravelyMod.Patches;

/// <summary>
/// Native hook on BtlLayoutCtrl.ProcessAutoBattle.
/// Replaces the simple record-playback with the conditional rule engine.
/// Falls back to original behavior if rule evaluation fails.
/// </summary>
public static unsafe class NativeAutoBattlePatch
{
    // void ProcessAutoBattle(BtlLayoutCtrl* this, int commandIndex, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_ProcessAutoBattle(nint instance, int commandIndex, nint methodInfo);

    // void AddAttackCommand(BtlLayoutCtrl* this, int charaIndex, int targetIndex, bool isTargetEnemy, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddAttackCommand(nint instance, int charaIndex, int targetIndex, byte isTargetEnemy, nint methodInfo);

    private static NativeHook<d_ProcessAutoBattle> _processHook;
    private static d_ProcessAutoBattle _pinnedProcess;

    // Cached function pointer for AddAttackCommand
    private static nint _addAttackCommandPtr;
    private static nint _addAttackCommandMethodInfo;

    private static readonly RuleEngine _ruleEngine = new();

    private static int _logCount = 0;
    private const int MaxLogLines = 20;

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
    }

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
        try
        {
            var field = typeof(Il2Cpp.BtlCommandRecorder).GetField(
                "NativeMethodInfoPtr_AddAttackCommand_Public_Void_BtlLayoutCtrl_Int32_Int32_Boolean_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

            if (field == null)
            {
                // Try alternative name patterns
                field = typeof(Il2Cpp.BtlCommandRecorder).GetField(
                    "NativeMethodInfoPtr_AddAttackCommand_Public_Static_Void_BtlLayoutCtrl_Int32_Int32_Boolean_0",
                    System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            }

            if (field == null)
            {
                Melon<Core>.Logger.Warning("[AutoBattle] AddAttackCommand field not found — will fallback to original");
                return;
            }

            var mi = (nint)field.GetValue(null);
            if (mi == 0)
            {
                Melon<Core>.Logger.Warning("[AutoBattle] AddAttackCommand method info ptr is null");
                return;
            }

            _addAttackCommandPtr = *(nint*)mi;
            _addAttackCommandMethodInfo = mi;
            Melon<Core>.Logger.Msg($"[AutoBattle] AddAttackCommand resolved @ 0x{_addAttackCommandPtr:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"[AutoBattle] AddAttackCommand resolve failed: {ex.Message}");
        }
    }

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

            // Evaluate rules for each living player character
            for (int i = 0; i < battle.Players.Length; i++)
            {
                var player = battle.Players[i];
                if (player.IsDead) continue;

                var resolved = _ruleEngine.EvaluateForCharacter(i, battle);
                if (resolved == null) continue;

                var action = resolved.Value;

                if (action.Type == ActionType.Attack && _addAttackCommandPtr != 0)
                {
                    CallAddAttackCommand(instance, player.Index, action.TargetIndex, action.IsTargetEnemy);
                    anyRuleApplied = true;

                    if (_logCount < MaxLogLines)
                    {
                        Melon<Core>.Logger.Msg(
                            $"[AutoBattle] Player {player.Index} -> Attack target {action.TargetIndex} (enemy={action.IsTargetEnemy})");
                        _logCount++;
                    }
                }
                else if (action.Type == ActionType.Ability)
                {
                    // TODO: Implement ability command submission (needs AddAbilityCommand address)
                    // For now, fall back to attack on the same target
                    if (_addAttackCommandPtr != 0)
                    {
                        // Fallback: if we wanted Cure but can't send ability commands yet, just attack weakest
                        int fallbackTarget = FindWeakestEnemyIndex(battle);
                        if (fallbackTarget >= 0)
                        {
                            CallAddAttackCommand(instance, player.Index, fallbackTarget, true);
                            anyRuleApplied = true;

                            if (_logCount < MaxLogLines)
                            {
                                Melon<Core>.Logger.Msg(
                                    $"[AutoBattle] Player {player.Index} -> Ability fallback: Attack target {fallbackTarget}");
                                _logCount++;
                            }
                        }
                    }
                }
                else if (action.Type == ActionType.Guard)
                {
                    // TODO: Implement guard command
                    if (_logCount < MaxLogLines)
                    {
                        Melon<Core>.Logger.Msg($"[AutoBattle] Player {player.Index} -> Guard (not yet implemented, skipping)");
                        _logCount++;
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

    private static void CallAddAttackCommand(nint btlLayoutCtrl, int charaIndex, int targetIndex, bool isTargetEnemy)
    {
        // Call native function pointer directly
        var fn = (delegate* unmanaged[Cdecl]<nint, int, int, byte, nint, void>)_addAttackCommandPtr;
        fn(btlLayoutCtrl, charaIndex, targetIndex, isTargetEnemy ? (byte)1 : (byte)0, _addAttackCommandMethodInfo);
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
