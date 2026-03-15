using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;
using BravelyMod.AutoBattle;

namespace BravelyMod.Patches;

/// <summary>
/// Hooks BtlGUIAutoWindow.UpdateAutoSubMenu to intercept the "Change Name" menu entry (index 4).
/// Instead of opening the rename dialog, it cycles through autobattle profiles and shows the
/// profile name via SetDialogText.
///
/// Also hooks AutoWindowAddCommandPlate to show multi-action rule previews on command plates.
/// Each plate now shows one action from the matched rule's action list, cycling through actions
/// for each successive plate call on the same character.
///
/// Sub-menu indices (from Ghidra decompilation):
///   0 = Use          -> phase 0x17 (AutoBattlePhase)
///   1 = Copy         -> phase 0x18 (AutoCopyMenuPhase via CopyOpen)
///   2 = Set to Cmds  -> rebuilds command layout
///   3 = Save Cmds    -> phase 0x19 (AutoDialogMenuPhase via DialogOpen)
///   4 = Change Name  -> phase 0x1A (AutoRenameMenuPhase via InputFieldOpen)
///
/// Key offsets on BtlGUIAutoWindow instance:
///   +0x98 = CursorIndex (int)     — which sub-menu row is highlighted
///   +0xB0 = PadSampler (ptr)      — input sampler
///   +0xB8 = m_HoldingCommand (int) — which tactic slot is selected (-1 = none)
///
/// Static fields via BtlGUIAutoWindow_TypeInfo + 0xB8:
///   +0x28 = m_Phase (int)
///   +0x30 = m_finger (AutoCursorLayout ptr)
/// </summary>
public static unsafe class NativeTacticsMenuPatch
{
    private const int SubMenuIndex_ChangeName = 4;
    private const int AutoRenameMenuPhase = 0x1A;

    // Original signature: void UpdateAutoSubMenu(BtlGUIAutoWindow* this, float delta, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_UpdateAutoSubMenu(nint instance, float delta, nint methodInfo);

    // SetDialogText(BtlGUIAutoWindow* this, Il2CppString* text, byte selVisible, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SetDialogText(nint instance, nint text, byte selVisible, nint methodInfo);

    // void AutoWindowAddCommandPlate(BtlGUIAutoWindow* this, int characterIndex, Il2CppString* commandName, Il2CppString* iconName, byte IsAbility, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AutoWindowAddCommandPlate(nint instance, int characterIndex, nint commandName, nint iconName, byte isAbility, nint methodInfo);

    private static NativeHook<d_UpdateAutoSubMenu> _updateHook;
    private static d_UpdateAutoSubMenu _pinnedUpdate;

    private static NativeHook<d_AutoWindowAddCommandPlate> _addCommandPlateHook;
    private static d_AutoWindowAddCommandPlate _pinnedAddCommandPlate;

    private static nint _setDialogTextPtr;
    private static nint _setDialogTextMethodInfo;

    private static int _logCount = 0;
    private const int MaxLogLines = 30;

    /// <summary>
    /// Tracks which action index to show next per character during command plate population.
    /// For multi-action rules, each plate call advances to the next action.
    /// Reset when character index decreases (new autobattle preview cycle).
    /// </summary>
    private static readonly int[] _actionIndexPerCharacter = new int[4];
    private static int _lastCharacterIndex = -1;

    public static void Apply()
    {
        HookUpdateAutoSubMenu();
        HookAutoWindowAddCommandPlate();
        ResolveSetDialogText();
    }

    private static void HookUpdateAutoSubMenu()
    {
        try
        {
            var field = typeof(Il2Cpp.BtlGUIAutoWindow).GetField(
                "NativeMethodInfoPtr_UpdateAutoSubMenu_Public_Void_Single_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null)
            {
                Melon<Core>.Logger.Warning("[TacticsMenu] UpdateAutoSubMenu field not found");
                return;
            }

            var mi = (nint)field.GetValue(null);
            if (mi == 0)
            {
                Melon<Core>.Logger.Warning("[TacticsMenu] UpdateAutoSubMenu method info ptr is null");
                return;
            }

            var native = *(nint*)mi;
            Melon<Core>.Logger.Msg($"[TacticsMenu] UpdateAutoSubMenu native @ 0x{native:X}");

            _pinnedUpdate = UpdateAutoSubMenu_Hook;
            var hookPtr = Marshal.GetFunctionPointerForDelegate(_pinnedUpdate);
            _updateHook = new NativeHook<d_UpdateAutoSubMenu>(native, hookPtr);
            _updateHook.Attach();
            Melon<Core>.Logger.Msg("[TacticsMenu] UpdateAutoSubMenu hook attached!");
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[TacticsMenu] UpdateAutoSubMenu hook failed: {ex.Message}");
        }
    }

    private static void ResolveSetDialogText()
    {
        try
        {
            var field = typeof(Il2Cpp.BtlGUIAutoWindow).GetField(
                "NativeMethodInfoPtr_SetDialogText_Public_Void_String_Boolean_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null)
            {
                Melon<Core>.Logger.Warning("[TacticsMenu] SetDialogText field not found");
                return;
            }

            var mi = (nint)field.GetValue(null);
            if (mi == 0)
            {
                Melon<Core>.Logger.Warning("[TacticsMenu] SetDialogText method info ptr is null");
                return;
            }

            _setDialogTextMethodInfo = mi;
            _setDialogTextPtr = *(nint*)mi;
            Melon<Core>.Logger.Msg($"[TacticsMenu] SetDialogText resolved @ 0x{_setDialogTextPtr:X}");
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[TacticsMenu] SetDialogText resolve failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Character names for display. Slot 0-3 map to the party order.
    /// </summary>
    private static readonly string[] CharacterSlotNames = { "Tiz", "Agnes", "Ringabel", "Edea" };

    /// <summary>
    /// Read CursorIndex from the BtlGUIAutoWindow instance (offset 0x98).
    /// </summary>
    private static int ReadCursorIndex(nint instance)
    {
        return *(int*)(instance + 0x98);
    }

    /// <summary>
    /// Read m_HoldingCommand from the BtlGUIAutoWindow instance (offset 0xB8).
    /// This is the tactic slot index (0-5) that is currently selected.
    /// Slots 0-3 map to party characters; we use this as the character index.
    /// Returns -1 if no slot is selected.
    /// </summary>
    private static int ReadHoldingCommand(nint instance)
    {
        return *(int*)(instance + 0xB8);
    }

    /// <summary>
    /// Read m_Phase from the static TypeInfo -> static fields -> offset 0x28.
    /// Returns -1 if unable to read.
    /// </summary>
    private static int ReadPhase()
    {
        try
        {
            return Il2Cpp.BtlGUIAutoWindow.m_Phase;
        }
        catch
        {
            return -1;
        }
    }

    /// <summary>
    /// Write m_Phase via Il2Cpp interop.
    /// </summary>
    private static void WritePhase(int phase)
    {
        try
        {
            Il2Cpp.BtlGUIAutoWindow.m_Phase = phase;
        }
        catch { }
    }

    /// <summary>
    /// The hook intercepts the original function. We watch for the confirm action
    /// when CursorIndex == 4 (Change Name). Instead of letting the original code
    /// enter the rename flow (AutoRenameMenuPhase), we cycle the per-character profile
    /// for the currently selected tactic slot and show "CharName: ProfileName".
    ///
    /// Strategy: Let the original run. If it transitions to AutoRenameMenuPhase,
    /// we revert the phase and cycle the per-character profile instead.
    /// The tactic slot index (m_HoldingCommand at +0xB8) maps to a character slot (0-3).
    /// </summary>
    private static void UpdateAutoSubMenu_Hook(nint instance, float delta, nint methodInfo)
    {
        try
        {
            int cursorBefore = ReadCursorIndex(instance);
            int phaseBefore = ReadPhase();

            // Let the original execute
            _updateHook.Trampoline(instance, delta, methodInfo);

            int phaseAfter = ReadPhase();

            // Detect: original just transitioned to AutoRenameMenuPhase (0x1A = 26)
            // from AutoSubMenuPhase (0x16 = 22), meaning "Change Name" was confirmed
            if (phaseBefore == 22 && phaseAfter == AutoRenameMenuPhase && cursorBefore == SubMenuIndex_ChangeName)
            {
                // Revert the phase back to AutoSubMenuPhase so the rename flow doesn't proceed
                WritePhase(22);

                var engine = NativeAutoBattlePatch.RuleEngine;

                // Read which tactic slot is selected — maps to character index
                int tacticSlot = ReadHoldingCommand(instance);
                int charIndex = (tacticSlot >= 0 && tacticSlot < 4) ? tacticSlot : -1;

                string displayText;
                if (charIndex >= 0)
                {
                    // Cycle the profile for this specific character
                    string newProfile = engine.CycleProfileForCharacter(charIndex);
                    string charName = charIndex < CharacterSlotNames.Length
                        ? CharacterSlotNames[charIndex]
                        : $"Slot {charIndex}";
                    displayText = $"{charName}: {newProfile}";

                    if (_logCount < MaxLogLines)
                    {
                        Melon<Core>.Logger.Msg($"[TacticsMenu] Slot {charIndex} ({charName}) -> profile: {newProfile}");
                        _logCount++;
                    }
                }
                else
                {
                    // Slot out of range (5+) — cycle the global default profile
                    string newProfile = engine.CycleProfile();
                    displayText = $"Default: {newProfile}";

                    if (_logCount < MaxLogLines)
                    {
                        Melon<Core>.Logger.Msg($"[TacticsMenu] Global profile cycled to: {newProfile}");
                        _logCount++;
                    }
                }

                // Save updated assignments to YAML
                AutoBattle.ProfileConfig.SaveFromEngine(NativeAutoBattlePatch.ConfigPath, engine);

                // Show the profile name using SetDialogText
                ShowProfileText(instance, displayText);
            }
        }
        catch (Exception ex)
        {
            if (_logCount < MaxLogLines)
            {
                Melon<Core>.Logger.Warning($"[TacticsMenu] Hook exception: {ex.Message}");
                _logCount++;
            }
            // If our hook logic threw, try to run original as fallback
            try { _updateHook.Trampoline(instance, delta, methodInfo); } catch { }
        }
    }

    /// <summary>
    /// Show arbitrary text by calling the game's DialogOpen + SetDialogText.
    /// Used to display per-character profile assignments like "Tiz: Attack 4x".
    /// </summary>
    private static void ShowProfileText(nint instance, string displayText)
    {
        if (_setDialogTextPtr == 0) return;

        try
        {
            // Call DialogOpen first to make the dialog visible
            var dialogOpenField = typeof(Il2Cpp.BtlGUIAutoWindow).GetField(
                "NativeMethodInfoPtr_DialogOpen_Public_Void_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

            if (dialogOpenField != null)
            {
                var dialogOpenMi = (nint)dialogOpenField.GetValue(null);
                if (dialogOpenMi != 0)
                {
                    var dialogOpenNative = *(nint*)dialogOpenMi;
                    var dialogOpenFn = (delegate* unmanaged[Cdecl]<nint, nint, void>)dialogOpenNative;
                    dialogOpenFn(instance, dialogOpenMi);
                }
            }

            // Create IL2CPP string for the display text
            var il2cppStr = Il2CppInterop.Runtime.IL2CPP.ManagedStringToIl2Cpp(displayText);

            // Call SetDialogText(instance, text, selVisible=0, methodInfo)
            var fn = (delegate* unmanaged[Cdecl]<nint, nint, byte, nint, void>)_setDialogTextPtr;
            fn(instance, il2cppStr, 0, _setDialogTextMethodInfo);

            if (_logCount < MaxLogLines)
            {
                Melon<Core>.Logger.Msg($"[TacticsMenu] Displayed profile name: {displayText}");
                _logCount++;
            }
        }
        catch (Exception ex)
        {
            if (_logCount < MaxLogLines)
            {
                Melon<Core>.Logger.Warning($"[TacticsMenu] ShowProfileText failed: {ex.Message}");
                _logCount++;
            }
        }
    }

    // ──────────────────────────────────────────────────────────────
    // AutoWindowAddCommandPlate hook — multi-action rule preview
    // ──────────────────────────────────────────────────────────────

    private static void HookAutoWindowAddCommandPlate()
    {
        try
        {
            var field = typeof(Il2Cpp.BtlGUIAutoWindow).GetField(
                "NativeMethodInfoPtr_AutoWindowAddCommandPlate_Public_Void_Int32_String_String_Boolean_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null)
            {
                Melon<Core>.Logger.Warning("[TacticsMenu] AutoWindowAddCommandPlate field not found");
                return;
            }

            var mi = (nint)field.GetValue(null);
            if (mi == 0)
            {
                Melon<Core>.Logger.Warning("[TacticsMenu] AutoWindowAddCommandPlate method info ptr is null");
                return;
            }

            var native = *(nint*)mi;
            Melon<Core>.Logger.Msg($"[TacticsMenu] AutoWindowAddCommandPlate native @ 0x{native:X}");

            _pinnedAddCommandPlate = AutoWindowAddCommandPlate_Hook;
            var hookPtr = Marshal.GetFunctionPointerForDelegate(_pinnedAddCommandPlate);
            _addCommandPlateHook = new NativeHook<d_AutoWindowAddCommandPlate>(native, hookPtr);
            _addCommandPlateHook.Attach();
            Melon<Core>.Logger.Msg("[TacticsMenu] AutoWindowAddCommandPlate hook attached!");
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[TacticsMenu] AutoWindowAddCommandPlate hook failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Hook for AutoWindowAddCommandPlate. Shows individual actions from the first matching
    /// rule's action list on successive command plates for each character.
    ///
    /// For a rule like "→ Atk Strong x4", each of the 4 plates shows "Atk Strong".
    /// For "HP &lt; 50% → Cure Ally, Atk Strong x2", plates show "Cure Ally", "Atk Strong", "Atk Strong".
    /// If the rule has fewer actions than plates, the rule's short summary is shown.
    /// </summary>
    private static void AutoWindowAddCommandPlate_Hook(nint instance, int characterIndex, nint commandName, nint iconName, byte isAbility, nint methodInfo)
    {
        try
        {
            var engine = NativeAutoBattlePatch.RuleEngine;
            var profile = engine.GetProfileForCharacter(characterIndex);

            if (profile != null && profile.Rules.Count > 0)
            {
                // Detect new preview cycle: when characterIndex goes back to 0 or lower than last seen
                if (characterIndex <= _lastCharacterIndex && characterIndex == 0)
                {
                    for (int i = 0; i < _actionIndexPerCharacter.Length; i++)
                        _actionIndexPerCharacter[i] = 0;
                }
                _lastCharacterIndex = characterIndex;

                int safeIdx = characterIndex >= 0 && characterIndex < _actionIndexPerCharacter.Length
                    ? characterIndex : 0;

                int actionIdx = _actionIndexPerCharacter[safeIdx];

                // Find the first rule (the one that would match in a generic preview context).
                // For preview, we show the first rule's actions since we don't have live battle state.
                var firstRule = profile.Rules[0];
                string summary;

                if (actionIdx < firstRule.Actions.Count)
                {
                    // Show individual action label for this plate
                    var action = firstRule.Actions[actionIdx];
                    summary = action.ToShortString();
                    _actionIndexPerCharacter[safeIdx] = actionIdx + 1;
                }
                else
                {
                    // More plates than actions: show the full rule summary
                    summary = firstRule.ToShortString();
                    _actionIndexPerCharacter[safeIdx] = actionIdx + 1;
                }

                // Create IL2CPP string and replace commandName
                commandName = Il2CppInterop.Runtime.IL2CPP.ManagedStringToIl2Cpp(summary);

                if (_logCount < MaxLogLines)
                {
                    Melon<Core>.Logger.Msg($"[TacticsMenu] Plate char={characterIndex} action={actionIdx}: {summary}");
                    _logCount++;
                }
            }
        }
        catch (Exception ex)
        {
            if (_logCount < MaxLogLines)
            {
                Melon<Core>.Logger.Warning($"[TacticsMenu] AddCommandPlate hook exception: {ex.Message}");
                _logCount++;
            }
        }

        // Call original with (possibly modified) commandName
        _addCommandPlateHook.Trampoline(instance, characterIndex, commandName, iconName, isAbility, methodInfo);
    }
}
