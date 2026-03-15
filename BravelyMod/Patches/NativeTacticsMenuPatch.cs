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

    private static NativeHook<d_UpdateAutoSubMenu> _updateHook;
    private static d_UpdateAutoSubMenu _pinnedUpdate;

    private static nint _setDialogTextPtr;
    private static nint _setDialogTextMethodInfo;

    private static int _logCount = 0;
    private const int MaxLogLines = 30;

    public static void Apply()
    {
        HookUpdateAutoSubMenu();
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
    /// Read CursorIndex from the BtlGUIAutoWindow instance (offset 0x98).
    /// </summary>
    private static int ReadCursorIndex(nint instance)
    {
        return *(int*)(instance + 0x98);
    }

    /// <summary>
    /// Read m_Phase from the static TypeInfo -> static fields -> offset 0x28.
    /// Returns -1 if unable to read.
    /// </summary>
    private static int ReadPhase()
    {
        try
        {
            // BtlGUIAutoWindow_TypeInfo is accessible via Il2Cpp interop
            var typeInfoField = typeof(Il2Cpp.BtlGUIAutoWindow).GetField(
                "Il2CppClassPointerStore_NativeClassPtr",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public);

            // Alternative: read from the Il2CppType directly
            // m_Phase is a public static int at static field offset 0x28
            // Access via Il2CppInterop: Il2Cpp.BtlGUIAutoWindow.m_Phase
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
    /// Check if the current phase is AutoSubMenuPhase (22 = 0x16).
    /// </summary>
    private static bool IsInSubMenuPhase()
    {
        return ReadPhase() == 22; // AutoSubMenuPhase
    }

    /// <summary>
    /// The hook intercepts the original function. We watch for the confirm action
    /// when CursorIndex == 4 (Change Name). Instead of letting the original code
    /// enter the rename flow (AutoRenameMenuPhase), we cycle profiles and show
    /// a brief text overlay.
    ///
    /// Strategy: Let the original run. If it transitions to AutoRenameMenuPhase,
    /// we revert the phase and cycle the profile instead.
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

                // Cancel any InputFieldOpen coroutine that may have been started
                // (The coroutine checks Editting flag and phase, so reverting phase should
                //  prevent it from doing anything meaningful on next tick)

                // Cycle to next profile
                var engine = NativeAutoBattlePatch.RuleEngine;
                string newProfile = engine.CycleProfile();

                if (_logCount < MaxLogLines)
                {
                    Melon<Core>.Logger.Msg($"[TacticsMenu] Cycled to profile: {newProfile}");
                    _logCount++;
                }

                // Show the profile name using SetDialogText if we have it
                ShowProfileName(instance, newProfile);
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
    /// Show the profile name by calling the game's DialogOpen + SetDialogText.
    /// We call DialogOpen to make the dialog pane visible, then SetDialogText
    /// with the profile name and selVisible=false (no Yes/No buttons).
    /// </summary>
    private static void ShowProfileName(nint instance, string profileName)
    {
        if (_setDialogTextPtr == 0) return;

        try
        {
            // Call DialogOpen first to make the dialog visible
            // DialogOpen is at instance method, we can call it via Il2Cpp interop or native ptr.
            // For simplicity, resolve and call DialogOpen via the Il2Cpp type.
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
            string displayText = $"Profile: {profileName}";
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
                Melon<Core>.Logger.Warning($"[TacticsMenu] ShowProfileName failed: {ex.Message}");
                _logCount++;
            }
        }
    }
}
