using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Allows Brave from submenus (spell/ability/item lists).
/// Hooks BtlTopMenuLayout.Update — when in Phase 3 (SubMenuPhase),
/// also calls MainWndProc._updateShortcutKeys() so the Brave button
/// is checked even while a submenu is open.
///
/// Phase machine (from Ghidra decompilation of BtlTopMenuLayout.Update @ 0x180584160):
///   Phase 0: Init — sets up layout, transitions to 1
///   Phase 1: MainPhase — calls HandleGoButtonInput, then MainWndProc.Update
///            (MainWndProc.Update internally calls _updateShortcutKeys → brave works)
///   Phase 2: Transition — SubWndProc profile update, waits for ClosedSubWindow, sets phase=3
///   Phase 3: SubMenuPhase — calls HandleGoButtonInput, then SubWndProc.Update
///            (SubWndProc.Update does NOT call _updateShortcutKeys → brave blocked)
///   Phase 4: Closing — waits for ClosedSubWindow, sets phase=1
///
/// Key field offsets (instance, NOT static):
///   instance+0x20 = m_mainWndProc
///   instance+0x28 = m_subWndProc
///   instance+0x38 = m_Phase (int, instance field)
///   instance+0x58 = PadSampler
///
/// Fix: After original Update runs, if m_Phase==3 (submenu open), call
/// _updateShortcutKeys on MainWndProc to enable Brave/Default button detection.
/// _updateShortcutKeys reads PadSampler via MainWndProc+0x20 (back-ref to
/// BtlTopMenuLayout) then +0x58, so it gets the same input as Update.
/// </summary>
public static unsafe class NativeBraveSubmenuPatch
{
    // void Update(this BtlTopMenuLayout, float time, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_Update(nint instance, float time, nint methodInfo);

    // void _updateShortcutKeys(this MainWndProc, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_UpdateShortcutKeys(nint instance, nint methodInfo);

    private static NativeHook<d_Update> _updateHook;
    private static d_Update _pinnedUpdate;

    private static nint _shortcutKeysPtr;
    private static nint _shortcutKeysMethodInfo;

    // Cached delegate to avoid repeated Marshal.GetDelegateForFunctionPointer per frame
    private static d_UpdateShortcutKeys _shortcutKeysFn;

    private static int _logCount;

    // Instance field offsets (from Ghidra decompilation)
    private const int OFF_MAIN_WND_PROC = 0x20;
    private const int OFF_SUB_WND_PROC  = 0x28;
    private const int OFF_PHASE         = 0x38;

    private const int PHASE_SUB_MENU = 3;

    public static void Apply()
    {
        try
        {
            // Hook BtlTopMenuLayout.Update
            var field = typeof(Il2Cpp.BtlTopMenuLayout).GetField(
                "NativeMethodInfoPtr_Update_Public_Virtual_Void_Single_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Melon<Core>.Logger.Warning("BraveSubmenu: Update field not found"); return; }

            var mi = (nint)field.GetValue(null);
            if (mi == 0) { Melon<Core>.Logger.Warning("BraveSubmenu: Update MethodInfo is null"); return; }
            var native = *(nint*)mi;

            _pinnedUpdate = Update_Hook;
            _updateHook = new NativeHook<d_Update>(native, Marshal.GetFunctionPointerForDelegate(_pinnedUpdate));
            _updateHook.Attach();
            Melon<Core>.Logger.Msg($"BraveSubmenu: Update hook @ 0x{native:X}");

            // Resolve _updateShortcutKeys on MainWndProc
            // MainWndProc is a nested class inside BtlTopMenuLayout
            var wndType = typeof(Il2Cpp.BtlTopMenuLayout).GetNestedType("MainWndProc");
            if (wndType == null)
            {
                // Fallback: try as a separate type in Il2Cpp namespace
                wndType = System.Type.GetType("Il2Cpp.BtlTopMenuLayout.MainWndProc, Assembly-CSharp");
            }

            if (wndType != null)
            {
                var skField = wndType.GetField(
                    "NativeMethodInfoPtr__updateShortcutKeys_Public_Void_0",
                    System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
                if (skField != null)
                {
                    var skMi = (nint)skField.GetValue(null);
                    if (skMi != 0)
                    {
                        _shortcutKeysPtr = *(nint*)skMi;
                        _shortcutKeysMethodInfo = skMi;
                        _shortcutKeysFn = Marshal.GetDelegateForFunctionPointer<d_UpdateShortcutKeys>(_shortcutKeysPtr);
                        Melon<Core>.Logger.Msg($"BraveSubmenu: _updateShortcutKeys @ 0x{_shortcutKeysPtr:X}");
                    }
                    else
                    {
                        Melon<Core>.Logger.Warning("BraveSubmenu: _updateShortcutKeys MethodInfo value is null");
                    }
                }
                else
                {
                    Melon<Core>.Logger.Warning("BraveSubmenu: _updateShortcutKeys field not found on MainWndProc");
                }
            }
            else
            {
                Melon<Core>.Logger.Warning("BraveSubmenu: MainWndProc type not found");
            }
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"BraveSubmenu: {ex.Message}");
        }
    }

    private static void Update_Hook(nint instance, float time, nint methodInfo)
    {
        try
        {
            // Call original Update first — it dispatches to the right phase handler
            _updateHook.Trampoline(instance, time, methodInfo);

            if (_shortcutKeysFn == null) return;

            // Read m_Phase — INSTANCE field at offset 0x38 (NOT a static field!)
            // Ghidra shows: iVar1 = *(int *)(param_1 + 0x38); with switch on 0,1,2,3,4
            int phase = *(int*)(instance + OFF_PHASE);

            // Only inject shortcut key handling during SubMenuPhase (3)
            // In Phase 1 (MainPhase), MainWndProc.Update already calls _updateShortcutKeys.
            // In Phase 3, SubWndProc.Update does NOT call it — that's the bug we fix.
            if (phase != PHASE_SUB_MENU) return;

            // Get MainWndProc at instance+0x20
            nint mainWndProc = *(nint*)(instance + OFF_MAIN_WND_PROC);
            if (mainWndProc == 0) return;

            // Read phase before calling _updateShortcutKeys, because _pushCmdBrave
            // (called internally when Brave button detected) may modify phase or other state
            int phaseBefore = *(int*)(instance + OFF_PHASE);

            // Call _updateShortcutKeys on MainWndProc — this checks for BR/BL button input
            // and calls _pushCmdBrave if pressed. It reads PadSampler from
            // MainWndProc->m_pBtlTopMenuLayout->PadSampler (same input source as Update).
            _shortcutKeysFn(mainWndProc, _shortcutKeysMethodInfo);

            // If _pushCmdBrave fired, it may have changed the phase (e.g., adding a brave
            // command could trigger UI transitions). Restore phase to SubMenuPhase so the
            // submenu stays open and the player can continue selecting actions.
            int phaseAfter = *(int*)(instance + OFF_PHASE);
            if (phaseAfter != phaseBefore)
            {
                _logCount++;
                if (_logCount <= 20)
                    Melon<Core>.Logger.Msg($"BraveSubmenu: Brave triggered in submenu! Phase {phaseBefore} -> {phaseAfter}, restoring to {PHASE_SUB_MENU}");

                *(int*)(instance + OFF_PHASE) = PHASE_SUB_MENU;
            }
        }
        catch (System.Exception ex)
        {
            // Swallow exceptions to avoid crashing the game loop, but log the first few
            _logCount++;
            if (_logCount <= 5)
                Melon<Core>.Logger.Warning($"BraveSubmenu: hook error: {ex.Message}");
        }
    }
}
