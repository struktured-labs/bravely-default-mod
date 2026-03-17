using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Brave from ANY submenu depth (spell picker, ability picker, etc.).
/// Hooks BtlTopMenuLayout.Update. During Phase 3 (SubMenuPhase),
/// reads Pad.pressBR directly and calls _pushCmdBrave on MainWndProc.
///
/// Why not _updateShortcutKeys? It reads from PadSampler which is stale
/// during Phase 3 — the submenu's input handler processes input first.
/// Reading Pad.pressBR (global static) bypasses this.
/// </summary>
public static unsafe class NativeBraveSubmenuPatch
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_Update(nint instance, float time, nint methodInfo);

    // void _pushCmdBrave(this MainWndProc, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_PushCmdBrave(nint instance, nint methodInfo);

    // static bool Pad.get_pressBR(MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_GetPressBR(nint methodInfo);

    private static NativeHook<d_Update> _updateHook;
    private static d_Update _pinnedUpdate;

    private static d_PushCmdBrave _pushCmdBrave;
    private static nint _pushCmdBrave_mi;

    private static d_GetPressBR _getPressBR;
    private static nint _getPressBR_mi;
    private static d_GetPressBR _getPressBL;
    private static nint _getPressBL_mi;

    private static int _logCount;

    private const int OFF_MAIN_WND_PROC = 0x20;
    private const int OFF_PHASE = 0x38;
    private const int PHASE_SUB_MENU = 3;

    // m_isRbuttonBrave on MainWndProc — offset 0x29 (byte/bool)
    private const int OFF_IS_RBUTTON_BRAVE = 0x29;

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
            if (mi == 0) return;
            var native = *(nint*)mi;
            _pinnedUpdate = Update_Hook;
            _updateHook = new NativeHook<d_Update>(native, Marshal.GetFunctionPointerForDelegate(_pinnedUpdate));
            _updateHook.Attach();
            Melon<Core>.Logger.Msg($"BraveSubmenu: Update hook @ 0x{native:X}");

            // Resolve _pushCmdBrave on MainWndProc
            var wndType = typeof(Il2Cpp.BtlTopMenuLayout).GetNestedType("MainWndProc")
                ?? System.Type.GetType("Il2Cpp.BtlTopMenuLayout.MainWndProc, Assembly-CSharp");
            if (wndType != null)
            {
                ResolveFn(wndType, "NativeMethodInfoPtr__pushCmdBrave_Private_Void_0",
                    out _pushCmdBrave, out _pushCmdBrave_mi, "_pushCmdBrave");
            }
            else
            {
                Melon<Core>.Logger.Warning("BraveSubmenu: MainWndProc type not found");
            }

            // Resolve Pad.pressBR and Pad.pressBL
            var padType = typeof(Il2Cpp.Pad);
            ResolveFn(padType, "NativeMethodInfoPtr_get_pressBR_Public_Static_get_Boolean_0",
                out _getPressBR, out _getPressBR_mi, "Pad.pressBR");
            ResolveFn(padType, "NativeMethodInfoPtr_get_pressBL_Public_Static_get_Boolean_0",
                out _getPressBL, out _getPressBL_mi, "Pad.pressBL");

            if (_pushCmdBrave != null && (_getPressBR != null || _getPressBL != null))
                Melon<Core>.Logger.Msg("BraveSubmenu: All resolved — submenu brave ready");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"BraveSubmenu: {ex.Message}");
        }
    }

    private static void ResolveFn<T>(System.Type type, string fieldName,
        out T fn, out nint mi, string label) where T : System.Delegate
    {
        fn = null;
        mi = 0;
        try
        {
            var field = type.GetField(fieldName,
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Melon<Core>.Logger.Warning($"BraveSubmenu: {label} not found"); return; }
            mi = (nint)field.GetValue(null);
            if (mi == 0) return;
            var native = *(nint*)mi;
            fn = Marshal.GetDelegateForFunctionPointer<T>(native);
            Melon<Core>.Logger.Msg($"BraveSubmenu: {label} @ 0x{native:X}");
        }
        catch { }
    }

    // Debounce: track whether we already braved this button press
    private static bool _braveButtonWasDown = false;

    private static void Update_Hook(nint instance, float time, nint methodInfo)
    {
        try
        {
            // Read phase BEFORE original Update
            int phase = *(int*)(instance + OFF_PHASE);

            // During Phase 3 (submenu open), check for brave button press
            if (phase == PHASE_SUB_MENU && _pushCmdBrave != null)
            {
                nint mainWndProc = *(nint*)(instance + OFF_MAIN_WND_PROC);
                if (mainWndProc != 0)
                {
                    // Check which button is brave (RB or LB)
                    bool isRButton = *(byte*)(mainWndProc + OFF_IS_RBUTTON_BRAVE) != 0;
                    bool pressed = false;

                    if (isRButton && _getPressBR != null)
                        pressed = _getPressBR(_getPressBR_mi) != 0;
                    else if (!isRButton && _getPressBL != null)
                        pressed = _getPressBL(_getPressBL_mi) != 0;

                    if (pressed && !_braveButtonWasDown)
                    {
                        // First frame of button press — fire once
                        _braveButtonWasDown = true;

                        _logCount++;
                        if (_logCount <= 20)
                            Melon<Core>.Logger.Msg("BraveSubmenu: Brave from submenu!");

                        // Call _pushCmdBrave — adds AP, command window, plays sound
                        _pushCmdBrave(mainWndProc, _pushCmdBrave_mi);

                        // Also play sound manually in case _pushCmdBrave's sound fails
                        try { Il2Cpp.SoundManager.PlaySE("BT_SPE_BRAVE", false, false, 0); } catch { }
                    }
                    else if (!pressed)
                    {
                        // Button released — reset debounce
                        _braveButtonWasDown = false;
                    }
                }
            }
            else
            {
                // Not in Phase 3 — reset debounce
                _braveButtonWasDown = false;
            }

            // Call original Update
            _updateHook.Trampoline(instance, time, methodInfo);
        }
        catch
        {
            try { _updateHook.Trampoline(instance, time, methodInfo); } catch { }
        }
    }
}
