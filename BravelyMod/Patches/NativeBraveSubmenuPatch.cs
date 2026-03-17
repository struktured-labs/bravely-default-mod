using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Allows Brave from submenus (spell/ability/item lists) WITHOUT kicking the
/// player back to the main command menu.
///
/// Phase machine (from Ghidra decompilation of BtlTopMenuLayout.Update @ 0x180584160):
///   Phase 0: Init
///   Phase 1: MainPhase — MainWndProc.Update calls _updateShortcutKeys -> _pushCmdBrave
///   Phase 2: Transition — waits for ClosedSubWindow, sets phase=3
///   Phase 3: SubMenuPhase — SubWndProc.Update does NOT call _updateShortcutKeys
///   Phase 4: Closing — waits for ClosedSubWindow, sets phase=1
///
/// BtlTopMenuLayout field offsets (from Ghidra):
///   +0x20 = m_mainWndProc (MainWndProc*)
///   +0x28 = m_subWndProc (SubWndProc*)
///   +0x38 = m_Phase (int)
///   +0x48 = BtlLayoutCtrl*
///   +0x58 = PadSampler*
///   +0x80 = MainCommandWnd*
///   +0x98 = BtlDScreenGui_BG*
///
/// BtlLayoutCtrl field offsets:
///   +0x204 = current character index (int)
///   +0x260 = BtlLytCharaCtrl*
///
/// Previous approach: Called _updateShortcutKeys which triggers _pushCmdBrave,
/// which calls ForceWindowAnimationToEnd + AddMessage causing UI transitions.
///
/// New approach: Detect Brave button press ourselves, then call ONLY the
/// data-modifying functions (AddAP, AddCommandWindow, DecrementPredictedBp)
/// without any UI transition calls. The submenu stays open.
/// </summary>
public static unsafe class NativeBraveSubmenuPatch
{
    // ── Delegate types ────────────────────────────────────────────────

    // void Update(this BtlTopMenuLayout, float time, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_Update(nint instance, float time, nint methodInfo);

    // bool Pad.pressBR/pressBL (static, MethodInfo*) — returns byte (0/1)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_PadGet(nint methodInfo);

    // bool gfc.IsEnableBrave(int partyIndex, BtlLayoutCtrl*, MethodInfo*) — static
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_IsEnableBrave(int partyIndex, nint btlLayoutCtrl, nint methodInfo);

    // bool BtlLayoutCtrl.IsSuperBraveMode(this, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_IsSuperBraveMode(nint instance, nint methodInfo);

    // BtlChara* BtlLytCharaCtrl.GetBtlChara(this, int index, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_GetBtlChara(nint instance, int index, nint methodInfo);

    // BtlActionPoint* BtlChara.GetActionPoint(this, MethodInfo*) — virtual
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_GetActionPoint(nint instance, nint methodInfo);

    // void BtlActionPoint.AddAP(this, int count, MethodInfo* not used in native)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddAP(nint instance, int count);

    // void BtlDScreenGui_BG.AddCommandWindow(this, bool isSuperBrave, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddCommandWindow(nint instance, byte isSuperBrave, nint methodInfo);

    // bool BtlDScreenGui_BG.IsRemoving(this, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_IsRemoving(nint instance, nint methodInfo);

    // void BtlLytCharaCtrl.AddPredictedBp(this, BtlChara*, int amount, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddPredictedBp(nint instance, nint btlChara, int amount, nint methodInfo);

    // void BtlLayoutCtrl.DecrementPredictedSp(this, MethodInfo*) — for super brave mode
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_DecrementPredictedSp(nint instance, nint methodInfo);

    // ── Hook storage ──────────────────────────────────────────────────

    private static NativeHook<d_Update> _updateHook;
    private static d_Update _pinnedUpdate;

    // ── Resolved native function pointers and MethodInfos ─────────────

    private static d_PadGet _pressBR;
    private static nint _pressBR_mi;

    private static d_PadGet _pressBL;
    private static nint _pressBL_mi;

    private static d_IsEnableBrave _isEnableBrave;
    private static nint _isEnableBrave_mi;

    private static d_IsEnableBrave _isEnableBraveAtSuperBrave;
    private static nint _isEnableBraveAtSuperBrave_mi;

    private static d_IsSuperBraveMode _isSuperBraveMode;
    private static nint _isSuperBraveMode_mi;

    private static d_GetBtlChara _getBtlChara;
    private static nint _getBtlChara_mi;

    private static d_AddAP _addAP;

    private static d_AddCommandWindow _addCommandWindow;
    private static nint _addCommandWindow_mi;

    private static d_IsRemoving _isRemoving;
    private static nint _isRemoving_mi;

    private static d_AddPredictedBp _addPredictedBp;
    private static nint _addPredictedBp_mi;

    private static d_DecrementPredictedSp _decrementPredictedSp;
    private static nint _decrementPredictedSp_mi;

    // m_isRbuttonBrave field offset on MainWndProc — resolved via IL2CPP field info
    private static int _isRbuttonBraveOffset = -1;

    private static int _logCount;

    // ── Instance field offsets (from Ghidra) ──────────────────────────

    private const int OFF_MAIN_WND_PROC    = 0x20;
    private const int OFF_PHASE            = 0x38;
    private const int OFF_BTL_LAYOUT_CTRL  = 0x48;
    private const int OFF_DSCREEN_GUI_BG   = 0x98;

    // BtlLayoutCtrl offsets
    private const int OFF_LC_CHAR_INDEX    = 0x204;
    private const int OFF_LC_CHARA_CTRL    = 0x260;

    private const int PHASE_SUB_MENU = 3;

    // ── Public entry point ────────────────────────────────────────────

    public static void Apply()
    {
        try
        {
            // 1. Hook BtlTopMenuLayout.Update
            var updateNative = ResolveNative(typeof(Il2Cpp.BtlTopMenuLayout),
                "NativeMethodInfoPtr_Update_Public_Virtual_Void_Single_0", out _);
            if (updateNative == 0) { Log("Update not found"); return; }

            _pinnedUpdate = Update_Hook;
            _updateHook = new NativeHook<d_Update>(updateNative, Marshal.GetFunctionPointerForDelegate(_pinnedUpdate));
            _updateHook.Attach();
            Log($"Update hook @ 0x{updateNative:X}");

            // 2. Resolve all native functions we need
            var padType = typeof(Il2Cpp.Pad);
            ResolveFn(padType, "NativeMethodInfoPtr_get_pressBR_Public_Static_get_Boolean_0",
                out _pressBR, out _pressBR_mi, "Pad.pressBR");
            ResolveFn(padType, "NativeMethodInfoPtr_get_pressBL_Public_Static_get_Boolean_0",
                out _pressBL, out _pressBL_mi, "Pad.pressBL");

            var gfcType = typeof(Il2Cpp.gfc);
            ResolveFn(gfcType, "NativeMethodInfoPtr_IsEnableBrave_Public_Static_Boolean_Int32_BtlLayoutCtrl_0",
                out _isEnableBrave, out _isEnableBrave_mi, "gfc.IsEnableBrave");
            ResolveFn(gfcType, "NativeMethodInfoPtr_IsEnableBraveAtSuperBrave_Public_Static_Boolean_Int32_BtlLayoutCtrl_0",
                out _isEnableBraveAtSuperBrave, out _isEnableBraveAtSuperBrave_mi, "gfc.IsEnableBraveAtSuperBrave");

            var lcType = typeof(Il2Cpp.BtlLayoutCtrl);
            ResolveFn(lcType, "NativeMethodInfoPtr_IsSuperBraveMode_Public_Boolean_0",
                out _isSuperBraveMode, out _isSuperBraveMode_mi, "BtlLayoutCtrl.IsSuperBraveMode");
            ResolveFn(lcType, "NativeMethodInfoPtr_DecrementPredictedSp_Public_Void_0",
                out _decrementPredictedSp, out _decrementPredictedSp_mi, "BtlLayoutCtrl.DecrementPredictedSp");

            var ccType = typeof(Il2Cpp.BtlLytCharaCtrl);
            ResolveFn(ccType, "NativeMethodInfoPtr_GetBtlChara_Public_BtlChara_Int32_0",
                out _getBtlChara, out _getBtlChara_mi, "BtlLytCharaCtrl.GetBtlChara");
            ResolveFn(ccType, "NativeMethodInfoPtr_AddPredictedBp_Public_Void_BtlChara_Int32_0",
                out _addPredictedBp, out _addPredictedBp_mi, "BtlLytCharaCtrl.AddPredictedBp");

            var apType = typeof(Il2Cpp.BtlActionPoint);
            // AddAP is special — Ghidra shows it takes (this, int) with no trailing MethodInfo*
            // Actually it does have a MethodInfo param in IL2CPP but the native just ignores it.
            // Let's use the standard pattern.
            {
                var apNative = ResolveNative(apType, "NativeMethodInfoPtr_AddAP_Public_Void_Int32_0", out _);
                if (apNative != 0)
                {
                    _addAP = Marshal.GetDelegateForFunctionPointer<d_AddAP>(apNative);
                    Log($"BtlActionPoint.AddAP @ 0x{apNative:X}");
                }
                else Warn("BtlActionPoint.AddAP not found");
            }

            var bgType = typeof(Il2Cpp.BtlDScreenGui_BG);
            ResolveFn(bgType, "NativeMethodInfoPtr_AddCommandWindow_Public_Void_Boolean_0",
                out _addCommandWindow, out _addCommandWindow_mi, "BtlDScreenGui_BG.AddCommandWindow");
            ResolveFn(bgType, "NativeMethodInfoPtr_IsRemoving_Public_Boolean_0",
                out _isRemoving, out _isRemoving_mi, "BtlDScreenGui_BG.IsRemoving");

            // 3. Resolve m_isRbuttonBrave field offset on MainWndProc
            ResolveRbuttonBraveOffset();

            Log("All functions resolved — submenu brave ready");
        }
        catch (System.Exception ex)
        {
            Warn($"Apply failed: {ex.Message}");
        }
    }

    // ── The Hook ──────────────────────────────────────────────────────

    private static void Update_Hook(nint instance, float time, nint methodInfo)
    {
        try
        {
            // Call original Update first — it dispatches to the right phase handler
            _updateHook.Trampoline(instance, time, methodInfo);

            // Only act during SubMenuPhase (3)
            int phase = *(int*)(instance + OFF_PHASE);
            if (phase != PHASE_SUB_MENU) return;

            // Check if all required functions were resolved
            if (_pressBR == null || _isEnableBrave == null) return;

            // Get MainWndProc to read m_isRbuttonBrave
            nint mainWndProc = *(nint*)(instance + OFF_MAIN_WND_PROC);
            if (mainWndProc == 0) return;

            // Determine which button is Brave: BR if m_isRbuttonBrave, BL otherwise
            bool braveIsRB = true; // default: RB = Brave
            if (_isRbuttonBraveOffset >= 0)
            {
                braveIsRB = *(byte*)(mainWndProc + _isRbuttonBraveOffset) != 0;
            }

            // Check if the Brave button was just pressed (rising edge)
            bool bravePressed;
            if (braveIsRB)
                bravePressed = _pressBR(_pressBR_mi) != 0;
            else
                bravePressed = _pressBL(_pressBL_mi) != 0;

            if (!bravePressed) return;

            // Get BtlLayoutCtrl
            nint btlLayoutCtrl = *(nint*)(instance + OFF_BTL_LAYOUT_CTRL);
            if (btlLayoutCtrl == 0) return;

            // Get BtlDScreenGui_BG
            nint dscreenGuiBg = *(nint*)(instance + OFF_DSCREEN_GUI_BG);
            if (dscreenGuiBg == 0) return;

            // Check IsRemoving — if the screen is being removed, bail
            if (_isRemoving != null && _isRemoving(dscreenGuiBg, _isRemoving_mi) != 0)
                return;

            // Get current character index
            int charIndex = *(int*)(btlLayoutCtrl + OFF_LC_CHAR_INDEX);

            // Check IsSuperBraveMode
            bool isSuperBrave = _isSuperBraveMode != null &&
                                _isSuperBraveMode(btlLayoutCtrl, _isSuperBraveMode_mi) != 0;

            // Check IsEnableBrave (or IsEnableBraveAtSuperBrave)
            bool canBrave;
            if (isSuperBrave && _isEnableBraveAtSuperBrave != null)
                canBrave = _isEnableBraveAtSuperBrave(charIndex, btlLayoutCtrl, _isEnableBraveAtSuperBrave_mi) != 0;
            else
                canBrave = _isEnableBrave(charIndex, btlLayoutCtrl, _isEnableBrave_mi) != 0;

            if (!canBrave)
            {
                // Play error SE (same as _pushCmdBrave does when brave is not available)
                // We just skip it — no sound, no action. The button press is silently ignored.
                _logCount++;
                if (_logCount <= 5)
                    Log($"Brave not available for char {charIndex} in submenu");
                return;
            }

            // Get BtlLytCharaCtrl
            nint charaCtrl = *(nint*)(btlLayoutCtrl + OFF_LC_CHARA_CTRL);
            if (charaCtrl == 0) return;

            // Get BtlChara for current character
            nint btlChara = _getBtlChara(charaCtrl, charIndex, _getBtlChara_mi);
            if (btlChara == 0) return;

            // Get BtlActionPoint from BtlChara (virtual call)
            // In native: vtable at *btlChara, GetActionPoint at vtable+0x678
            // The MethodInfo for the virtual call is at vtable+0x680
            nint vtable = *(nint*)btlChara;
            nint getAPFn = *(nint*)(vtable + 0x678);
            nint getAPMi = *(nint*)(vtable + 0x680);
            if (getAPFn == 0) return;
            var getAPDel = Marshal.GetDelegateForFunctionPointer<d_GetActionPoint>(getAPFn);
            nint actionPoint = getAPDel(btlChara, getAPMi);
            if (actionPoint == 0) return;

            // === Perform the Brave action (data only, no UI transitions) ===

            // 1. AddAP(1) — adds an action slot
            _addAP(actionPoint, 1);

            // 2. AddCommandWindow — adds a command window to the bottom screen
            byte superBraveByte = isSuperBrave ? (byte)1 : (byte)0;
            _addCommandWindow(dscreenGuiBg, superBraveByte, _addCommandWindow_mi);

            // 3. DecrementPredictedBp — update the BP prediction display
            if (isSuperBrave)
            {
                // Super brave mode uses DecrementPredictedSp on BtlLayoutCtrl
                if (_decrementPredictedSp != null)
                    _decrementPredictedSp(btlLayoutCtrl, _decrementPredictedSp_mi);
            }
            else
            {
                // Normal mode: decrement predicted BP for this character
                // Use BtlLytCharaCtrl.AddPredictedBp(btlChara, -1)
                if (_addPredictedBp != null)
                    _addPredictedBp(charaCtrl, btlChara, -1, _addPredictedBp_mi);
            }

            // NOTE: We intentionally skip the following calls from _pushCmdBrave:
            // - ForceWindowAnimationToEnd — causes submenu to close
            // - AddMessage — triggers UI transition animation
            // - Virtual calls at vtable+0xBB8 and vtable+0x6D8 — UI state changes
            // The submenu stays open; the player can continue selecting actions.

            _logCount++;
            if (_logCount <= 20)
                Log($"Brave in submenu! char={charIndex} superBrave={isSuperBrave} (submenu stays open)");
        }
        catch (System.Exception ex)
        {
            _logCount++;
            if (_logCount <= 5)
                Warn($"hook error: {ex.Message}\n{ex.StackTrace}");
        }
    }

    // ── Resolution helpers ────────────────────────────────────────────

    private static nint ResolveNative(System.Type type, string fieldName, out nint methodInfo)
    {
        methodInfo = 0;
        var field = type.GetField(fieldName,
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        if (field == null) return 0;
        var mi = (nint)field.GetValue(null);
        if (mi == 0) return 0;
        methodInfo = mi;
        return *(nint*)mi;
    }

    private static void ResolveFn<T>(System.Type type, string fieldName, out T fn, out nint mi, string label)
        where T : System.Delegate
    {
        fn = null;
        mi = 0;
        var native = ResolveNative(type, fieldName, out mi);
        if (native != 0)
        {
            fn = Marshal.GetDelegateForFunctionPointer<T>(native);
            Log($"{label} @ 0x{native:X}");
        }
        else
        {
            Warn($"{label} not found ({fieldName})");
        }
    }

    private static void ResolveRbuttonBraveOffset()
    {
        try
        {
            // MainWndProc is a nested type of BtlTopMenuLayout
            var wndType = typeof(Il2Cpp.BtlTopMenuLayout).GetNestedType("MainWndProc");
            if (wndType == null)
                wndType = System.Type.GetType("Il2Cpp.BtlTopMenuLayout+MainWndProc, Assembly-CSharp");
            if (wndType == null) { Warn("MainWndProc type not found for m_isRbuttonBrave"); return; }

            var fieldInfo = wndType.GetField("NativeFieldInfoPtr_m_isRbuttonBrave",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (fieldInfo == null) { Warn("m_isRbuttonBrave field info not found"); return; }

            var ptr = (nint)fieldInfo.GetValue(null);
            if (ptr == 0) { Warn("m_isRbuttonBrave pointer is null"); return; }

            // Use il2cpp_field_get_offset to get the IL2CPP field offset
            // This gives us the byte offset from the object pointer
            _isRbuttonBraveOffset = (int)Il2CppInterop.Runtime.IL2CPP.il2cpp_field_get_offset(ptr);
            Log($"m_isRbuttonBrave offset = 0x{_isRbuttonBraveOffset:X}");
        }
        catch (System.Exception ex)
        {
            Warn($"ResolveRbuttonBraveOffset: {ex.Message}");
        }
    }

    private static void Log(string msg) => Melon<Core>.Logger.Msg($"BraveSubmenu: {msg}");
    private static void Warn(string msg) => Melon<Core>.Logger.Warning($"BraveSubmenu: {msg}");
}
