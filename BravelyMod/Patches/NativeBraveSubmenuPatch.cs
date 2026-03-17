using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Brave from any menu depth. Reads Pad.pressBR directly, then performs
/// ONLY the data operations (AddAP, AddCommandWindow, DecrementPredictedBp)
/// WITHOUT calling _pushCmdBrave (which resets cursor and closes submenus).
/// Falls back to _pushCmdBrave if any data operation can't be resolved.
/// </summary>
public static unsafe class NativeBraveSubmenuPatch
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_Update(nint instance, float time, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_PushCmdBrave(nint instance, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_GetBool(nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_IsEnableBrave(int partyindex, nint pBtlLayoutCtrl, nint methodInfo);

    // void AddAP(this BtlActionPoint, int count) — no trailing MethodInfo
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddAP(nint instance, int count);

    // void AddCommandWindow(this BtlDScreenGui_BG, bool isSuperBrave, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddCommandWindow(nint instance, byte isSuperBrave, nint methodInfo);

    // void AddPredictedBp(this BtlLytCharaCtrl, BtlChara, int amount, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddPredictedBp(nint instance, nint btlChara, int amount, nint methodInfo);

    // bool IsRemoving(this BtlDScreenGui_BG, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_IsRemoving(nint instance, nint methodInfo);

    private static NativeHook<d_Update> _updateHook;
    private static d_Update _pinnedUpdate;

    // Resolved functions
    private static d_GetBool _pressBR, _pressBL;
    private static nint _pressBR_mi, _pressBL_mi;
    private static d_IsEnableBrave _isEnableBrave;
    private static nint _isEnableBrave_mi;
    private static d_AddAP _addAP;
    private static d_AddCommandWindow _addCommandWindow;
    private static nint _addCommandWindow_mi;
    private static d_AddPredictedBp _addPredictedBp;
    private static nint _addPredictedBp_mi;
    private static d_IsRemoving _isRemoving;
    private static nint _isRemoving_mi;
    private static d_PushCmdBrave _pushCmdBrave;
    private static nint _pushCmdBrave_mi;

    private static bool _useDirectApproach = false;
    private static bool _braveWasDown = false;
    private static int _logCount;

    private const int OFF_MAIN_WND_PROC = 0x20;
    private const int OFF_PHASE = 0x38;
    private const int OFF_IS_RBUTTON_BRAVE = 0x29;
    // BtlTopMenuLayout offsets for data operations
    private const int OFF_BTL_LAYOUT_CTRL = 0x48;
    private const int OFF_DSCREEN_GUI_BG = 0x98;
    // BtlLayoutCtrl offsets
    private const int OFF_CHARA_INDEX = 0x204;
    private const int OFF_CHARA_CTRL = 0x260;

    public static void Apply()
    {
        try
        {
            // Hook Update
            var updateField = typeof(Il2Cpp.BtlTopMenuLayout).GetField(
                "NativeMethodInfoPtr_Update_Public_Virtual_Void_Single_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (updateField == null) { Log("Update field not found"); return; }
            var mi = (nint)updateField.GetValue(null);
            if (mi == 0) return;
            var native = *(nint*)mi;
            _pinnedUpdate = Update_Hook;
            _updateHook = new NativeHook<d_Update>(native, Marshal.GetFunctionPointerForDelegate(_pinnedUpdate));
            _updateHook.Attach();
            Log($"Update hook @ 0x{native:X}");

            // Resolve button reads
            Resolve<d_GetBool>(typeof(Il2Cpp.Pad), "NativeMethodInfoPtr_get_pressBR_Public_Static_get_Boolean_0", out _pressBR, out _pressBR_mi);
            Resolve<d_GetBool>(typeof(Il2Cpp.Pad), "NativeMethodInfoPtr_get_pressBL_Public_Static_get_Boolean_0", out _pressBL, out _pressBL_mi);

            // Resolve IsEnableBrave
            Resolve<d_IsEnableBrave>(typeof(Il2Cpp.gfc), "NativeMethodInfoPtr_IsEnableBrave_Public_Static_Boolean_Int32_BtlLayoutCtrl_0", out _isEnableBrave, out _isEnableBrave_mi);

            // Resolve _pushCmdBrave (fallback)
            var wndType = typeof(Il2Cpp.BtlTopMenuLayout).GetNestedType("MainWndProc")
                ?? System.Type.GetType("Il2Cpp.BtlTopMenuLayout.MainWndProc, Assembly-CSharp");
            if (wndType != null)
                Resolve<d_PushCmdBrave>(wndType, "NativeMethodInfoPtr__pushCmdBrave_Private_Void_0", out _pushCmdBrave, out _pushCmdBrave_mi);

            // Try to resolve direct data operations
            try
            {
                Resolve<d_IsRemoving>(typeof(Il2Cpp.BtlDScreenGui_BG), "NativeMethodInfoPtr_IsRemoving_Public_Boolean_0", out _isRemoving, out _isRemoving_mi);

                // AddAP — no MethodInfo trailing param
                var apField = typeof(Il2Cpp.BtlActionPoint).GetField("NativeMethodInfoPtr_AddAP_Public_Void_Int32_0",
                    System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
                if (apField != null)
                {
                    var apMi = (nint)apField.GetValue(null);
                    if (apMi != 0) { _addAP = Marshal.GetDelegateForFunctionPointer<d_AddAP>(*(nint*)apMi); Log($"AddAP resolved"); }
                }

                Resolve<d_AddCommandWindow>(typeof(Il2Cpp.BtlDScreenGui_BG), "NativeMethodInfoPtr_AddCommandWindow_Public_Void_Boolean_0", out _addCommandWindow, out _addCommandWindow_mi);
                Resolve<d_AddPredictedBp>(typeof(Il2Cpp.BtlLytCharaCtrl), "NativeMethodInfoPtr_AddPredictedBp_Public_Void_BtlChara_Int32_0", out _addPredictedBp, out _addPredictedBp_mi);

                _useDirectApproach = _addAP != null && _addCommandWindow != null;
                Log(_useDirectApproach ? "Direct approach ready (cursor stays)" : "Falling back to _pushCmdBrave");
            }
            catch { _useDirectApproach = false; }

            Log("Submenu brave ready");
        }
        catch (System.Exception ex) { Warn(ex.Message); }
    }

    private static void Update_Hook(nint instance, float time, nint methodInfo)
    {
        try
        {
            // Read AP count BEFORE vanilla Update
            int apBefore = -1;
            nint btlLC = *(nint*)(instance + OFF_BTL_LAYOUT_CTRL);
            if (btlLC != 0)
            {
                int cIdx = *(int*)(btlLC + OFF_CHARA_INDEX);
                nint cMgr = *(nint*)(btlLC + 0x218);
                if (cMgr != 0)
                {
                    nint cArr = *(nint*)(cMgr + 0x20);
                    if (cArr != 0 && cIdx >= 0 && cIdx < *(int*)(cArr + 0x18))
                    {
                        nint ch = *(nint*)(cArr + 0x20 + cIdx * 8);
                        if (ch != 0)
                        {
                            nint ap = *(nint*)(ch + 0x148);
                            if (ap != 0) apBefore = *(int*)(ap + 0x10);
                        }
                    }
                }
            }

            // Call original Update — vanilla brave may fire here
            _updateHook.Trampoline(instance, time, methodInfo);

            // Read AP count AFTER vanilla Update
            int apAfter = -1;
            if (btlLC != 0)
            {
                int cIdx = *(int*)(btlLC + OFF_CHARA_INDEX);
                nint cMgr = *(nint*)(btlLC + 0x218);
                if (cMgr != 0)
                {
                    nint cArr = *(nint*)(cMgr + 0x20);
                    if (cArr != 0 && cIdx >= 0 && cIdx < *(int*)(cArr + 0x18))
                    {
                        nint ch = *(nint*)(cArr + 0x20 + cIdx * 8);
                        if (ch != 0)
                        {
                            nint ap = *(nint*)(ch + 0x148);
                            if (ap != 0) apAfter = *(int*)(ap + 0x10);
                        }
                    }
                }
            }

            bool vanillaBraved = apBefore >= 0 && apAfter > apBefore;

            // Only fire our brave if vanilla DIDN'T handle it
            if (!vanillaBraved && (_pressBR != null || _pressBL != null))
            {
                nint mainWndProc = *(nint*)(instance + OFF_MAIN_WND_PROC);
                if (mainWndProc != 0)
                {
                    bool isRButton = *(byte*)(mainWndProc + OFF_IS_RBUTTON_BRAVE) != 0;
                    bool pressed = false;
                    if (isRButton && _pressBR != null) pressed = _pressBR(_pressBR_mi) != 0;
                    else if (!isRButton && _pressBL != null) pressed = _pressBL(_pressBL_mi) != 0;

                    if (pressed && !_braveWasDown)
                    {
                        _braveWasDown = true;
                        DoBrave(instance, mainWndProc);
                    }
                    else if (!pressed)
                    {
                        _braveWasDown = false;
                    }
                }
            }
            else if (vanillaBraved)
            {
                // Reset debounce since vanilla consumed the press
                _braveWasDown = false;
            }
        }
        catch
        {
            try { _updateHook.Trampoline(instance, time, methodInfo); } catch { }
        }
    }

    private static void DoBrave(nint topMenuLayout, nint mainWndProc)
    {
        try
        {
            nint btlLayoutCtrl = *(nint*)(topMenuLayout + OFF_BTL_LAYOUT_CTRL);
            nint dscreenGuiBg = *(nint*)(topMenuLayout + OFF_DSCREEN_GUI_BG);
            if (btlLayoutCtrl == 0 || dscreenGuiBg == 0) return;

            // Check IsRemoving
            if (_isRemoving != null && _isRemoving(dscreenGuiBg, _isRemoving_mi) != 0) return;

            // Get character index and check IsEnableBrave
            int charaIdx = *(int*)(btlLayoutCtrl + OFF_CHARA_INDEX);
            if (_isEnableBrave != null && _isEnableBrave(charaIdx, btlLayoutCtrl, _isEnableBrave_mi) == 0) return;

            if (_useDirectApproach)
            {
                // Direct: AddAP + AddCommandWindow + DecrementPredictedBp
                // No ForceWindowAnimationToEnd — cursor stays!

                // Get BtlChara from BtlLytCharaCtrl
                nint charaCtrl = *(nint*)(btlLayoutCtrl + OFF_CHARA_CTRL);

                // Get ActionPoint: BtlChara -> vtable+0x678 -> GetActionPoint
                // Actually simpler: BtlChara+0x148 = BtlActionPoint
                nint btlChara = 0;
                if (charaCtrl != 0)
                {
                    // Try GetBtlChara — but we don't have it resolved cleanly
                    // Use the character array approach from BattleState
                    // Actually, BtlLayoutCtrl stores current chara differently
                    // For now, get it from the character manager
                }

                // Fallback: use _pushCmdBrave but it's better than nothing
                // Actually let's try: read BtlChara from BtlCharaManager
                nint charaManager = *(nint*)(btlLayoutCtrl + 0x218);
                if (charaManager != 0)
                {
                    nint charaArray = *(nint*)(charaManager + 0x20);
                    if (charaArray != 0 && charaIdx >= 0 && charaIdx < *(int*)(charaArray + 0x18))
                    {
                        btlChara = *(nint*)(charaArray + 0x20 + charaIdx * 8);
                    }
                }

                if (btlChara != 0)
                {
                    // Get ActionPoint at BtlChara+0x148
                    nint actionPoint = *(nint*)(btlChara + 0x148);
                    if (actionPoint != 0)
                    {
                        _addAP(actionPoint, 1);
                        _addCommandWindow(dscreenGuiBg, 0, _addCommandWindow_mi);

                        if (_addPredictedBp != null && charaCtrl != 0)
                            _addPredictedBp(charaCtrl, btlChara, -1, _addPredictedBp_mi);

                        // Play brave sound via BtlSoundManager (at BtlLayoutCtrl+0x40)
                        try
                        {
                            nint btlSoundMgr = *(nint*)(btlLayoutCtrl + 0x40);
                            if (btlSoundMgr != 0)
                            {
                                var soundMgr = new Il2Cpp.BtlSoundManager(btlSoundMgr);
                                soundMgr.PlaySE("BT_SPE_BRAVE", false, 0);
                            }
                        }
                        catch { }
                        // Fallback static
                        try { Il2Cpp.SoundManager.PlaySE("BT_SPE_BRAVE", false, false, 0); } catch { }

                        _logCount++;
                        if (_logCount <= 20) Log("Brave from submenu (direct, cursor stays)!");
                        return;
                    }
                }
            }

            // Fallback: use _pushCmdBrave (cursor jumps but brave works)
            if (_pushCmdBrave != null)
            {
                _pushCmdBrave(mainWndProc, _pushCmdBrave_mi);
                _logCount++;
                if (_logCount <= 20) Log("Brave from submenu (fallback _pushCmdBrave)");
            }
        }
        catch (System.Exception ex)
        {
            _logCount++;
            if (_logCount <= 5) Warn($"DoBrave error: {ex.Message}");
        }
    }

    private static void Resolve<T>(System.Type type, string fieldName, out T fn, out nint mi) where T : System.Delegate
    {
        fn = null; mi = 0;
        try
        {
            var field = type.GetField(fieldName, System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) return;
            mi = (nint)field.GetValue(null);
            if (mi == 0) return;
            fn = Marshal.GetDelegateForFunctionPointer<T>(*(nint*)mi);
            Log($"{typeof(T).Name.Replace("d_", "")} resolved");
        }
        catch { }
    }

    private static void Log(string msg) => Melon<Core>.Logger.Msg($"BraveSubmenu: {msg}");
    private static void Warn(string msg) => Melon<Core>.Logger.Warning($"BraveSubmenu: {msg}");
}
