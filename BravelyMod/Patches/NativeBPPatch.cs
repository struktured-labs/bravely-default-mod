using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// BP system mods:
/// - BtlCharaPlayer.SetBP: raise the internal clamp from BP_MAX=3 to configurable
/// - IsEnableBrave: extend brave allowance (vanilla allows 4 actions, we allow more)
/// - SetDelayBPUp: multiply BP gained per turn
/// </summary>
public static unsafe class NativeBPPatch
{
    // int BtlCharaPlayer.SetBP(this, int bp, MethodInfo*) — returns clamped value
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_SetBP(nint instance, int bp, nint methodInfo);

    // bool IsEnableBrave(int partyindex, BtlLayoutCtrl*, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_IsEnableBrave(int partyindex, nint pBtlLayoutCtrl, nint methodInfo);

    // void SetDelayBPUp(this, float delayTime, int nBPUp, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SetDelayBPUp(nint instance, float delayTime, int nBPUp, nint methodInfo);

    private static NativeHook<d_SetBP> _setBPHook;
    private static NativeHook<d_IsEnableBrave> _braveHook;
    private static NativeHook<d_SetDelayBPUp> _delayBPHook;

    private static d_SetBP _pSetBP;
    private static d_IsEnableBrave _pBrave;
    private static d_SetDelayBPUp _pDelayBP;

    public static void Apply()
    {
        // Hook BtlCharaPlayer.SetBP — the override that clamps to BP_MAX
        Hook(typeof(Il2Cpp.BtlChara),
            "NativeMethodInfoPtr_SetBP_Public_Virtual_New_Int32_Int32_0",
            "SetBP", ref _pSetBP, SetBP_Hook, out _setBPHook);

        // Hook IsEnableBrave
        Hook(typeof(Il2Cpp.gfc),
            "NativeMethodInfoPtr_IsEnableBrave_Public_Static_Boolean_Int32_BtlLayoutCtrl_0",
            "IsEnableBrave", ref _pBrave, IsEnableBrave_Hook, out _braveHook);

        // Hook SetDelayBPUp for extra BP per turn
        Hook(typeof(Il2Cpp.BtlChara),
            "NativeMethodInfoPtr_SetDelayBPUp_Public_Virtual_New_Void_Single_Int32_0",
            "SetDelayBPUp", ref _pDelayBP, SetDelayBPUp_Hook, out _delayBPHook);
    }

    private static void Hook<T>(System.Type type, string fieldName, string name,
        ref T pinned, T hookDelegate, out NativeHook<T> hook) where T : System.Delegate
    {
        hook = default;
        try
        {
            var field = type.GetField(fieldName,
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Melon<Core>.Logger.Warning($"{name}: field not found"); return; }
            var mi = (nint)field.GetValue(null);
            if (mi == 0) return;
            var native = *(nint*)mi;
            pinned = hookDelegate;
            var hookPtr = Marshal.GetFunctionPointerForDelegate(pinned);
            hook = new NativeHook<T>(native, hookPtr);
            hook.Attach();
            Melon<Core>.Logger.Msg($"{name}: native hook @ 0x{native:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"{name}: {ex.Message}");
        }
    }

    private static int _setBPLog = 0;

    private static int SetBP_Hook(nint instance, int bp, nint methodInfo)
    {
        try
        {
            if (!Core.BpModEnabled.Value)
                return _setBPHook.Trampoline(instance, bp, methodInfo);

            // Decompiled SetBP: clamps to Max(-4, Min(bp, 3_or_4)), stores at this[0x28]+0x18
            // We call original (which clamps to 3), then overwrite with our extended clamp
            int limit = Core.BpLimitOverride.Value;
            int clampedBP = System.Math.Max(-limit, System.Math.Min(limit, bp));

            // Call original for side effects (returns old_bp - new_bp)
            _setBPHook.Trampoline(instance, bp, methodInfo);

            // Overwrite: this[0x28] is a pointer (offset 0x140), +0x18 is the BP value
            nint statePtr = *(nint*)(instance + 0x140);
            if (statePtr != 0)
            {
                *(int*)(statePtr + 0x18) = clampedBP;
            }

            _setBPLog++;
            if (_setBPLog <= 5)
                Melon<Core>.Logger.Msg($"[BP] SetBP({bp}) -> {clampedBP} (limit ±{limit})");

            return clampedBP;
        }
        catch
        {
            try { return _setBPHook.Trampoline(instance, bp, methodInfo); } catch { return bp; }
        }
    }

    private static int _braveLog = 0;

    private static byte IsEnableBrave_Hook(int partyindex, nint pBtlLayoutCtrl, nint methodInfo)
    {
        try
        {
            if (!Core.BpModEnabled.Value)
                return _braveHook.Trampoline(partyindex, pBtlLayoutCtrl, methodInfo);

            // Let original decide first
            var orig = _braveHook.Trampoline(partyindex, pBtlLayoutCtrl, methodInfo);
            if (orig != 0) return 1;

            // Original said no. Allow if we haven't hit our extended negative limit.
            // We can't easily read BP here, so just allow up to (limit - 3) extra braves
            int extraAllowed = Core.BpLimitOverride.Value - 3;
            if (extraAllowed <= 0) return 0;

            _braveLog++;
            if (_braveLog <= 5)
                Melon<Core>.Logger.Msg($"[BP] IsEnableBrave({partyindex}) extended");
            return 1;
        }
        catch { return 0; }
    }

    private static int _delayLog = 0;

    private static void SetDelayBPUp_Hook(nint instance, float delayTime, int nBPUp, nint methodInfo)
    {
        try
        {
            if (Core.BpModEnabled.Value)
            {
                int extraBP = Core.BpPerTurn.Value;
                _delayLog++;
                if (_delayLog <= 5)
                    Melon<Core>.Logger.Msg($"[BP] SetDelayBPUp: {nBPUp} -> {nBPUp * extraBP} (x{extraBP})");
                nBPUp *= extraBP;
            }
            _delayBPHook.Trampoline(instance, delayTime, nBPUp, methodInfo);
        }
        catch
        {
            try { _delayBPHook.Trampoline(instance, delayTime, nBPUp, methodInfo); } catch { }
        }
    }
}
