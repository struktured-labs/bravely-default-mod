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

    // void SetBaseBP(this, int basebp, MethodInfo*) — virtual new (override)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SetBaseBP(nint instance, int basebp, nint methodInfo);

    // int GetBP(this, MethodInfo*) — reads from +0x18 only, misses base BP at +0x1C
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_GetBP(nint instance, nint methodInfo);

    private static NativeHook<d_SetBP> _setBPHook;
    private static NativeHook<d_IsEnableBrave> _braveHook;
    private static NativeHook<d_SetDelayBPUp> _delayBPHook;
    private static NativeHook<d_SetBaseBP> _setBaseBPHook;
    private static NativeHook<d_GetBP> _getBPHook;

    private static d_SetBP _pSetBP;
    private static d_IsEnableBrave _pBrave;
    private static d_SetDelayBPUp _pDelayBP;
    private static d_SetBaseBP _pSetBaseBP;
    private static d_GetBP _pGetBP;

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

        // Hook SetBaseBP — turn recovery writes base BP to +0x1C
        Hook(typeof(Il2Cpp.BtlChara),
            "NativeMethodInfoPtr_SetBaseBP_Public_Virtual_New_Void_Int32_0",
            "SetBaseBP", ref _pSetBaseBP, SetBaseBP_Hook, out _setBaseBPHook);

        // Hook GetBP — sync the active BP (+0x18) with boosted base BP (+0x1C)
        Hook(typeof(Il2Cpp.BtlChara),
            "NativeMethodInfoPtr_GetBP_Public_Virtual_New_Int32_0",
            "GetBP", ref _pGetBP, GetBP_Hook, out _getBPHook);
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

            // Read current BP before the change
            int currentBP = 0;
            nint stateCheck = *(nint*)(instance + 0x140);
            if (stateCheck != 0)
                currentBP = *(int*)(stateCheck + 0x18);

            // If BP is going UP (recovery), multiply the gain
            int extraBP = Core.BpPerTurn.Value;
            if (bp > currentBP && extraBP > 1)
            {
                int gain = bp - currentBP;
                bp = currentBP + (gain * extraBP);
                _setBPLog++;
                if (_setBPLog <= 5)
                    Melon<Core>.Logger.Msg($"[BP] Recovery boosted: {currentBP} + {gain}*{extraBP} = {bp}");
            }

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

            // Just use the original check — don't extend brave count beyond vanilla
            // BP storage is already extended to 9 via SetBP hook, so starting with
            // more BP naturally gives more actions without needing to override this
            return _braveHook.Trampoline(partyindex, pBtlLayoutCtrl, methodInfo);
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

    private static int _getBPLog = 0;

    private static int GetBP_Hook(nint instance, nint methodInfo)
    {
        try
        {
            int orig = _getBPHook.Trampoline(instance, methodInfo);
            if (!Core.BpModEnabled.Value) return orig;

            // GetBP reads +0x18 (active BP, clamped to 3 by SetBP)
            // SetBaseBP writes boosted value to +0x1C
            // When base BP > active BP, sync active up to base
            nint statePtr = *(nint*)(instance + 0x140);
            if (statePtr != 0)
            {
                int baseBP = *(int*)(statePtr + 0x1C);
                if (baseBP > orig)
                {
                    // Also write it to +0x18 so everything stays in sync
                    int limit = Core.BpLimitOverride.Value;
                    int clamped = System.Math.Min(baseBP, limit);
                    *(int*)(statePtr + 0x18) = clamped;

                    _getBPLog++;
                    if (_getBPLog <= 5)
                        Melon<Core>.Logger.Msg($"[BP] GetBP synced: active {orig} -> base {clamped}");
                    return clamped;
                }
            }
            return orig;
        }
        catch { try { return _getBPHook.Trampoline(instance, methodInfo); } catch { return 0; } }
    }

    private static int _baseBPLog = 0;

    private static void SetBaseBP_Hook(nint instance, int basebp, nint methodInfo)
    {
        try
        {
            if (Core.BpModEnabled.Value)
            {
                _baseBPLog++;
                if (_baseBPLog <= 10)
                    Melon<Core>.Logger.Msg($"[BP] SetBaseBP({basebp}) called");

                // If basebp is going up (recovery), multiply the gain
                // BaseBP typically goes 0 -> 1 each turn. We make it 0 -> 2.
                if (basebp > 0)
                {
                    int boosted = basebp * Core.BpPerTurn.Value;
                    if (_baseBPLog <= 10)
                        Melon<Core>.Logger.Msg($"[BP] SetBaseBP {basebp} -> {boosted} (x{Core.BpPerTurn.Value})");
                    basebp = boosted;
                }
            }
            _setBaseBPHook.Trampoline(instance, basebp, methodInfo);
        }
        catch
        {
            try { _setBaseBPHook.Trampoline(instance, basebp, methodInfo); } catch { }
        }
    }
}
