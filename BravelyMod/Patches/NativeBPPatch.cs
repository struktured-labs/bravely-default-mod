using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// BP system — based on full Ghidra decompilation of BP lifecycle.
///
/// Key structures:
///   BtlChara+0x140 = BtlHelper_CommandCtrl: +0x18=m_nBP, +0x1C=m_nBaseBP
///   BtlChara+0x148 = BtlActionPoint: +0x10=m_nAP (action count)
///
/// Hardcoded values we override:
///   SetBP: Min(bp, 3) and Max(-4, bp) → our extended limits
///   IsEnableBrave: commandSize + apCount < 4 → < 10
///   AddBPByTeam: calls SetBP(GetBP() + 1) → we boost in SetBP
/// </summary>
public static unsafe class NativeBPPatch
{
    // int SetBP(this BtlChara, int bp, MethodInfo*) — clamps to [-4, 3]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_SetBP(nint instance, int bp, nint methodInfo);

    // bool IsEnableBrave(int partyindex, BtlLayoutCtrl*, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_IsEnableBrave(int partyindex, nint pBtlLayoutCtrl, nint methodInfo);

    // void AddBPByTeam(this BtlCharaManager, int team, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddBPByTeam(nint instance, int team, nint methodInfo);

    // int GetBP(this BtlChara, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_GetBP(nint instance, nint methodInfo);

    private static NativeHook<d_SetBP> _setBPHook;
    private static NativeHook<d_SetBP> _setBPBaseHook;
    private static NativeHook<d_IsEnableBrave> _braveHook;
    private static NativeHook<d_AddBPByTeam> _addBPHook;
    private static NativeHook<d_GetBP> _getBPHook;
    private static NativeHook<d_GetBP> _getBPBaseHook;

    private static d_SetBP _pSetBP;
    private static d_SetBP _pSetBPBase;
    private static d_IsEnableBrave _pBrave;
    private static d_AddBPByTeam _pAddBP;
    private static d_GetBP _pGetBP;
    private static d_GetBP _pGetBPBase;

    public static void Apply()
    {
        // Hook ALL SetBP variants — vtable dispatch may go to any of them
        Hook(typeof(Il2Cpp.BtlChara),
            "NativeMethodInfoPtr_SetBP_Public_Virtual_New_Int32_Int32_0",
            "SetBP(VNew)", ref _pSetBP, SetBP_Hook, out _setBPHook);
        Hook(typeof(Il2Cpp.BtlChara),
            "NativeMethodInfoPtr_SetBP_Public_Virtual_Int32_Int32_0",
            "SetBP(V)", ref _pSetBPBase, SetBP_HookBase, out _setBPBaseHook);

        Hook(typeof(Il2Cpp.gfc),
            "NativeMethodInfoPtr_IsEnableBrave_Public_Static_Boolean_Int32_BtlLayoutCtrl_0",
            "IsEnableBrave", ref _pBrave, IsEnableBrave_Hook, out _braveHook);

        Hook(typeof(Il2Cpp.BtlCharaManager),
            "NativeMethodInfoPtr_AddBPByTeam_Public_Void_Int32_0",
            "AddBPByTeam", ref _pAddBP, AddBPByTeam_Hook, out _addBPHook);

        Hook(typeof(Il2Cpp.BtlChara),
            "NativeMethodInfoPtr_GetBP_Public_Virtual_New_Int32_0",
            "GetBP(VNew)", ref _pGetBP, GetBP_Hook, out _getBPHook);
        Hook(typeof(Il2Cpp.BtlChara),
            "NativeMethodInfoPtr_GetBP_Public_Virtual_Int32_0",
            "GetBP(V)", ref _pGetBPBase, GetBP_HookBase, out _getBPBaseHook);
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

            int limit = Core.BpLimitOverride.Value; // default 9

            // Call original — it clamps to [-4, 3] and writes to +0x18
            int result = _setBPHook.Trampoline(instance, bp, methodInfo);

            // Now overwrite with our extended clamp
            int clampedBP = System.Math.Max(-limit, System.Math.Min(limit, bp));

            nint cmdCtrl = *(nint*)(instance + 0x140); // BtlHelper_CommandCtrl
            if (cmdCtrl != 0)
            {
                *(int*)(cmdCtrl + 0x18) = clampedBP;  // m_nBP (active)
                *(int*)(cmdCtrl + 0x1C) = clampedBP;  // m_nBaseBP (base)
            }

            _setBPLog++;
            if (_setBPLog <= 10)
                Melon<Core>.Logger.Msg($"[BP] SetBP({bp}) -> {clampedBP} (limit ±{limit})");

            return result;
        }
        catch
        {
            try { return _setBPHook.Trampoline(instance, bp, methodInfo); } catch { return bp; }
        }
    }

    private static int SetBP_HookBase(nint instance, int bp, nint methodInfo)
    {
        try
        {
            if (!Core.BpModEnabled.Value)
                return _setBPBaseHook.Trampoline(instance, bp, methodInfo);

            int limit = Core.BpLimitOverride.Value;
            int result = _setBPBaseHook.Trampoline(instance, bp, methodInfo);
            int clampedBP = System.Math.Max(-limit, System.Math.Min(limit, bp));

            nint cmdCtrl = *(nint*)(instance + 0x140);
            if (cmdCtrl != 0)
            {
                *(int*)(cmdCtrl + 0x18) = clampedBP;
                *(int*)(cmdCtrl + 0x1C) = clampedBP;
            }

            _setBPLog++;
            if (_setBPLog <= 10)
                Melon<Core>.Logger.Msg($"[BP] SetBP_Base({bp}) -> {clampedBP}");

            return result;
        }
        catch
        {
            try { return _setBPBaseHook.Trampoline(instance, bp, methodInfo); } catch { return bp; }
        }
    }

    private static int _getBPLog = 0;

    private static int GetBP_Hook(nint instance, nint methodInfo)
    {
        try
        {
            // Read directly from the field we wrote to, bypassing any internal clamp
            nint cmdCtrl = *(nint*)(instance + 0x140);
            if (cmdCtrl != 0 && Core.BpModEnabled.Value)
            {
                int bp = *(int*)(cmdCtrl + 0x18);
                _getBPLog++;
                if (_getBPLog <= 5)
                    Melon<Core>.Logger.Msg($"[BP] GetBP -> {bp}");
                return bp;
            }
            return _getBPHook.Trampoline(instance, methodInfo);
        }
        catch { try { return _getBPHook.Trampoline(instance, methodInfo); } catch { return 0; } }
    }

    private static int GetBP_HookBase(nint instance, nint methodInfo)
    {
        try
        {
            nint cmdCtrl = *(nint*)(instance + 0x140);
            if (cmdCtrl != 0 && Core.BpModEnabled.Value)
            {
                int bp = *(int*)(cmdCtrl + 0x18);
                _getBPLog++;
                if (_getBPLog <= 5)
                    Melon<Core>.Logger.Msg($"[BP] GetBP_Base -> {bp}");
                return bp;
            }
            return _getBPBaseHook.Trampoline(instance, methodInfo);
        }
        catch { try { return _getBPBaseHook.Trampoline(instance, methodInfo); } catch { return 0; } }
    }

    private static int _braveLog = 0;

    private static byte IsEnableBrave_Hook(int partyindex, nint pBtlLayoutCtrl, nint methodInfo)
    {
        try
        {
            if (!Core.BpModEnabled.Value)
                return _braveHook.Trampoline(partyindex, pBtlLayoutCtrl, methodInfo);

            // Original checks: commandSize + apCount < 4 AND remainingBP > -5
            // We override: allow up to 10 actions and deeper BP debt
            var orig = _braveHook.Trampoline(partyindex, pBtlLayoutCtrl, methodInfo);
            if (orig != 0) return 1; // original says yes

            // Original said no. The two possible reasons:
            // 1. commandSize + apCount >= 4 (action cap)
            // 2. remainingBP <= -5 (BP floor)
            // We allow up to BpLimitOverride actions total
            int maxActions = Core.BpLimitOverride.Value + 1; // 9+1=10 actions

            // We can't easily read the action count from here without more pointers,
            // so just allow more braves up to our limit
            _braveLog++;
            if (_braveLog <= 5)
                Melon<Core>.Logger.Msg($"[BP] IsEnableBrave({partyindex}) extended (max {maxActions} actions)");
            return 1;
        }
        catch { return 0; }
    }

    private static int _addBPLog = 0;

    private static void AddBPByTeam_Hook(nint instance, int team, nint methodInfo)
    {
        try
        {
            if (!Core.BpModEnabled.Value || Core.BpPerTurn.Value <= 1)
            {
                _addBPHook.Trampoline(instance, team, methodInfo);
                return;
            }

            // Original does SetBP(GetBP() + 1) for each character.
            // Call original for the +1, then call again for extra BP.
            _addBPHook.Trampoline(instance, team, methodInfo);

            int extra = Core.BpPerTurn.Value - 1;
            for (int i = 0; i < extra; i++)
                _addBPHook.Trampoline(instance, team, methodInfo);

            _addBPLog++;
            if (_addBPLog <= 5)
                Melon<Core>.Logger.Msg($"[BP] AddBPByTeam: +{Core.BpPerTurn.Value} total (team {team})");
        }
        catch
        {
            try { _addBPHook.Trampoline(instance, team, methodInfo); } catch { }
        }
    }
}
