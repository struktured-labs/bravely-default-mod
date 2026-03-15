using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// BP system mods:
/// - IsEnableBrave: always allow braving (raises effective BP cap)
/// - GetLimitBP: raise the BP cap value
/// - AddBPByTeam: grant extra BP per turn
/// </summary>
public static unsafe class NativeBPPatch
{
    // static bool IsEnableBrave(int partyindex, BtlLayoutCtrl* pBtlLayoutCtrl, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_IsEnableBrave(int partyindex, nint pBtlLayoutCtrl, nint methodInfo);

    // static int GetLimitBP(BtlChara* pChr, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_GetLimitBP(nint pChr, nint methodInfo);

    // void AddBPByTeam(this, int _team, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddBPByTeam(nint instance, int team, nint methodInfo);

    private static NativeHook<d_IsEnableBrave> _braveHook;
    private static NativeHook<d_GetLimitBP> _limitHook;
    private static NativeHook<d_AddBPByTeam> _addBPHook;

    private static d_IsEnableBrave _pinnedBrave;
    private static d_GetLimitBP _pinnedLimit;
    private static d_AddBPByTeam _pinnedAddBP;

    public static void Apply()
    {
        // Hook IsEnableBrave — always allow brave
        Hook(typeof(Il2Cpp.gfc),
            "NativeMethodInfoPtr_IsEnableBrave_Public_Static_Boolean_Int32_BtlLayoutCtrl_0",
            "IsEnableBrave", ref _pinnedBrave, IsEnableBrave_Hook, out _braveHook);

        // Hook GetLimitBP — raise cap
        Hook(typeof(Il2Cpp.gfc),
            "NativeMethodInfoPtr_GetLimitBP_Public_Static_Int32_BtlChara_0",
            "GetLimitBP", ref _pinnedLimit, GetLimitBP_Hook, out _limitHook);

        // Hook AddBPByTeam — extra BP per turn
        Hook(typeof(Il2Cpp.BtlCharaManager),
            "NativeMethodInfoPtr_AddBPByTeam_Public_Void_Int32_0",
            "AddBPByTeam", ref _pinnedAddBP, AddBPByTeam_Hook, out _addBPHook);
    }

    private static void Hook<T>(System.Type type, string fieldName, string name,
        ref T pinnedDelegate, T hookDelegate, out NativeHook<T> hook) where T : System.Delegate
    {
        hook = default;
        try
        {
            var field = type.GetField(fieldName,
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Melon<Core>.Logger.Warning($"{name}: field not found"); return; }
            var mi = (nint)field.GetValue(null);
            if (mi == 0) { Melon<Core>.Logger.Warning($"{name}: null ptr"); return; }
            var native = *(nint*)mi;
            pinnedDelegate = hookDelegate;
            var hookPtr = Marshal.GetFunctionPointerForDelegate(pinnedDelegate);
            hook = new NativeHook<T>(native, hookPtr);
            hook.Attach();
            Melon<Core>.Logger.Msg($"{name}: native hook @ 0x{native:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"{name}: failed: {ex.Message}");
        }
    }

    private static int _braveLogCount = 0;

    private static byte IsEnableBrave_Hook(int partyindex, nint pBtlLayoutCtrl, nint methodInfo)
    {
        try
        {
            if (!Core.BpModEnabled.Value)
                return _braveHook.Trampoline(partyindex, pBtlLayoutCtrl, methodInfo);

            // Always allow brave
            _braveLogCount++;
            if (_braveLogCount <= 3)
                Melon<Core>.Logger.Msg($"[BP] IsEnableBrave({partyindex}) -> true");
            return 1;
        }
        catch { return 1; }
    }

    private static int GetLimitBP_Hook(nint pChr, nint methodInfo)
    {
        try
        {
            var orig = _limitHook.Trampoline(pChr, methodInfo);
            if (!Core.BpModEnabled.Value) return orig;
            var limit = Core.BpLimitOverride.Value;
            return orig < limit ? limit : orig;
        }
        catch { return 3; }
    }

    private static int _addBPLogCount = 0;

    private static void AddBPByTeam_Hook(nint instance, int team, nint methodInfo)
    {
        try
        {
            // Call original (+1 BP to each character on team)
            _addBPHook.Trampoline(instance, team, methodInfo);

            if (!Core.BpModEnabled.Value) return;

            int extraCalls = Core.BpPerTurn.Value - 1;
            if (extraCalls <= 0) return;

            // Call original again for extra BP
            for (int i = 0; i < extraCalls; i++)
                _addBPHook.Trampoline(instance, team, methodInfo);

            _addBPLogCount++;
            if (_addBPLogCount <= 3)
                Melon<Core>.Logger.Msg($"[BP] AddBPByTeam: +{Core.BpPerTurn.Value} total (team {team})");
        }
        catch { }
    }
}
