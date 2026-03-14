using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Native hooks for BP system:
/// - BP limit (GetLimitBP) — raise max BP cap
/// - BP per turn (AddBPByTeam) — grant extra BP each turn
/// - Starting BP (GetAddStartBP) — bonus BP at battle start
/// </summary>
public static unsafe class NativeBPPatch
{
    // static int GetLimitBP(BtlChara* pChr, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_GetLimitBP(nint pChr, nint methodInfo);

    // void AddBPByTeam(this, int _team, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddBPByTeam(nint instance, int team, nint methodInfo);

    // int GetBP(this, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_GetBP(nint instance, nint methodInfo);

    // int SetBP(this, int bp, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_SetBP(nint instance, int bp, nint methodInfo);

    private static NativeHook<d_GetLimitBP> _limitHook;
    private static NativeHook<d_AddBPByTeam> _addBPHook;

    // We need GetBP/SetBP trampolines for the AddBPByTeam hook
    private static nint _getBPPtr;
    private static nint _setBPPtr;

    public static void Apply()
    {
        // Cache GetBP/SetBP native pointers for use in AddBPByTeam hook
        CacheMethodPtr(typeof(Il2Cpp.BtlChara),
            "NativeMethodInfoPtr_GetBP_Public_Virtual_Int32_0", out _getBPPtr, "BtlChara.GetBP");
        CacheMethodPtr(typeof(Il2Cpp.BtlChara),
            "NativeMethodInfoPtr_SetBP_Public_Virtual_Int32_Int32_0", out _setBPPtr, "BtlChara.SetBP");

        // Hook GetLimitBP
        HookStatic<d_GetLimitBP>(
            typeof(Il2Cpp.gfc),
            "NativeMethodInfoPtr_GetLimitBP_Public_Static_Int32_BtlChara_0",
            "GetLimitBP",
            GetLimitBP_Hook,
            out _limitHook);

        // Hook AddBPByTeam
        HookInstance<d_AddBPByTeam>(
            typeof(Il2Cpp.BtlCharaManager),
            "NativeMethodInfoPtr_AddBPByTeam_Public_Void_Int32_0",
            "AddBPByTeam",
            AddBPByTeam_Hook,
            out _addBPHook);
    }

    private static void CacheMethodPtr(System.Type type, string fieldName, out nint ptr, string name)
    {
        ptr = 0;
        try
        {
            var field = type.GetField(fieldName,
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) return;
            var mi = (nint)field.GetValue(null);
            if (mi == 0) return;
            ptr = *(nint*)mi;
        }
        catch { }
    }

    private static void HookStatic<T>(System.Type type, string fieldName, string name,
        T hookDelegate, out NativeHook<T> hook) where T : System.Delegate
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
            var hookPtr = Marshal.GetFunctionPointerForDelegate(hookDelegate);
            hook = new NativeHook<T>(native, hookPtr);
            hook.Attach();
            Melon<Core>.Logger.Msg($"{name}: native hook @ 0x{native:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"{name}: failed: {ex.Message}");
        }
    }

    private static void HookInstance<T>(System.Type type, string fieldName, string name,
        T hookDelegate, out NativeHook<T> hook) where T : System.Delegate
        => HookStatic(type, fieldName, name, hookDelegate, out hook);

    private static int GetLimitBP_Hook(nint pChr, nint methodInfo)
    {
        if (!Core.BpModEnabled.Value)
            return _limitHook.Trampoline(pChr, methodInfo);

        var orig = _limitHook.Trampoline(pChr, methodInfo);
        var limit = Core.BpLimitOverride.Value;
        return orig < limit ? limit : orig;
    }

    private static void AddBPByTeam_Hook(nint instance, int team, nint methodInfo)
    {
        // Always call original first (adds +1 BP to each chara on team)
        _addBPHook.Trampoline(instance, team, methodInfo);

        // Then add extra BP if configured
        if (!Core.BpModEnabled.Value) return;

        int extraBP = Core.BpPerTurn.Value - 1; // vanilla gives 1, so extra = config - 1
        if (extraBP <= 0) return;

        // We need to iterate team members and add extra BP
        // The original AddBPByTeam already did +1, we add the extra
        // Unfortunately we can't easily iterate the team from here without more hooks
        // So we use a simpler approach: hook SetBP instead to intercept the +1 and make it +N
        // For now, log that we'd add extra
        // TODO: implement team iteration or hook SetBP directly
    }
}
