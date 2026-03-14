using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

public static unsafe class NativeBuffPatch
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate float d_GetBuffMax(nint instance, int buffType, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_IsBuffLimit(nint instance, int buffType, nint methodInfo);

    private static NativeHook<d_GetBuffMax> _maxHook;
    private static NativeHook<d_IsBuffLimit> _limitHook;
    private static NativeHook<d_IsBuffLimit> _specialLimitHook;

    // Pin delegates
    private static d_GetBuffMax _pinnedMax;
    private static d_IsBuffLimit _pinnedLimit;
    private static d_IsBuffLimit _pinnedSpecialLimit;

    public static void Apply()
    {
        Hook(typeof(Il2Cpp.BtlStatusManager),
            "NativeMethodInfoPtr_IsBuffLimit_Public_Boolean_Int32_0",
            "IsBuffLimit", ref _pinnedLimit, IsBuffLimit_Hook, out _limitHook);

        Hook(typeof(Il2Cpp.BtlStatusManager),
            "NativeMethodInfoPtr_IsSpecialBuffLimit_Public_Boolean_Int32_0",
            "IsSpecialBuffLimit", ref _pinnedSpecialLimit, IsSpecialBuffLimit_Hook, out _specialLimitHook);

        Hook(typeof(Il2Cpp.BtlDataManager),
            "NativeMethodInfoPtr_GetBuffMax_Public_Single_Int32_0",
            "GetBuffMax", ref _pinnedMax, GetBuffMax_Hook, out _maxHook);
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

    private static byte IsBuffLimit_Hook(nint instance, int buffType, nint methodInfo)
    {
        return 0; // never at limit
    }

    private static byte IsSpecialBuffLimit_Hook(nint instance, int buffType, nint methodInfo)
    {
        return 0;
    }

    private static float GetBuffMax_Hook(nint instance, int buffType, nint methodInfo)
    {
        try
        {
            var orig = _maxHook.Trampoline(instance, buffType, methodInfo);
            return orig * 2.0f;
        }
        catch
        {
            return 1.5f; // vanilla default
        }
    }
}
