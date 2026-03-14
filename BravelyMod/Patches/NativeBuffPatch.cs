using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Raises or removes buff/debuff caps.
/// Hooks BtlDataManager.GetBuffMax to return higher caps.
/// Hooks BtlStatusManager.IsBuffLimit to always return false.
/// </summary>
public static unsafe class NativeBuffPatch
{
    // float GetBuffMax(this, int buffType, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate float d_GetBuffMax(nint instance, int buffType, nint methodInfo);

    // bool IsBuffLimit(this, int buffType, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_IsBuffLimit(nint instance, int buffType, nint methodInfo);

    private static NativeHook<d_GetBuffMax> _maxHook;
    private static NativeHook<d_IsBuffLimit> _limitHook;
    private static NativeHook<d_IsBuffLimit> _specialLimitHook;

    public static void Apply()
    {
        Hook<d_IsBuffLimit>(
            typeof(Il2Cpp.BtlStatusManager),
            "NativeMethodInfoPtr_IsBuffLimit_Public_Boolean_Int32_0",
            "IsBuffLimit",
            IsBuffLimit_Hook,
            out _limitHook);

        Hook<d_IsBuffLimit>(
            typeof(Il2Cpp.BtlStatusManager),
            "NativeMethodInfoPtr_IsSpecialBuffLimit_Public_Boolean_Int32_0",
            "IsSpecialBuffLimit",
            IsSpecialBuffLimit_Hook,
            out _specialLimitHook);

        Hook<d_GetBuffMax>(
            typeof(Il2Cpp.BtlDataManager),
            "NativeMethodInfoPtr_GetBuffMax_Public_Single_Int32_0",
            "GetBuffMax",
            GetBuffMax_Hook,
            out _maxHook);
    }

    private static void Hook<T>(System.Type type, string fieldName, string name,
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

    private static byte IsBuffLimit_Hook(nint instance, int buffType, nint methodInfo)
    {
        // Always allow more buffs
        return 0; // false
    }

    private static byte IsSpecialBuffLimit_Hook(nint instance, int buffType, nint methodInfo)
    {
        return 0; // false
    }

    private static float GetBuffMax_Hook(nint instance, int buffType, nint methodInfo)
    {
        var orig = _maxHook.Trampoline(instance, buffType, methodInfo);
        // Double the buff cap (e.g., 150% -> 300%)
        return orig * 2.0f;
    }
}
