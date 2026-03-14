using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Native function pointer hooks for EXP/JP.
/// Bypasses Harmony which can't detour IL2CPP methods on Unity 6.
/// </summary>
public static unsafe class NativeExpPatch
{
    // IL2CPP calling convention: (IntPtr instance, params..., IntPtr methodInfo)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_ReviseAddEXP(nint instance, int exp, int bonusexp, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_ReviseAddJEXP(nint instance, int jexp, int bonusjexp, nint methodInfo);

    private static NativeHook<d_ReviseAddEXP> _expHook;
    private static NativeHook<d_ReviseAddJEXP> _jexpHook;

    public static void Apply()
    {
        HookMethod<d_ReviseAddEXP>(
            "ReviseAddEXP",
            "NativeMethodInfoPtr_ReviseAddEXP_Public_Void_Int32_Int32_0",
            typeof(Il2Cpp.BtlResultCtrl),
            ReviseAddEXP_Hook,
            out _expHook);

        HookMethod<d_ReviseAddJEXP>(
            "ReviseAddJEXP",
            "NativeMethodInfoPtr_ReviseAddJEXP_Public_Void_Int32_Int32_0",
            typeof(Il2Cpp.BtlResultCtrl),
            ReviseAddJEXP_Hook,
            out _jexpHook);
    }

    private static void HookMethod<T>(
        string name,
        string ptrFieldName,
        System.Type type,
        T hookDelegate,
        out NativeHook<T> hook) where T : System.Delegate
    {
        hook = default;
        try
        {
            var field = type.GetField(ptrFieldName,
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null)
            {
                Melon<Core>.Logger.Warning($"{name}: field {ptrFieldName} not found");
                return;
            }

            var methodInfoPtr = (nint)field.GetValue(null);
            if (methodInfoPtr == 0)
            {
                Melon<Core>.Logger.Warning($"{name}: method info ptr is null");
                return;
            }

            // Il2CppMethodInfo->methodPointer is at offset 0
            var nativePtr = *(nint*)methodInfoPtr;
            Melon<Core>.Logger.Msg($"{name}: native @ 0x{nativePtr:X}");

            var hookPtr = Marshal.GetFunctionPointerForDelegate(hookDelegate);
            hook = new NativeHook<T>(nativePtr, hookPtr);
            hook.Attach();
            Melon<Core>.Logger.Msg($"{name}: native hook attached!");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"{name}: hook failed: {ex.Message}");
        }
    }

    private static int _expCallCount = 0;

    private static void ReviseAddEXP_Hook(nint instance, int exp, int bonusexp, nint methodInfo)
    {
        _expCallCount++;
        if (_expCallCount <= 5)
            Melon<Core>.Logger.Msg($"[NATIVE EXP] #{_expCallCount} called! exp={exp} bonus={bonusexp} inst=0x{instance:X}");

        if (Core.ExpBoostEnabled.Value)
        {
            var mult = Core.ExpMultiplier.Value;
            exp = (int)(exp * mult);
            bonusexp = (int)(bonusexp * mult);
        }

        if (_expCallCount <= 5)
            Melon<Core>.Logger.Msg($"[NATIVE EXP] #{_expCallCount} -> exp={exp} bonus={bonusexp}");

        _expHook.Trampoline(instance, exp, bonusexp, methodInfo);
    }

    private static void ReviseAddJEXP_Hook(nint instance, int jexp, int bonusjexp, nint methodInfo)
    {
        if (Core.ExpBoostEnabled.Value)
        {
            var mult = Core.JexpMultiplier.Value;
            jexp = (int)(jexp * mult);
            bonusjexp = (int)(bonusjexp * mult);
        }
        _jexpHook.Trampoline(instance, jexp, bonusjexp, methodInfo);
    }
}
