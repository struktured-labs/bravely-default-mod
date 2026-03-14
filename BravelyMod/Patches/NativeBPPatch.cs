using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

public static unsafe class NativeBPPatch
{
    // static int GetLimitBP(BtlChara* pChr, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_GetLimitBP(nint pChr, nint methodInfo);

    private static NativeHook<d_GetLimitBP> _limitHook;
    private static d_GetLimitBP _pinnedLimitDelegate;

    public static void Apply()
    {
        try
        {
            var field = typeof(Il2Cpp.gfc).GetField(
                "NativeMethodInfoPtr_GetLimitBP_Public_Static_Int32_BtlChara_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

            if (field == null) { Melon<Core>.Logger.Warning("GetLimitBP: field not found"); return; }

            var mi = (nint)field.GetValue(null);
            if (mi == 0) { Melon<Core>.Logger.Warning("GetLimitBP: null ptr"); return; }

            var native = *(nint*)mi;
            _pinnedLimitDelegate = GetLimitBP_Hook;
            var hookPtr = Marshal.GetFunctionPointerForDelegate(_pinnedLimitDelegate);
            _limitHook = new NativeHook<d_GetLimitBP>(native, hookPtr);
            _limitHook.Attach();
            Melon<Core>.Logger.Msg($"GetLimitBP: native hook @ 0x{native:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"GetLimitBP: failed: {ex.Message}");
        }
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
        catch
        {
            return 3; // vanilla default
        }
    }
}
