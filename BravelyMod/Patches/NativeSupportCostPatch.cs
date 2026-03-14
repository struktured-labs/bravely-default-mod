using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

public static unsafe class NativeSupportCostPatch
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_GetParam(int abilityId, byte abiLink, byte bNoAbort, nint methodInfo);

    private static NativeHook<d_GetParam> _hook;
    // Pin delegate to prevent GC collection
    private static d_GetParam _pinnedDelegate;

    public static void Apply()
    {
        try
        {
            var field = typeof(Il2Cpp.SupportAbility).GetField(
                "NativeMethodInfoPtr_GetParam_Public_Static_SupportAbility_Int32_Boolean_Boolean_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

            if (field == null) { Melon<Core>.Logger.Warning("SupportCost: field not found"); return; }

            var methodInfoPtr = (nint)field.GetValue(null);
            if (methodInfoPtr == 0) { Melon<Core>.Logger.Warning("SupportCost: null ptr"); return; }

            var nativePtr = *(nint*)methodInfoPtr;
            Melon<Core>.Logger.Msg($"SupportAbility.GetParam: native @ 0x{nativePtr:X}");

            _pinnedDelegate = GetParam_Hook;
            var hookPtr = Marshal.GetFunctionPointerForDelegate(_pinnedDelegate);
            _hook = new NativeHook<d_GetParam>(nativePtr, hookPtr);
            _hook.Attach();
            Melon<Core>.Logger.Msg("SupportCost: hook attached!");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"SupportCost: failed: {ex.Message}");
        }
    }

    private static int _logCount = 0;

    private static nint GetParam_Hook(int abilityId, byte abiLink, byte bNoAbort, nint methodInfo)
    {
        nint result;
        try
        {
            result = _hook.Trampoline(abilityId, abiLink, bNoAbort, methodInfo);
        }
        catch
        {
            return 0;
        }

        if (result == 0) return 0;

        try
        {
            var costPtr = (int*)(result + 0x30);
            int origCost = *costPtr;
            int target = Core.SupportCostOverride.Value;

            if (origCost > target)
            {
                *costPtr = target;
                _logCount++;
                if (_logCount <= 3)
                    Melon<Core>.Logger.Msg($"[SupportCost] id={abilityId}: {origCost} -> {target}");
            }
        }
        catch
        {
            // Don't crash on bad pointer reads
        }

        return result;
    }
}
