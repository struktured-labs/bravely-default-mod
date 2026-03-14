using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Fixes the battle results display to show multiplied EXP/JP/Gold values.
/// Hooks BtlLowerResultLayout2.SetResult — after the original clones ResultData
/// to this+0x70, we multiply the exp/jobexp/gil fields.
/// ResultData offsets: gil=0x10, exp=0x14, jobexp=0x18
/// </summary>
public static unsafe class NativeResultDisplayPatch
{
    // void SetResult(this, ResultData resultData, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SetResult(nint instance, nint resultData, nint methodInfo);

    private static NativeHook<d_SetResult> _hook;
    private static d_SetResult _pinnedDelegate;

    public static void Apply()
    {
        try
        {
            var field = typeof(Il2Cpp.BtlLowerResultLayout2).GetField(
                "NativeMethodInfoPtr_SetResult_Public_Void_ResultData_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

            if (field == null) { Melon<Core>.Logger.Warning("ResultDisplay: field not found"); return; }

            var mi = (nint)field.GetValue(null);
            if (mi == 0) { Melon<Core>.Logger.Warning("ResultDisplay: null ptr"); return; }

            var native = *(nint*)mi;
            _pinnedDelegate = Hook;
            var hookPtr = Marshal.GetFunctionPointerForDelegate(_pinnedDelegate);
            _hook = new NativeHook<d_SetResult>(native, hookPtr);
            _hook.Attach();
            Melon<Core>.Logger.Msg($"ResultDisplay: native hook @ 0x{native:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"ResultDisplay: failed: {ex.Message}");
        }
    }

    private static int _logCount = 0;

    private static void Hook(nint instance, nint resultData, nint methodInfo)
    {
        // Call original — it clones ResultData to this+0x70
        try { _hook.Trampoline(instance, resultData, methodInfo); } catch { return; }

        if (!Core.ExpBoostEnabled.Value) return;

        try
        {
            // Access the cloned ResultData at this+0x70
            nint clonedData = *(nint*)(instance + 0x70);
            if (clonedData == 0) return;

            // ResultData fields: gil=0x10, exp=0x14, jobexp=0x18
            var gilPtr = (int*)(clonedData + 0x10);
            var expPtr = (int*)(clonedData + 0x14);
            var jexpPtr = (int*)(clonedData + 0x18);

            float expMult = Core.ExpMultiplier.Value;
            float jpMult = Core.JexpMultiplier.Value;
            float goldMult = Core.GoldMultiplier.Value;

            int origExp = *expPtr;
            int origJexp = *jexpPtr;
            int origGil = *gilPtr;

            *expPtr = (int)(origExp * expMult);
            *jexpPtr = (int)(origJexp * jpMult);
            *gilPtr = (int)(origGil * goldMult);

            _logCount++;
            if (_logCount <= 3)
                Melon<Core>.Logger.Msg($"[ResultDisplay] exp {origExp}->{*expPtr}, jp {origJexp}->{*jexpPtr}, gil {origGil}->{*gilPtr}");
        }
        catch { }
    }
}
