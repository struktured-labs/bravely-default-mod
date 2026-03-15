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
    // void CreateResultData(this BtlSequenceCtrl, MethodInfo*) — creates the result data with base values
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_CreateResultData(nint instance, nint methodInfo);

    private static NativeHook<d_CreateResultData> _createHook;
    private static d_CreateResultData _pinnedCreate;

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

            // Also hook CreateResultData to multiply gold/exp/jp at the SOURCE
            // so the actual rewards match the display
            var createField = typeof(Il2Cpp.BtlSequenceCtrl).GetField(
                "NativeMethodInfoPtr_CreateResultData_Public_Void_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (createField != null)
            {
                var createMi = (nint)createField.GetValue(null);
                if (createMi != 0)
                {
                    var createNative = *(nint*)createMi;
                    _pinnedCreate = CreateResultData_Hook;
                    _createHook = new NativeHook<d_CreateResultData>(createNative, Marshal.GetFunctionPointerForDelegate(_pinnedCreate));
                    _createHook.Attach();
                    Melon<Core>.Logger.Msg($"ResultDisplay: CreateResultData hook @ 0x{createNative:X}");
                }
            }
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"ResultDisplay: failed: {ex.Message}");
        }
    }

    private static int _createLog = 0;

    private static void CreateResultData_Hook(nint instance, nint methodInfo)
    {
        try
        {
            // Call original — creates ResultData with base values
            _createHook.Trampoline(instance, methodInfo);

            if (!Core.ExpBoostEnabled.Value) return;

            // ResultData is at BtlSequenceCtrl+0x58
            nint resultData = *(nint*)(instance + 0x58);
            if (resultData == 0) return;

            // Multiply at the source: gil=0x10, exp=0x14, jobexp=0x18
            var gilPtr = (int*)(resultData + 0x10);
            var expPtr = (int*)(resultData + 0x14);
            var jexpPtr = (int*)(resultData + 0x18);

            int origGil = *gilPtr;
            int origExp = *expPtr;
            int origJexp = *jexpPtr;

            *gilPtr = (int)(origGil * Core.GoldMultiplier.Value);
            *expPtr = (int)(origExp * Core.ExpMultiplier.Value);
            *jexpPtr = (int)(origJexp * Core.JexpMultiplier.Value);

            _createLog++;
            if (_createLog <= 3)
                Melon<Core>.Logger.Msg($"[Result] CreateResultData: gil {origGil}->{*gilPtr}, exp {origExp}->{*expPtr}, jp {origJexp}->{*jexpPtr}");
        }
        catch
        {
            try { _createHook.Trampoline(instance, methodInfo); } catch { }
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
