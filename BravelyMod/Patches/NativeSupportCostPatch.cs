using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Reduces all support ability equip costs to 1 slot.
/// Hooks SupportAbility.GetParam(int, bool, bool) and overrides COST field on returned object.
/// SupportAbility.COST is at IL2CPP object offset 0x30.
/// </summary>
public static unsafe class NativeSupportCostPatch
{
    // static SupportAbility GetParam(int AbilityId, bool AbiLink, bool bNoAbort)
    // IL2CPP: (IntPtr abilityId_boxed... no, static methods don't have instance ptr)
    // Static IL2CPP calling convention: (params..., IntPtr methodInfo)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_GetParam(int abilityId, byte abiLink, byte bNoAbort, nint methodInfo);

    private static NativeHook<d_GetParam> _hook;

    public static void Apply()
    {
        try
        {
            var field = typeof(Il2Cpp.SupportAbility).GetField(
                "NativeMethodInfoPtr_GetParam_Public_Static_SupportAbility_Int32_Boolean_Boolean_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

            if (field == null)
            {
                Melon<Core>.Logger.Warning("SupportCost: GetParam field not found");
                return;
            }

            var methodInfoPtr = (nint)field.GetValue(null);
            if (methodInfoPtr == 0)
            {
                Melon<Core>.Logger.Warning("SupportCost: method info ptr is null");
                return;
            }

            var nativePtr = *(nint*)methodInfoPtr;
            Melon<Core>.Logger.Msg($"SupportAbility.GetParam: native @ 0x{nativePtr:X}");

            var hookPtr = Marshal.GetFunctionPointerForDelegate(new d_GetParam(GetParam_Hook));
            _hook = new NativeHook<d_GetParam>(nativePtr, hookPtr);
            _hook.Attach();
            Melon<Core>.Logger.Msg("SupportAbility.GetParam: native hook attached! (all costs -> 1)");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"SupportCost: hook failed: {ex.Message}");
        }
    }

    private static int _callCount = 0;

    private static nint GetParam_Hook(int abilityId, byte abiLink, byte bNoAbort, nint methodInfo)
    {
        var result = _hook.Trampoline(abilityId, abiLink, bNoAbort, methodInfo);

        if (result != 0)
        {
            // SupportAbility.COST is at offset 0x30 from the IL2CPP object base
            var costPtr = (int*)(result + 0x30);
            int origCost = *costPtr;

            int target = Core.SupportCostOverride.Value;
            if (origCost > target)
            {
                *costPtr = target;
                _callCount++;
                if (_callCount <= 5)
                    Melon<Core>.Logger.Msg($"[SupportCost] ability {abilityId}: cost {origCost} -> 1");
            }
        }

        return result;
    }
}
