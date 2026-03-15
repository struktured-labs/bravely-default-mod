using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Native hook for BtlActionCalc.CheckDamageRange to override the damage cap.
///
/// The original function clamps BtlDamageData.damage to Min(damage, 9999)
/// or 99999 when bLimitBreak is set. We save the unclamped damage before
/// the original runs, then re-apply our own higher cap afterwards.
///
/// BtlDamageData layout (from dump.cs):
///   +0x10  int hitType
///   +0x14  int damage      &lt;-- the field we modify
///   +0x18  int mpDamage
/// </summary>
public static unsafe class NativeDamageCapPatch
{
    // IL2CPP calling convention: (IntPtr instance, params..., IntPtr methodInfo)
    // CheckDamageRange(BtlDamageData pDamageData, bool bMonster, bool bLimitBreak)
    // bools are marshalled as single bytes in IL2CPP native calls
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_CheckDamageRange(nint instance, nint pDamageData, byte bMonster, byte bLimitBreak, nint methodInfo);

    private static NativeHook<d_CheckDamageRange> _hook;
    private static d_CheckDamageRange _pinnedDelegate;

    // BtlDamageData field offsets (IL2CPP managed object: 0x10 header + fields)
    private const int OFFSET_DAMAGE = 0x14;

    private static int _logCount = 0;

    public static void Apply()
    {
        try
        {
            var field = typeof(Il2Cpp.BtlActionCalc).GetField(
                "NativeMethodInfoPtr_CheckDamageRange_Public_Void_BtlDamageData_Boolean_Boolean_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

            if (field == null)
            {
                Melon<Core>.Logger.Warning("DamageCap: NativeMethodInfoPtr field not found");
                return;
            }

            var methodInfoPtr = (nint)field.GetValue(null);
            if (methodInfoPtr == 0)
            {
                Melon<Core>.Logger.Warning("DamageCap: method info ptr is null");
                return;
            }

            // Il2CppMethodInfo->methodPointer is at offset 0
            var nativePtr = *(nint*)methodInfoPtr;
            Melon<Core>.Logger.Msg($"CheckDamageRange: native @ 0x{nativePtr:X}");

            _pinnedDelegate = CheckDamageRange_Hook;
            var hookPtr = Marshal.GetFunctionPointerForDelegate(_pinnedDelegate);
            _hook = new NativeHook<d_CheckDamageRange>(nativePtr, hookPtr);
            _hook.Attach();
            Melon<Core>.Logger.Msg("DamageCap: native hook attached!");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"DamageCap: hook failed: {ex.Message}");
        }
    }

    private static void CheckDamageRange_Hook(nint instance, nint pDamageData, byte bMonster, byte bLimitBreak, nint methodInfo)
    {
        if (pDamageData == 0)
        {
            try { _hook.Trampoline(instance, pDamageData, bMonster, bLimitBreak, methodInfo); } catch { }
            return;
        }

        int preDamage = 0;
        bool captured = false;

        // Save the unclamped damage value BEFORE the original runs
        try
        {
            var damagePtr = (int*)(pDamageData + OFFSET_DAMAGE);
            preDamage = *damagePtr;
            captured = true;
        }
        catch { }

        // Let the original clamping run (caps to 9999 or 99999)
        try
        {
            _hook.Trampoline(instance, pDamageData, bMonster, bLimitBreak, methodInfo);
        }
        catch
        {
            return;
        }

        if (!Core.DamageCapEnabled.Value) return;
        if (!captured) return;

        try
        {
            var damagePtr = (int*)(pDamageData + OFFSET_DAMAGE);
            int postDamage = *damagePtr;
            int cap = Core.DamageCapOverride.Value;

            // Re-clamp using our higher cap instead of the vanilla 9999/99999
            // Use the pre-clamp value (which may have been very large from calc),
            // and apply our own ceiling
            int newDamage = System.Math.Min(preDamage, cap);

            // Also ensure we don't go below 0 (the original enforces a minimum too)
            if (newDamage < 0) newDamage = 0;

            if (newDamage != postDamage)
            {
                *damagePtr = newDamage;

                _logCount++;
                if (_logCount <= 10)
                    Melon<Core>.Logger.Msg(
                        $"[DamageCap] pre={preDamage} vanilla_capped={postDamage} -> {newDamage} (cap={cap} lb={bLimitBreak})");
            }
        }
        catch
        {
            // Don't crash on bad pointer reads
        }
    }
}
