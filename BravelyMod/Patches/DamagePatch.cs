using HarmonyLib;
using MelonLoader;

namespace BravelyMod.Patches;

/// <summary>
/// Removes or raises the damage cap.
/// Hooks BtlActionCalc.CheckDamageRange(BtlDamageData, bool, bool).
/// We postfix to modify the damage data after the cap is applied.
/// </summary>
[HarmonyPatch(typeof(Il2Cpp.BtlActionCalc), nameof(Il2Cpp.BtlActionCalc.CheckDamageRange))]
public static class DamagePatch
{
    [HarmonyPostfix]
    public static void Postfix(Il2Cpp.BtlDamageData pDamageData)
    {
        if (!Core.DamageCapEnabled) return;
        // BtlDamageData contains the damage value after capping.
        // We'll need to inspect the struct at runtime to find the damage field.
        // For now this is a placeholder — the exact field offset needs runtime testing.
    }
}
