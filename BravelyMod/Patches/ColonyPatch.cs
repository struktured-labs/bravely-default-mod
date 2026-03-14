using HarmonyLib;
using MelonLoader;

namespace BravelyMod.Patches;

/// <summary>
/// Colony build speed.
/// Signature: int GetMinutes() (instance method on FenceParameter)
/// </summary>
[HarmonyPatch(typeof(Il2Cpp.ColonyShare.DataAccessor.FenceParameter),
              nameof(Il2Cpp.ColonyShare.DataAccessor.FenceParameter.GetMinutes))]
public static class ColonyPatch
{
    [HarmonyPostfix]
    public static void Postfix(ref int __result)
    {
        var mult = Core.ColonySpeedMultiplier.Value;
        if (mult > 1.0f)
            __result = System.Math.Max(1, (int)(__result / mult));
    }
}
