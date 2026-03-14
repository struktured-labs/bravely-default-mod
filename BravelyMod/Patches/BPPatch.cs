using HarmonyLib;
using MelonLoader;

namespace BravelyMod.Patches;

/// <summary>
/// Raises BP limit.
/// Signature: static int GetLimitBP(BtlChara pChr)
/// </summary>
[HarmonyPatch(typeof(Il2Cpp.gfc), nameof(Il2Cpp.gfc.GetLimitBP))]
public static class BPPatch
{
    [HarmonyPostfix]
    public static void Postfix(ref int __result)
    {
        var limit = Core.BpLimitOverride.Value;
        if (__result < limit)
            __result = limit;
    }
}
