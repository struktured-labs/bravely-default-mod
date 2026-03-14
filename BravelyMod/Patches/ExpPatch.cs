using HarmonyLib;
using MelonLoader;

namespace BravelyMod.Patches;

[HarmonyPatch]
public static class ExpPatch
{
    private static int _callCount = 0;

    [HarmonyPatch(typeof(Il2Cpp.BtlResultCtrl), nameof(Il2Cpp.BtlResultCtrl.ReviseAddEXP))]
    [HarmonyPrefix]
    public static void ReviseAddEXP_Prefix(ref int exp, ref int bonusexp)
    {
        _callCount++;
        if (_callCount <= 3)
            Melon<Core>.Logger.Msg($"[EXP HOOK] ReviseAddEXP called! exp={exp} bonus={bonusexp}");

        if (!Core.ExpBoostEnabled.Value) return;
        var mult = Core.ExpMultiplier.Value;
        exp = (int)(exp * mult);
        bonusexp = (int)(bonusexp * mult);

        if (_callCount <= 3)
            Melon<Core>.Logger.Msg($"[EXP HOOK] After multiply: exp={exp} bonus={bonusexp}");
    }

    [HarmonyPatch(typeof(Il2Cpp.BtlResultCtrl), nameof(Il2Cpp.BtlResultCtrl.ReviseAddJEXP))]
    [HarmonyPrefix]
    public static void ReviseAddJEXP_Prefix(ref int jexp, ref int bonusjexp)
    {
        if (!Core.ExpBoostEnabled.Value) return;
        var mult = Core.JexpMultiplier.Value;
        jexp = (int)(jexp * mult);
        bonusjexp = (int)(bonusjexp * mult);
    }

    [HarmonyPatch(typeof(Il2Cpp.AbilityCostCalculator), nameof(Il2Cpp.AbilityCostCalculator.GetCalculatedAbilityGold))]
    [HarmonyPostfix]
    public static void GetCalculatedAbilityGold_Postfix(ref int __result)
    {
        if (!Core.ExpBoostEnabled.Value) return;
        var mult = Core.GoldMultiplier.Value;
        __result = (int)(__result * mult);
    }
}
