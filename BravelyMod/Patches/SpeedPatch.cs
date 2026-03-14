using HarmonyLib;
using MelonLoader;

namespace BravelyMod.Patches;

/// <summary>
/// Battle speed multiplier.
/// Signature: void SetTimeSpeed(float _speed)
/// </summary>
[HarmonyPatch(typeof(Il2Cpp.BtlFunction), nameof(Il2Cpp.BtlFunction.SetTimeSpeed))]
public static class SpeedPatch
{
    [HarmonyPrefix]
    public static void Prefix(ref float _speed)
    {
        var mult = Core.BattleSpeedMultiplier.Value;
        if (mult > 1.0f)
            _speed *= mult;
    }
}
