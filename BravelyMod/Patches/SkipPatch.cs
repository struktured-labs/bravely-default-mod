using HarmonyLib;
using MelonLoader;

namespace BravelyMod.Patches;

/// <summary>
/// Force scene skip.
/// Signatures:
///   void EventSkipLock(bool b)
///   bool IsEventSkipEnable()
/// </summary>
[HarmonyPatch]
public static class SkipPatch
{
    [HarmonyPatch(typeof(Il2Cpp.MB_EventGuide), nameof(Il2Cpp.MB_EventGuide.EventSkipLock))]
    [HarmonyPrefix]
    public static bool EventSkipLock_Prefix()
    {
        if (Core.ForceSceneSkip.Value)
            return false; // skip the method — never lock
        return true;
    }

    [HarmonyPatch(typeof(Il2Cpp.MB_EventGuide), nameof(Il2Cpp.MB_EventGuide.IsEventSkipEnable))]
    [HarmonyPostfix]
    public static void IsEventSkipEnable_Postfix(ref bool __result)
    {
        if (Core.ForceSceneSkip.Value)
            __result = true;
    }
}
