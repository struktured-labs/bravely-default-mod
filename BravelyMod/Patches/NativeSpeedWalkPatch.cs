using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Speed walk: hooks GlobalUserData.IsDash delegate to always return true.
/// This forces the 1.6x dash multiplier at all times.
/// Safe approach — no memory patching needed.
/// </summary>
public static unsafe class NativeSpeedWalkPatch
{
    // The IsDash property returns a Func<bool>. We hook bDashAlways setter instead.
    // Simplest: just set bDashAlways = true at init and periodically.

    public static void Apply()
    {
        try
        {
            Il2Cpp.GlobalUserData.bDashAlways = true;
            Melon<Core>.Logger.Msg("SpeedWalk: forced always-dash ON (1.6x base speed)");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"SpeedWalk: couldn't set bDashAlways: {ex.Message}");
        }
    }
}
