using System.Runtime.InteropServices;
using MelonLoader;

namespace BravelyMod.Patches;

/// <summary>
/// Speed walk: patches the dash speed multiplier constant in memory.
/// Original: 1.6f at RVA 0x243d2e8 in GameAssembly.dll.
/// We overwrite it with a configurable value (default 3.0).
/// Also forces "always dash" via GlobalUserData.bDashAlways.
/// </summary>
public static unsafe class NativeSpeedWalkPatch
{
    // The dash multiplier float constant RVA in GameAssembly.dll
    private const int DASH_MULT_RVA = 0x243d2e8;
    private static float _originalDashMult = 1.6f;
    private static bool _patched = false;

    public static void Apply()
    {
        try
        {
            // Get GameAssembly.dll base address
            var modules = System.Diagnostics.Process.GetCurrentProcess().Modules;
            nint gameAssemblyBase = 0;
            foreach (System.Diagnostics.ProcessModule mod in modules)
            {
                if (mod.ModuleName != null &&
                    mod.ModuleName.Equals("GameAssembly.dll", System.StringComparison.OrdinalIgnoreCase))
                {
                    gameAssemblyBase = mod.BaseAddress;
                    break;
                }
            }

            if (gameAssemblyBase == 0)
            {
                Melon<Core>.Logger.Warning("SpeedWalk: GameAssembly.dll not found");
                return;
            }

            nint dashMultAddr = gameAssemblyBase + DASH_MULT_RVA;
            float current = *(float*)dashMultAddr;
            Melon<Core>.Logger.Msg($"SpeedWalk: dash mult @ 0x{dashMultAddr:X} = {current}");

            if (System.Math.Abs(current - 1.6f) < 0.01f)
            {
                _originalDashMult = current;
                float newMult = Core.WalkSpeedMultiplier.Value;
                *(float*)dashMultAddr = newMult;
                _patched = true;
                Melon<Core>.Logger.Msg($"SpeedWalk: dash mult {current} -> {newMult}");
            }
            else
            {
                Melon<Core>.Logger.Warning($"SpeedWalk: unexpected dash mult value {current}, skipping patch");
            }

            // Force always-dash on
            try
            {
                Il2Cpp.GlobalUserData.bDashAlways = true;
                Melon<Core>.Logger.Msg("SpeedWalk: forced always-dash ON");
            }
            catch (System.Exception ex)
            {
                Melon<Core>.Logger.Warning($"SpeedWalk: couldn't set bDashAlways: {ex.Message}");
            }
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"SpeedWalk: failed: {ex.Message}");
        }
    }
}
