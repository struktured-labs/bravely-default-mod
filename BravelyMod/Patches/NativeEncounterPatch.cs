using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Hooks GetEncountRate to allow zero encounters.
/// When the game's encounter rate is at minimum (-100), force it to -999 to guarantee no encounters.
/// </summary>
public static unsafe class NativeEncounterPatch
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_GetEncountRate(nint instance, nint methodInfo);

    private static NativeHook<d_GetEncountRate> _hook;
    private static d_GetEncountRate _pinned;

    public static void Apply()
    {
        try
        {
            var field = typeof(Il2Cpp.ConfigData_tr.Difficulty).GetField(
                "NativeMethodInfoPtr_GetEncountRate_Public_Int32_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Melon<Core>.Logger.Warning("EncountRate: field not found"); return; }
            var mi = (nint)field.GetValue(null);
            if (mi == 0) return;
            var native = *(nint*)mi;
            _pinned = Hook;
            _hook = new NativeHook<d_GetEncountRate>(native, Marshal.GetFunctionPointerForDelegate(_pinned));
            _hook.Attach();
            Melon<Core>.Logger.Msg($"EncountRate: hook @ 0x{native:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"EncountRate: {ex.Message}");
        }
    }

    private static int _logCount = 0;

    private static int Hook(nint instance, nint methodInfo)
    {
        try
        {
            int orig = _hook.Trampoline(instance, methodInfo);

            // When encounter rate is at minimum (typically -100), force to -999 for zero encounters
            if (orig <= -100)
            {
                _logCount++;
                if (_logCount <= 3)
                    Melon<Core>.Logger.Msg($"[Encounter] Rate {orig} -> -999 (zero encounters)");
                return -999;
            }
            return orig;
        }
        catch { return 0; }
    }
}
