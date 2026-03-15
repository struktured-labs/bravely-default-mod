using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// "Switch Mode" — swaps A↔B by hooking Pad getters.
/// Uses trampolines to avoid infinite loops.
/// Hook get_A → call get_B's trampoline (real B), and vice versa.
/// Must hook B first, then A, so A's hook can use B's trampoline.
/// </summary>
public static unsafe class NativeButtonSwapPatch
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_GetBool(nint methodInfo);

    private static NativeHook<d_GetBool> _hGetA, _hGetB;
    private static NativeHook<d_GetBool> _hPressA, _hPressB;
    private static NativeHook<d_GetBool> _hRepeatA, _hRepeatB;
    private static NativeHook<d_GetBool> _hReleaseA, _hReleaseB;

    // Must pin ALL delegates
    private static d_GetBool _dGetA, _dGetB, _dPressA, _dPressB;
    private static d_GetBool _dRepeatA, _dRepeatB, _dReleaseA, _dReleaseB;

    public static void Apply()
    {
        var pad = typeof(Il2Cpp.Pad);
        int ok = 0;

        // Hook B FIRST, then A. A's hook calls B's trampoline (original B).
        // B's hook calls A's trampoline (original A).
        ok += SwapOne(pad,
            "NativeMethodInfoPtr_get_B_Public_Static_get_Boolean_0",
            "NativeMethodInfoPtr_get_A_Public_Static_get_Boolean_0",
            ref _dGetB, ref _dGetA, out _hGetB, out _hGetA, "get");

        ok += SwapOne(pad,
            "NativeMethodInfoPtr_get_pressB_Public_Static_get_Boolean_0",
            "NativeMethodInfoPtr_get_pressA_Public_Static_get_Boolean_0",
            ref _dPressB, ref _dPressA, out _hPressB, out _hPressA, "press");

        ok += SwapOne(pad,
            "NativeMethodInfoPtr_get_repeatB_Public_Static_get_Boolean_0",
            "NativeMethodInfoPtr_get_repeatA_Public_Static_get_Boolean_0",
            ref _dRepeatB, ref _dRepeatA, out _hRepeatB, out _hRepeatA, "repeat");

        ok += SwapOne(pad,
            "NativeMethodInfoPtr_get_releaseB_Public_Static_get_Boolean_0",
            "NativeMethodInfoPtr_get_releaseA_Public_Static_get_Boolean_0",
            ref _dReleaseB, ref _dReleaseA, out _hReleaseB, out _hReleaseA, "release");

        Melon<Core>.Logger.Msg($"ButtonSwap: {ok}/4 pairs swapped (A↔B)");
    }

    /// <summary>
    /// Hooks B first, then A. A calls B's trampoline, B calls A's trampoline.
    /// Order matters to avoid hooking what we just hooked.
    /// </summary>
    private static int SwapOne(System.Type type,
        string fieldB, string fieldA,
        ref d_GetBool pinB, ref d_GetBool pinA,
        out NativeHook<d_GetBool> hookB, out NativeHook<d_GetBool> hookA,
        string name)
    {
        hookB = default;
        hookA = default;
        try
        {
            var fB = type.GetField(fieldB, System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            var fA = type.GetField(fieldA, System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (fA == null || fB == null) return 0;

            var miB = (nint)fB.GetValue(null);
            var miA = (nint)fA.GetValue(null);
            if (miA == 0 || miB == 0) return 0;

            var nativeB = *(nint*)miB;
            var nativeA = *(nint*)miA;

            // Step 1: Hook B with a temporary passthrough
            pinB = (nint mi) => 0; // placeholder
            hookB = new NativeHook<d_GetBool>(nativeB, Marshal.GetFunctionPointerForDelegate(pinB));
            hookB.Attach();
            // Now hookB.Trampoline = original B

            // Step 2: Hook A to call original B (via hookB.Trampoline)
            var origB = hookB.Trampoline;
            pinA = (nint mi) => { try { return origB(mi); } catch { return 0; } };
            hookA = new NativeHook<d_GetBool>(nativeA, Marshal.GetFunctionPointerForDelegate(pinA));
            hookA.Attach();
            // Now hookA.Trampoline = original A

            // Step 3: Re-hook B to call original A (via hookA.Trampoline)
            var origA = hookA.Trampoline;
            hookB.Detach();
            pinB = (nint mi) => { try { return origA(mi); } catch { return 0; } };
            hookB = new NativeHook<d_GetBool>(nativeB, Marshal.GetFunctionPointerForDelegate(pinB));
            hookB.Attach();

            return 1;
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"ButtonSwap {name}: {ex.Message}");
            return 0;
        }
    }
}
