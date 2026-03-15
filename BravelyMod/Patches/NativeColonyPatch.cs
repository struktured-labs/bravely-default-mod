using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

public static unsafe class NativeColonyPatch
{
    // int GetMinutes(this FenceParameter, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_GetMinutes(nint instance, nint methodInfo);

    private static NativeHook<d_GetMinutes> _hook;
    private static d_GetMinutes _pinned;

    public static void Apply()
    {
        try
        {
            var field = typeof(Il2Cpp.ColonyShare.DataAccessor.FenceParameter).GetField(
                "NativeMethodInfoPtr_GetMinutes_Public_Int32_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Melon<Core>.Logger.Warning("Colony: field not found"); return; }
            var mi = (nint)field.GetValue(null);
            if (mi == 0) return;
            var native = *(nint*)mi;
            _pinned = Hook;
            _hook = new NativeHook<d_GetMinutes>(native, Marshal.GetFunctionPointerForDelegate(_pinned));
            _hook.Attach();
            Melon<Core>.Logger.Msg($"Colony: GetMinutes hook @ 0x{native:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"Colony: {ex.Message}");
        }
    }

    private static int Hook(nint instance, nint methodInfo)
    {
        try
        {
            var orig = _hook.Trampoline(instance, methodInfo);
            if (!Core.ColonyModEnabled.Value) return orig;
            var mult = Core.ColonySpeedMultiplier.Value;
            return System.Math.Max(1, (int)(orig / mult));
        }
        catch { return 1; }
    }
}
