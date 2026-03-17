using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

public static unsafe class NativeColonyPatch
{
    // int GetMinutes(this FenceParameter, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_GetMinutes(nint instance, nint methodInfo);

    // static int GetMinutes(TimeSpan _, MethodInfo*) — TimeSpan is 8 bytes (long ticks)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_GetMinutesStatic(long timeSpanTicks, nint methodInfo);

    private static NativeHook<d_GetMinutes> _hook;
    private static d_GetMinutes _pinned;

    private static NativeHook<d_GetMinutesStatic> _staticHook;
    private static d_GetMinutesStatic _pinnedStatic;

    private static int _logCount = 0;

    public static void Apply()
    {
        // Hook instance GetMinutes on FenceParameter
        try
        {
            var field = typeof(Il2Cpp.ColonyShare.DataAccessor.FenceParameter).GetField(
                "NativeMethodInfoPtr_GetMinutes_Public_Int32_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Melon<Core>.Logger.Warning("Colony: FenceParameter.GetMinutes not found"); }
            else
            {
                var mi = (nint)field.GetValue(null);
                if (mi != 0)
                {
                    var native = *(nint*)mi;
                    _pinned = Hook;
                    _hook = new NativeHook<d_GetMinutes>(native, Marshal.GetFunctionPointerForDelegate(_pinned));
                    _hook.Attach();
                    Melon<Core>.Logger.Msg($"Colony: FenceParameter.GetMinutes hook @ 0x{native:X}");
                }
            }
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"Colony instance: {ex.Message}");
        }

        // Hook static GetMinutes(TimeSpan) on SfmtCustom
        try
        {
            var field = typeof(Il2Cpp.ColonyShare.SfmtCustom).GetField(
                "NativeMethodInfoPtr_GetMinutes_Public_Static_Int32_TimeSpan_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Melon<Core>.Logger.Warning("Colony: SfmtCustom.GetMinutes not found"); }
            else
            {
                var mi = (nint)field.GetValue(null);
                if (mi != 0)
                {
                    var native = *(nint*)mi;
                    _pinnedStatic = HookStatic;
                    _staticHook = new NativeHook<d_GetMinutesStatic>(native, Marshal.GetFunctionPointerForDelegate(_pinnedStatic));
                    _staticHook.Attach();
                    Melon<Core>.Logger.Msg($"Colony: SfmtCustom.GetMinutes(TimeSpan) hook @ 0x{native:X}");
                }
            }
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"Colony static: {ex.Message}");
        }
    }

    private static int Hook(nint instance, nint methodInfo)
    {
        try
        {
            var orig = _hook.Trampoline(instance, methodInfo);
            if (!Core.ColonyModEnabled.Value) return orig;
            var mult = Core.ColonySpeedMultiplier.Value;
            int result = System.Math.Max(1, (int)(orig / mult));
            _logCount++;
            if (_logCount <= 5)
                Melon<Core>.Logger.Msg($"[Colony] GetMinutes: {orig} -> {result}");
            return result;
        }
        catch { return 1; }
    }

    private static int HookStatic(long timeSpanTicks, nint methodInfo)
    {
        try
        {
            var orig = _staticHook.Trampoline(timeSpanTicks, methodInfo);
            if (!Core.ColonyModEnabled.Value) return orig;
            var mult = Core.ColonySpeedMultiplier.Value;
            int result = System.Math.Max(1, (int)(orig / mult));
            _logCount++;
            if (_logCount <= 5)
                Melon<Core>.Logger.Msg($"[Colony] GetMinutes(TimeSpan): {orig} -> {result}");
            return result;
        }
        catch { return 1; }
    }
}
