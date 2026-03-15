using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Battle speed: hooks both GameData.GetBattleSpeed and BtlFunction.SetTimeSpeed.
/// GetBattleSpeed returns the speed tier (0,1,2 = 1x,2x,4x). We extend to higher values.
/// SetTimeSpeed gets the float speed — we multiply it.
/// </summary>
public static unsafe class NativeBattleSpeedPatch
{
    // uint GetBattleSpeed(this GameData, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint d_GetBattleSpeed(nint instance, nint methodInfo);

    // void SetTimeSpeed(this BtlFunction, float speed, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SetTimeSpeed(nint instance, float speed, nint methodInfo);

    private static NativeHook<d_GetBattleSpeed> _getBattleSpeedHook;
    private static NativeHook<d_SetTimeSpeed> _setTimeSpeedHook;
    private static d_GetBattleSpeed _pinnedGetBS;
    private static d_SetTimeSpeed _pinnedSetTS;

    public static void Apply()
    {
        // Hook SetTimeSpeed — multiply the float speed
        try
        {
            var field = typeof(Il2Cpp.BtlFunction).GetField(
                "NativeMethodInfoPtr_SetTimeSpeed_Public_Void_Single_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field != null)
            {
                var mi = (nint)field.GetValue(null);
                if (mi != 0)
                {
                    var native = *(nint*)mi;
                    _pinnedSetTS = SetTimeSpeed_Hook;
                    _setTimeSpeedHook = new NativeHook<d_SetTimeSpeed>(native, Marshal.GetFunctionPointerForDelegate(_pinnedSetTS));
                    _setTimeSpeedHook.Attach();
                    Melon<Core>.Logger.Msg($"BattleSpeed: SetTimeSpeed hook @ 0x{native:X}");
                }
            }
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"BattleSpeed SetTimeSpeed: {ex.Message}");
        }

        // Hook GetBattleSpeed — for logging/debugging what tier the game is using
        try
        {
            var field = typeof(Il2Cpp.GameData).GetField(
                "NativeMethodInfoPtr_GetBattleSpeed_Public_UInt32_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field != null)
            {
                var mi = (nint)field.GetValue(null);
                if (mi != 0)
                {
                    var native = *(nint*)mi;
                    _pinnedGetBS = GetBattleSpeed_Hook;
                    _getBattleSpeedHook = new NativeHook<d_GetBattleSpeed>(native, Marshal.GetFunctionPointerForDelegate(_pinnedGetBS));
                    _getBattleSpeedHook.Attach();
                    Melon<Core>.Logger.Msg($"BattleSpeed: GetBattleSpeed hook @ 0x{native:X}");
                }
            }
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"BattleSpeed GetBattleSpeed: {ex.Message}");
        }
    }

    private static int _tsLogCount = 0;

    private static void SetTimeSpeed_Hook(nint instance, float speed, nint methodInfo)
    {
        try
        {
            if (Core.SpeedModEnabled.Value && speed > 1.0f)
            {
                // Double all speeds above 1x: 2x→4x, 4x→8x. Leave 1x alone.
                float mult = Core.BattleSpeedMultiplier.Value;
                float newSpeed = speed * mult;
                _tsLogCount++;
                if (_tsLogCount <= 5)
                    Melon<Core>.Logger.Msg($"[BattleSpeed] SetTimeSpeed {speed} * {mult} = {newSpeed}");
                speed = newSpeed;
            }
            _setTimeSpeedHook.Trampoline(instance, speed, methodInfo);
        }
        catch
        {
            try { _setTimeSpeedHook.Trampoline(instance, speed, methodInfo); } catch { }
        }
    }

    private static int _bsLogCount = 0;

    private static uint GetBattleSpeed_Hook(nint instance, nint methodInfo)
    {
        try
        {
            var orig = _getBattleSpeedHook.Trampoline(instance, methodInfo);
            _bsLogCount++;
            if (_bsLogCount <= 5)
                Melon<Core>.Logger.Msg($"[BattleSpeed] GetBattleSpeed = {orig}");
            return orig;
        }
        catch { return 0; }
    }
}
