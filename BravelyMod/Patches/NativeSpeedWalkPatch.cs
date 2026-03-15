using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Speed walk: two approaches combined:
/// 1. Hook GlobalUserData.PostInitialize to set bDashAlways (1.6x base)
/// 2. Hook CollisionCtrl.MovePosition to multiply movement vector (additional multiplier)
/// </summary>
public static unsafe class NativeSpeedWalkPatch
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Vector3 { public float x, y, z; }

    // static void PostInitialize(MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_PostInitialize(nint methodInfo);

    // void MovePosition(this CollisionCtrl, Unit unit, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_MovePosition(nint instance, nint unit, nint methodInfo);

    private static NativeHook<d_PostInitialize> _postInitHook;
    private static d_PostInitialize _pinnedPostInit;

    private static NativeHook<d_MovePosition> _moveHook;
    private static d_MovePosition _pinnedMove;

    public static void Apply()
    {
        // Hook PostInitialize for bDashAlways
        try
        {
            var field = typeof(Il2Cpp.GlobalUserData).GetField(
                "NativeMethodInfoPtr_PostInitialize_Private_Static_Void_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Melon<Core>.Logger.Warning("SpeedWalk: PostInitialize not found"); return; }
            var mi = (nint)field.GetValue(null);
            if (mi == 0) return;
            var native = *(nint*)mi;
            _pinnedPostInit = PostInitialize_Hook;
            _postInitHook = new NativeHook<d_PostInitialize>(native, Marshal.GetFunctionPointerForDelegate(_pinnedPostInit));
            _postInitHook.Attach();
            Melon<Core>.Logger.Msg($"SpeedWalk: PostInitialize hook @ 0x{native:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"SpeedWalk PostInit: {ex.Message}");
        }

        // Hook CollisionCtrl.MovePosition to scale movement
        try
        {
            var field = typeof(Il2Cpp.CollisionCtrl).GetField(
                "NativeMethodInfoPtr_MovePosition_Public_Void_Unit_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Melon<Core>.Logger.Warning("SpeedWalk: MovePosition not found"); return; }
            var mi = (nint)field.GetValue(null);
            if (mi == 0) return;
            var native = *(nint*)mi;
            _pinnedMove = MovePosition_Hook;
            _moveHook = new NativeHook<d_MovePosition>(native, Marshal.GetFunctionPointerForDelegate(_pinnedMove));
            _moveHook.Attach();
            Melon<Core>.Logger.Msg($"SpeedWalk: MovePosition hook @ 0x{native:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"SpeedWalk MovePosition: {ex.Message}");
        }
    }

    private static bool _dashApplied = false;

    private static void PostInitialize_Hook(nint methodInfo)
    {
        try { _postInitHook.Trampoline(methodInfo); } catch { return; }
        if (_dashApplied || !Core.WalkSpeedModEnabled.Value) return;
        _dashApplied = true;
        try
        {
            Il2Cpp.GlobalUserData.bDashAlways = true;
            Melon<Core>.Logger.Msg("SpeedWalk: always-dash ON");
        }
        catch { }
    }

    private static void MovePosition_Hook(nint instance, nint unit, nint methodInfo)
    {
        if (!Core.WalkSpeedModEnabled.Value || unit == 0)
        {
            try { _moveHook.Trampoline(instance, unit, methodInfo); } catch { }
            return;
        }

        try
        {
            // Read unit's m_vecMovePosition at offset 0x98 (Vector3: x,y,z floats)
            var movePtr = (float*)(unit + 0x98);
            float mult = Core.WalkSpeedMultiplier.Value;

            // Scale X and Z (horizontal movement), leave Y alone (vertical/gravity)
            movePtr[0] *= mult; // X
            movePtr[2] *= mult; // Z

            // Call original with scaled movement
            _moveHook.Trampoline(instance, unit, methodInfo);
        }
        catch
        {
            try { _moveHook.Trampoline(instance, unit, methodInfo); } catch { }
        }
    }
}
