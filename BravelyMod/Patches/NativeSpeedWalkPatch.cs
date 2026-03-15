using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Speed walk: hooks MovePosition to scale movement by different amounts
/// based on the game's movement mode (L3 toggle).
///
/// Game modes (ConfigInterface.Movement):
///   AUTO=0, FIXED_RUN=1, WALK100=2, WALK50=3, WALK150=4
///
/// We map to 3 tiers:
///   WALK50 (3)         → 1.0x  "Normal"
///   WALK100 (2)        → 3.0x  "Super Fast"
///   Everything else    → 6.0x  "Insanely Fast"
///
/// Also hooks GlobalUserData.PostInitialize to force dash always on.
/// </summary>
public static unsafe class NativeSpeedWalkPatch
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Vector3 { public float x, y, z; }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_PostInitialize(nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_MovePosition(nint instance, nint unit, nint methodInfo);

    // int GetMovement(this ConfigInterface, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_GetMovement(nint instance, nint methodInfo);

    private static NativeHook<d_PostInitialize> _postInitHook;
    private static d_PostInitialize _pinnedPostInit;

    private static NativeHook<d_MovePosition> _moveHook;
    private static d_MovePosition _pinnedMove;

    private static NativeHook<d_GetMovement> _getMovementHook;
    private static d_GetMovement _pinnedGetMovement;

    // Track current movement mode
    private static int _currentMode = 0;

    public static void Apply()
    {
        // Hook PostInitialize for bDashAlways
        try
        {
            var field = typeof(Il2Cpp.GlobalUserData).GetField(
                "NativeMethodInfoPtr_PostInitialize_Private_Static_Void_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field != null)
            {
                var mi = (nint)field.GetValue(null);
                if (mi != 0)
                {
                    var native = *(nint*)mi;
                    _pinnedPostInit = PostInitialize_Hook;
                    _postInitHook = new NativeHook<d_PostInitialize>(native, Marshal.GetFunctionPointerForDelegate(_pinnedPostInit));
                    _postInitHook.Attach();
                    Melon<Core>.Logger.Msg($"SpeedWalk: PostInitialize hook @ 0x{native:X}");
                }
            }
        }
        catch (System.Exception ex) { Melon<Core>.Logger.Warning($"SpeedWalk PostInit: {ex.Message}"); }

        // Hook GetMovement to track current mode
        try
        {
            var field = typeof(Il2Cpp.ConfigInterface).GetField(
                "NativeMethodInfoPtr_GetMovement_Public_Movement_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field != null)
            {
                var mi = (nint)field.GetValue(null);
                if (mi != 0)
                {
                    var native = *(nint*)mi;
                    _pinnedGetMovement = GetMovement_Hook;
                    _getMovementHook = new NativeHook<d_GetMovement>(native, Marshal.GetFunctionPointerForDelegate(_pinnedGetMovement));
                    _getMovementHook.Attach();
                    Melon<Core>.Logger.Msg($"SpeedWalk: GetMovement hook @ 0x{native:X}");
                }
            }
            else
            {
                Melon<Core>.Logger.Warning("SpeedWalk: GetMovement field not found");
            }
        }
        catch (System.Exception ex) { Melon<Core>.Logger.Warning($"SpeedWalk GetMovement: {ex.Message}"); }

        // Hook MovePosition to scale movement
        try
        {
            var field = typeof(Il2Cpp.CollisionCtrl).GetField(
                "NativeMethodInfoPtr_MovePosition_Public_Void_Unit_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field != null)
            {
                var mi = (nint)field.GetValue(null);
                if (mi != 0)
                {
                    var native = *(nint*)mi;
                    _pinnedMove = MovePosition_Hook;
                    _moveHook = new NativeHook<d_MovePosition>(native, Marshal.GetFunctionPointerForDelegate(_pinnedMove));
                    _moveHook.Attach();
                    Melon<Core>.Logger.Msg($"SpeedWalk: MovePosition hook @ 0x{native:X}");
                }
            }
        }
        catch (System.Exception ex) { Melon<Core>.Logger.Warning($"SpeedWalk MovePosition: {ex.Message}"); }
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

    private static int GetMovement_Hook(nint instance, nint methodInfo)
    {
        try
        {
            _currentMode = _getMovementHook.Trampoline(instance, methodInfo);
            return _currentMode;
        }
        catch { return 0; }
    }

    private static float GetSpeedMultiplier()
    {
        // Map game modes to 3 tiers:
        // WALK50 (3)      → 1.0x  "Normal"
        // WALK100 (2)     → 3.0x  "Super Fast"
        // AUTO/RUN/150    → 6.0x  "Insanely Fast"
        return _currentMode switch
        {
            3 => 0.5f,   // WALK50 → slow (half speed, useful for precision)
            2 => 1.0f,   // WALK100 → normal (no boost)
            _ => 2.5f,   // AUTO, FIXED_RUN, WALK150 → fast
        };
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
            float mult = GetSpeedMultiplier();
            if (mult > 1.0f)
            {
                var movePtr = (float*)(unit + 0x98);
                movePtr[0] *= mult; // X
                movePtr[2] *= mult; // Z
            }
            _moveHook.Trampoline(instance, unit, methodInfo);
        }
        catch
        {
            try { _moveHook.Trampoline(instance, unit, methodInfo); } catch { }
        }
    }
}
