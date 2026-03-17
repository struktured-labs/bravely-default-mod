using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Colony speed mod: hooks multiple functions to accelerate fence/plant build times.
///
/// Architecture (from Ghidra reverse engineering):
///   - ColonyTaskWatcher.FenceTask stores m_completeTime (DateTime) at offset 0x30
///   - ColonyTaskWatcher.PlantTask stores m_completeTime (DateTime) at offset 0x30
///   - GetRemainTime() computes: remain = m_completeTime - DateTime.Now
///     then clamps: maxTime = TimeSpan.FromMinutes(GetMinutes()) / personnel
///     if remain > maxTime, it clamps down and updates m_completeTime
///   - The UI reads from GetRemainTime() every frame in _Update
///   - Entry() calls GetRemainTime() to get current remain, then sets
///     completeTime = now + (remain / newPersonnel)
///
/// Hook strategy:
///   1. FenceParameter.GetMinutes() — reduces the clamp ceiling inside FenceTask.GetRemainTime
///   2. FenceTask.GetRemainTime() — scales the returned TimeSpan for display + Entry calcs
///   3. PlantTask.GetRemainTime() — same for plants (plants bypass FenceParameter.GetMinutes)
///   4. DataAccessor.GetFenceRemainTime() — used when no workers assigned (personnel=0 path)
///   5. DataAccessor.GetPlantRemainTime() — same for plants
/// </summary>
public static unsafe class NativeColonyPatch
{
    // ── Delegate types ──────────────────────────────────────────────────

    // int GetMinutes(this FenceParameter, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_GetMinutes(nint instance, nint methodInfo);

    // TimeSpan GetRemainTime(this FenceTask/PlantTask, MethodInfo*)
    // TimeSpan is a struct with a single long (Ticks), returned as long in native.
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate long d_GetRemainTime(nint instance, nint methodInfo);

    // TimeSpan GetFenceRemainTime(this DataAccessor, FenceId, MethodInfo*)
    // FenceId is an int enum
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate long d_GetFenceRemainTime(nint instance, int fenceId, nint methodInfo);

    // TimeSpan GetPlantRemainTime(this DataAccessor, PlantId, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate long d_GetPlantRemainTime(nint instance, int plantId, nint methodInfo);

    // ── Hook storage ────────────────────────────────────────────────────

    private static NativeHook<d_GetMinutes> _getMinutesHook;
    private static d_GetMinutes _pinnedGetMinutes;

    private static NativeHook<d_GetRemainTime> _fenceRemainHook;
    private static d_GetRemainTime _pinnedFenceRemain;

    private static NativeHook<d_GetRemainTime> _plantRemainHook;
    private static d_GetRemainTime _pinnedPlantRemain;

    private static NativeHook<d_GetFenceRemainTime> _fenceRemainDataHook;
    private static d_GetFenceRemainTime _pinnedFenceRemainData;

    private static NativeHook<d_GetPlantRemainTime> _plantRemainDataHook;
    private static d_GetPlantRemainTime _pinnedPlantRemainData;

    private static int _logCount = 0;
    private const int MaxLogs = 20;

    // ── Apply ───────────────────────────────────────────────────────────

    public static void Apply()
    {
        // 1. Hook FenceParameter.GetMinutes — reduces the clamp inside FenceTask.GetRemainTime
        HookMethod<d_GetMinutes>(
            typeof(Il2Cpp.ColonyShare.DataAccessor.FenceParameter),
            "NativeMethodInfoPtr_GetMinutes_Public_Int32_0",
            GetMinutes_Hook, ref _pinnedGetMinutes, ref _getMinutesHook,
            "FenceParameter.GetMinutes");

        // 2. Hook FenceTask.GetRemainTime — scales remaining time for fences
        HookMethod<d_GetRemainTime>(
            typeof(Il2Cpp.ColonyTaskWatcher.FenceTask),
            "NativeMethodInfoPtr_GetRemainTime_Internal_TimeSpan_0",
            FenceRemainTime_Hook, ref _pinnedFenceRemain, ref _fenceRemainHook,
            "FenceTask.GetRemainTime");

        // 3. Hook PlantTask.GetRemainTime — scales remaining time for plants
        HookMethod<d_GetRemainTime>(
            typeof(Il2Cpp.ColonyTaskWatcher.PlantTask),
            "NativeMethodInfoPtr_GetRemainTime_Public_TimeSpan_0",
            PlantRemainTime_Hook, ref _pinnedPlantRemain, ref _plantRemainHook,
            "PlantTask.GetRemainTime");

        // 4. Hook DataAccessor.GetFenceRemainTime — no-workers path for fences
        HookMethod<d_GetFenceRemainTime>(
            typeof(Il2Cpp.ColonyShare.DataAccessor),
            "NativeMethodInfoPtr_GetFenceRemainTime_Public_TimeSpan_FenceId_0",
            FenceRemainTimeData_Hook, ref _pinnedFenceRemainData, ref _fenceRemainDataHook,
            "DataAccessor.GetFenceRemainTime");

        // 5. Hook DataAccessor.GetPlantRemainTime — no-workers path for plants
        HookMethod<d_GetPlantRemainTime>(
            typeof(Il2Cpp.ColonyShare.DataAccessor),
            "NativeMethodInfoPtr_GetPlantRemainTime_Public_TimeSpan_PlantId_0",
            PlantRemainTimeData_Hook, ref _pinnedPlantRemainData, ref _plantRemainDataHook,
            "DataAccessor.GetPlantRemainTime");
    }

    // ── Hook helpers ────────────────────────────────────────────────────

    private static void HookMethod<TDelegate>(
        System.Type type, string fieldName,
        TDelegate hookFn, ref TDelegate pinned, ref NativeHook<TDelegate> hook,
        string label) where TDelegate : System.Delegate
    {
        try
        {
            var field = type.GetField(fieldName,
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null)
            {
                Melon<Core>.Logger.Warning($"Colony: {label} field '{fieldName}' not found");
                return;
            }
            var mi = (nint)field.GetValue(null);
            if (mi == 0)
            {
                Melon<Core>.Logger.Warning($"Colony: {label} MethodInfo pointer is null");
                return;
            }
            var native = *(nint*)mi;
            pinned = hookFn;
            hook = new NativeHook<TDelegate>(native, Marshal.GetFunctionPointerForDelegate(pinned));
            hook.Attach();
            Melon<Core>.Logger.Msg($"Colony: {label} hook @ 0x{native:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"Colony: {label} failed: {ex.Message}");
        }
    }

    private static long ScaleTimeSpan(long ticks)
    {
        if (!Core.ColonyModEnabled.Value) return ticks;
        var mult = (double)Core.ColonySpeedMultiplier.Value;
        if (mult <= 1.0) return ticks;
        long result = (long)(ticks / mult);
        // Minimum 1 second if there was any time at all
        if (ticks > 0 && result < System.TimeSpan.TicksPerSecond)
            result = System.TimeSpan.TicksPerSecond;
        return result;
    }

    private static void LogOnce(string msg)
    {
        _logCount++;
        if (_logCount <= MaxLogs)
            Melon<Core>.Logger.Msg(msg);
    }

    // ── Hook implementations ────────────────────────────────────────────

    private static int GetMinutes_Hook(nint instance, nint methodInfo)
    {
        try
        {
            var orig = _getMinutesHook.Trampoline(instance, methodInfo);
            if (!Core.ColonyModEnabled.Value) return orig;
            var mult = Core.ColonySpeedMultiplier.Value;
            int result = System.Math.Max(1, (int)(orig / mult));
            LogOnce($"[Colony] GetMinutes: {orig} -> {result} (x{mult})");
            return result;
        }
        catch { return 1; }
    }

    private static long FenceRemainTime_Hook(nint instance, nint methodInfo)
    {
        try
        {
            var orig = _fenceRemainHook.Trampoline(instance, methodInfo);
            if (!Core.ColonyModEnabled.Value) return orig;
            var scaled = ScaleTimeSpan(orig);
            LogOnce($"[Colony] FenceTask.GetRemainTime: {System.TimeSpan.FromTicks(orig)} -> {System.TimeSpan.FromTicks(scaled)}");
            return scaled;
        }
        catch { return 0; }
    }

    private static long PlantRemainTime_Hook(nint instance, nint methodInfo)
    {
        try
        {
            var orig = _plantRemainHook.Trampoline(instance, methodInfo);
            if (!Core.ColonyModEnabled.Value) return orig;
            var scaled = ScaleTimeSpan(orig);
            LogOnce($"[Colony] PlantTask.GetRemainTime: {System.TimeSpan.FromTicks(orig)} -> {System.TimeSpan.FromTicks(scaled)}");
            return scaled;
        }
        catch { return 0; }
    }

    private static long FenceRemainTimeData_Hook(nint instance, int fenceId, nint methodInfo)
    {
        try
        {
            var orig = _fenceRemainDataHook.Trampoline(instance, fenceId, methodInfo);
            if (!Core.ColonyModEnabled.Value) return orig;
            var scaled = ScaleTimeSpan(orig);
            LogOnce($"[Colony] DataAccessor.GetFenceRemainTime[{fenceId}]: {System.TimeSpan.FromTicks(orig)} -> {System.TimeSpan.FromTicks(scaled)}");
            return scaled;
        }
        catch { return 0; }
    }

    private static long PlantRemainTimeData_Hook(nint instance, int plantId, nint methodInfo)
    {
        try
        {
            var orig = _plantRemainDataHook.Trampoline(instance, plantId, methodInfo);
            if (!Core.ColonyModEnabled.Value) return orig;
            var scaled = ScaleTimeSpan(orig);
            LogOnce($"[Colony] DataAccessor.GetPlantRemainTime[{plantId}]: {System.TimeSpan.FromTicks(orig)} -> {System.TimeSpan.FromTicks(scaled)}");
            return scaled;
        }
        catch { return 0; }
    }
}
