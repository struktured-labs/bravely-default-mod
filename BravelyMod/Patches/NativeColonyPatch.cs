using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Colony speed mod: accelerates fence and plant build times in Norende village.
///
/// ## Architecture (Ghidra RE of GameAssembly.dll)
///
/// ColonyTaskWatcher.FenceTask: m_fenceId@0x28, m_completeTime@0x30 (DateTime ticks)
/// ColonyTaskWatcher.PlantTask: m_plantId@0x28, m_completeTime@0x30 (DateTime ticks)
/// ColonyData.Fence: personnel@0x18, progress(ms)@0x20, completeTime@0x28
/// ColonyData.Plant: personnel@0x18, level@0x14, progress(ms)@0x20, completeTime@0x28
///
/// Fence minutes: FenceParameter.GetMinutes() -> ColonyFenceParameterWorkload.minutes
/// Plant minutes: PlantParameter.GetWorkload().GetDetails(level).minutes (raw field read)
///
/// GetRemainTime() [workers assigned]:
///   remain = m_completeTime - now
///   maxTime = totalMinutes / personnel
///   if remain > maxTime: m_completeTime = now + maxTime; remain = maxTime
///   return max(remain, 0)
///
/// Entry(personnel):
///   remain = GetRemainTime()
///   colonyData.personnel = personnel
///   colonyData.completeTime = now + remain / personnel
///   Resume() -> copies to m_completeTime
///
/// Judge(): return GetRemainTime() == TimeSpan.Zero
///
/// ## Hook strategy
///
/// FENCES: Hook GetMinutes() alone. Works because GetRemainTime's clamp uses
///   GetMinutes(), self-correcting m_completeTime every tick. Entry calls
///   GetRemainTime -> all paths use GetMinutes. Existing saves auto-correct.
///
/// PLANTS: No hookable function for minutes. Multi-hook approach:
///   1. Entry hook: let original run, then scale m_completeTime once (/mult)
///   2. GetRemainTime hook: for existing saves, scale m_completeTime once on
///      first call per task instance. Does NOT scale the return value (the
///      adjusted m_completeTime makes the return naturally correct).
///   3. DataAccessor.GetPlantRemainTime: scale no-workers path result
///   4. Reduce hook: scale the minMinutes argument
/// </summary>
public static unsafe class NativeColonyPatch
{
    // ── Delegates ───────────────────────────────────────────────────────

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int d_GetMinutes(nint instance, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate long d_GetRemainTime(nint instance, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_Entry(nint instance, int personnel, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate long d_DataRemainTime(nint instance, int id, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_Reduce(nint instance, int minMinutes, nint methodInfo);

    // ── Hook storage ────────────────────────────────────────────────────

    private static NativeHook<d_GetMinutes> _getMinutesHook;
    private static d_GetMinutes _pinnedGetMinutes;

    private static NativeHook<d_GetRemainTime> _plantGetRemainHook;
    private static d_GetRemainTime _pinnedPlantGetRemain;

    private static NativeHook<d_Entry> _plantEntryHook;
    private static d_Entry _pinnedPlantEntry;

    private static NativeHook<d_DataRemainTime> _plantDataRemainHook;
    private static d_DataRemainTime _pinnedPlantDataRemain;

    private static NativeHook<d_Reduce> _plantReduceHook;
    private static d_Reduce _pinnedPlantReduce;

    private static int _logCount = 0;
    private const int MaxLogs = 40;

    /// <summary>
    /// Tracks plant task instances whose m_completeTime has been scaled.
    /// Prevents re-scaling on every GetRemainTime tick.
    /// Entry clears the entry, then re-adds after scaling.
    /// </summary>
    private static readonly System.Collections.Generic.HashSet<nint> _scaledPlants = new();

    /// <summary>
    /// Guard: set during Entry so GetRemainTime (called inside Entry) skips scaling.
    /// Entry will handle the scaling itself after the original returns.
    /// </summary>
    [ThreadStatic] private static bool _inPlantEntry;

    // ── Apply ───────────────────────────────────────────────────────────

    public static void Apply()
    {
        Melon<Core>.Logger.Msg($"[Colony] Applying colony speed hooks (multiplier={Core.ColonySpeedMultiplier.Value}x, enabled={Core.ColonyModEnabled.Value})");
        Melon<Core>.Logger.Msg("[Colony] Note: 'Time' display on colony screen shows original cached duration from build start; 'remaining' time is live and correctly scaled.");

        // --- FENCE: single hook handles everything ---
        Install<d_GetMinutes>(
            typeof(Il2Cpp.ColonyShare.DataAccessor.FenceParameter),
            "NativeMethodInfoPtr_GetMinutes_Public_Int32_0",
            GetMinutes_Hook, ref _pinnedGetMinutes, ref _getMinutesHook,
            "FenceParameter.GetMinutes");

        // --- PLANT: multi-hook ---
        Install<d_GetRemainTime>(
            typeof(Il2Cpp.ColonyTaskWatcher.PlantTask),
            "NativeMethodInfoPtr_GetRemainTime_Public_TimeSpan_0",
            PlantGetRemainTime_Hook, ref _pinnedPlantGetRemain, ref _plantGetRemainHook,
            "PlantTask.GetRemainTime");

        Install<d_Entry>(
            typeof(Il2Cpp.ColonyTaskWatcher.PlantTask),
            "NativeMethodInfoPtr_Entry_Public_Void_Int32_0",
            PlantEntry_Hook, ref _pinnedPlantEntry, ref _plantEntryHook,
            "PlantTask.Entry");

        Install<d_DataRemainTime>(
            typeof(Il2Cpp.ColonyShare.DataAccessor),
            "NativeMethodInfoPtr_GetPlantRemainTime_Public_TimeSpan_PlantId_0",
            PlantDataRemainTime_Hook, ref _pinnedPlantDataRemain, ref _plantDataRemainHook,
            "DataAccessor.GetPlantRemainTime");

        Install<d_Reduce>(
            typeof(Il2Cpp.ColonyTaskWatcher.PlantTask),
            "NativeMethodInfoPtr_Reduce_Public_Void_Int32_0",
            PlantReduce_Hook, ref _pinnedPlantReduce, ref _plantReduceHook,
            "PlantTask.Reduce");
    }

    // ── Generic hook installer ──────────────────────────────────────────

    private static void Install<T>(
        System.Type type, string fieldName,
        T hookFn, ref T pinned, ref NativeHook<T> hook,
        string label) where T : System.Delegate
    {
        try
        {
            var field = type.GetField(fieldName,
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null)
            {
                Melon<Core>.Logger.Warning($"Colony: {label} - field not found: {fieldName}");
                return;
            }
            var mi = (nint)field.GetValue(null);
            if (mi == 0) { Melon<Core>.Logger.Warning($"Colony: {label} - null MethodInfo"); return; }
            var native = *(nint*)mi;
            pinned = hookFn;
            hook = new NativeHook<T>(native, Marshal.GetFunctionPointerForDelegate(pinned));
            hook.Attach();
            Melon<Core>.Logger.Msg($"Colony: {label} hooked @ 0x{native:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"Colony: {label} - {ex.Message}");
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static float Mult => System.Math.Max(1.0f, Core.ColonySpeedMultiplier.Value);
    private static bool Enabled => Core.ColonyModEnabled.Value && Mult > 1.0f;

    private static void Log(string msg)
    {
        if (++_logCount <= MaxLogs) Melon<Core>.Logger.Msg(msg);
    }

    private static string TS(long ticks) =>
        System.TimeSpan.FromTicks(System.Math.Abs(ticks)).ToString(@"d\.hh\:mm\:ss");

    /// <summary>
    /// Scale m_completeTime (offset 0x30) on a plant task instance, ONCE.
    /// Subsequent calls for the same pointer are no-ops.
    /// </summary>
    private static void ScaleCompleteTimeOnce(nint taskPtr, string label)
    {
        if (_scaledPlants.Contains(taskPtr)) return;

        long completeTicks = *(long*)(taskPtr + 0x30);
        long nowTicks = System.DateTime.Now.Ticks;
        long remainTicks = completeTicks - nowTicks;

        if (remainTicks <= 0)
        {
            _scaledPlants.Add(taskPtr);
            return; // already complete
        }

        double mult = Mult;
        long scaled = System.Math.Max((long)(remainTicks / mult), System.TimeSpan.TicksPerSecond);
        *(long*)(taskPtr + 0x30) = nowTicks + scaled;
        _scaledPlants.Add(taskPtr);

        Log($"[Colony] {label}: m_completeTime {TS(remainTicks)} -> {TS(scaled)} (/{mult})");
    }

    // ═══════════════════════════════════════════════════════════════════
    //  FENCE: GetMinutes hook
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>
    /// Reduces fence build minutes. GetRemainTime's clamp uses this, so it
    /// self-corrects m_completeTime every tick. Handles all fence scenarios.
    /// </summary>
    private static int GetMinutes_Hook(nint self, nint mi)
    {
        try
        {
            int orig = _getMinutesHook.Trampoline(self, mi);
            if (!Enabled) return orig;
            int result = System.Math.Max(1, (int)(orig / Mult));
            Log($"[Colony] FenceGetMinutes: {orig} -> {result} (/{Mult})");
            return result;
        }
        catch { return 1; }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  PLANT: GetRemainTime hook
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>
    /// Handles existing saves: on first call per task, scale m_completeTime.
    /// Then call original (which now computes from the adjusted m_completeTime).
    /// Does NOT scale the return value -- avoids double-scaling spiral.
    /// </summary>
    private static long PlantGetRemainTime_Hook(nint self, nint mi)
    {
        try
        {
            if (!_inPlantEntry && Enabled)
            {
                // First-time correction for existing saves or after Resume
                ScaleCompleteTimeOnce(self, "PlantGetRemain[existing]");
            }

            // Call original. If m_completeTime was just scaled, the original
            // computes a naturally smaller remain. The original's own clamp
            // (using raw Details.minutes) won't trigger because our scaled
            // remain is always < rawMinutes/personnel.
            return _plantGetRemainHook.Trampoline(self, mi);
        }
        catch { return 0; }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  PLANT: Entry hook
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>
    /// After Entry sets m_completeTime, scale it. Guard prevents
    /// GetRemainTime (called inside Entry) from pre-scaling.
    /// </summary>
    private static void PlantEntry_Hook(nint self, int personnel, nint mi)
    {
        try
        {
            // Clear tracking so we can re-scale after this Entry
            _scaledPlants.Remove(self);

            // Guard: suppress GetRemainTime scaling inside Entry
            _inPlantEntry = true;
            try { _plantEntryHook.Trampoline(self, personnel, mi); }
            finally { _inPlantEntry = false; }

            if (!Enabled) { _scaledPlants.Add(self); return; }

            // Scale the freshly-set m_completeTime
            long completeTicks = *(long*)(self + 0x30);
            long nowTicks = System.DateTime.Now.Ticks;
            long remainTicks = completeTicks - nowTicks;

            if (remainTicks <= 0) { _scaledPlants.Add(self); return; }

            double mult = Mult;
            long scaled = System.Math.Max((long)(remainTicks / mult), System.TimeSpan.TicksPerSecond);
            *(long*)(self + 0x30) = nowTicks + scaled;
            _scaledPlants.Add(self);

            Log($"[Colony] PlantEntry({personnel}): {TS(remainTicks)} -> {TS(scaled)} (/{mult})");
        }
        catch
        {
            _inPlantEntry = false;
            try { _plantEntryHook.Trampoline(self, personnel, mi); } catch { }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  PLANT: DataAccessor.GetPlantRemainTime (no-workers path)
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>
    /// When no workers are assigned, returns totalMinutes - progress.
    /// Scale the result so the displayed "required time" is reduced.
    /// Skip scaling when called from Entry (guard flag) to avoid double-scaling:
    /// Entry -> GetRemainTime -> GetPlantRemainTime (here). Entry hook will
    /// scale m_completeTime separately.
    /// </summary>
    private static long PlantDataRemainTime_Hook(nint self, int plantId, nint mi)
    {
        try
        {
            long orig = _plantDataRemainHook.Trampoline(self, plantId, mi);
            if (_inPlantEntry || !Enabled) return orig;
            double mult = Mult;
            long result = (long)(orig / mult);
            if (orig > 0 && result < System.TimeSpan.TicksPerSecond)
                result = System.TimeSpan.TicksPerSecond;
            Log($"[Colony] PlantDataRemain[{plantId}]: {TS(orig)} -> {TS(result)}");
            return result;
        }
        catch { return 0; }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  PLANT: Reduce hook
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>
    /// Reduce(minMinutes) caps m_completeTime to now + minMinutes.
    /// Scale minMinutes for a tighter deadline.
    /// Clear tracking since m_completeTime changes.
    /// </summary>
    private static void PlantReduce_Hook(nint self, int minMinutes, nint mi)
    {
        try
        {
            _scaledPlants.Remove(self);
            int scaled = minMinutes;
            if (Enabled)
            {
                scaled = System.Math.Max(1, (int)(minMinutes / Mult));
                Log($"[Colony] PlantReduce: {minMinutes} min -> {scaled} min");
            }
            _plantReduceHook.Trampoline(self, scaled, mi);
            _scaledPlants.Add(self); // Reduce already set a scaled m_completeTime
        }
        catch
        {
            try { _plantReduceHook.Trampoline(self, minMinutes, mi); } catch { }
        }
    }
}
