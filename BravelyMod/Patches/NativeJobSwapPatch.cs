using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// QoL: When changing jobs, if the new job's command matches the equipped
/// secondary command, swap it to the old job's command instead of duplicating.
///
/// Hook target: CharacterState.SetJOBID(int)
/// IL2CPP sig:  void (nint instance, int jobId, nint methodInfo)
///
/// Additional native calls:
///   - JobTable.GetParam(int, bool) -> JobTable*  (static, reads JCID at +0x28)
///   - JobCommandState.Create(int)  -> JobCommandState* (static)
///   - CharacterState.SetJOBCOMMAND(JobCommandState) (instance)
/// </summary>
public static unsafe class NativeJobSwapPatch
{
    // --- Delegate types (IL2CPP calling convention: instance, params..., methodInfo) ---

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SetJOBID(nint instance, int jobId, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_JobTableGetParam(int jobId, byte bNoAbort, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_JobCommandStateCreate(int id, nint methodInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SetJOBCOMMAND(nint instance, nint jobCommandState, nint methodInfo);

    // --- Hook + pinned delegate ---

    private static NativeHook<d_SetJOBID> _setJobIdHook;
    private static d_SetJOBID _pinnedSetJobId;

    // --- Resolved native function pointers for helper calls ---

    private static nint _jobTableGetParamPtr;
    private static nint _jobTableGetParamMethodInfo;

    private static nint _jobCommandStateCreatePtr;
    private static nint _jobCommandStateCreateMethodInfo;

    private static nint _setJobCommandPtr;
    private static nint _setJobCommandMethodInfo;

    // --- Offsets (from IL2CPP dump) ---

    private const int OFF_CharacterState_JOBID = 0x28;
    private const int OFF_CharacterState_JobCommandState = 0x120;
    private const int OFF_JobCommandState_ID = 0x10;
    private const int OFF_JobTable_JCID = 0x28;

    private static int _logCount = 0;
    private const int MaxLogLines = 20;

    public static void Apply()
    {
        HookSetJOBID();
        ResolveJobTableGetParam();
        ResolveJobCommandStateCreate();
        ResolveSetJOBCOMMAND();
    }

    // ─────────────────────────────────────────
    // Hook: CharacterState.SetJOBID
    // ─────────────────────────────────────────

    private static void HookSetJOBID()
    {
        try
        {
            var field = typeof(Il2Cpp.CharacterState).GetField(
                "NativeMethodInfoPtr_SetJOBID_Public_Void_Int32_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

            if (field == null)
            {
                Melon<Core>.Logger.Warning("[JobSwap] SetJOBID field not found");
                return;
            }

            var mi = (nint)field.GetValue(null);
            if (mi == 0)
            {
                Melon<Core>.Logger.Warning("[JobSwap] SetJOBID method info ptr is null");
                return;
            }

            var native = *(nint*)mi;
            Melon<Core>.Logger.Msg($"[JobSwap] SetJOBID native @ 0x{native:X}");

            _pinnedSetJobId = SetJOBID_Hook;
            var hookPtr = Marshal.GetFunctionPointerForDelegate(_pinnedSetJobId);
            _setJobIdHook = new NativeHook<d_SetJOBID>(native, hookPtr);
            _setJobIdHook.Attach();
            Melon<Core>.Logger.Msg("[JobSwap] SetJOBID hook attached!");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"[JobSwap] SetJOBID hook failed: {ex.Message}");
        }
    }

    // ─────────────────────────────────────────
    // Resolve: JobTable.GetParam (static)
    // ─────────────────────────────────────────

    private static void ResolveJobTableGetParam()
    {
        try
        {
            var field = typeof(Il2Cpp.JobTable).GetField(
                "NativeMethodInfoPtr_GetParam_Public_Static_JobTable_Int32_Boolean_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

            if (field == null)
            {
                Melon<Core>.Logger.Warning("[JobSwap] JobTable.GetParam field not found");
                return;
            }

            var mi = (nint)field.GetValue(null);
            if (mi == 0)
            {
                Melon<Core>.Logger.Warning("[JobSwap] JobTable.GetParam method info ptr is null");
                return;
            }

            _jobTableGetParamMethodInfo = mi;
            _jobTableGetParamPtr = *(nint*)mi;
            Melon<Core>.Logger.Msg($"[JobSwap] JobTable.GetParam resolved @ 0x{_jobTableGetParamPtr:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"[JobSwap] JobTable.GetParam resolve failed: {ex.Message}");
        }
    }

    // ─────────────────────────────────────────
    // Resolve: JobCommandState.Create (static)
    // ─────────────────────────────────────────

    private static void ResolveJobCommandStateCreate()
    {
        try
        {
            var field = typeof(Il2Cpp.JobCommandState).GetField(
                "NativeMethodInfoPtr_Create_Public_Static_JobCommandState_Int32_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

            if (field == null)
            {
                Melon<Core>.Logger.Warning("[JobSwap] JobCommandState.Create field not found");
                return;
            }

            var mi = (nint)field.GetValue(null);
            if (mi == 0)
            {
                Melon<Core>.Logger.Warning("[JobSwap] JobCommandState.Create method info ptr is null");
                return;
            }

            _jobCommandStateCreateMethodInfo = mi;
            _jobCommandStateCreatePtr = *(nint*)mi;
            Melon<Core>.Logger.Msg($"[JobSwap] JobCommandState.Create resolved @ 0x{_jobCommandStateCreatePtr:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"[JobSwap] JobCommandState.Create resolve failed: {ex.Message}");
        }
    }

    // ─────────────────────────────────────────
    // Resolve: CharacterState.SetJOBCOMMAND (instance)
    // ─────────────────────────────────────────

    private static void ResolveSetJOBCOMMAND()
    {
        try
        {
            var field = typeof(Il2Cpp.CharacterState).GetField(
                "NativeMethodInfoPtr_SetJOBCOMMAND_Public_Void_JobCommandState_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

            if (field == null)
            {
                Melon<Core>.Logger.Warning("[JobSwap] SetJOBCOMMAND field not found");
                return;
            }

            var mi = (nint)field.GetValue(null);
            if (mi == 0)
            {
                Melon<Core>.Logger.Warning("[JobSwap] SetJOBCOMMAND method info ptr is null");
                return;
            }

            _setJobCommandMethodInfo = mi;
            _setJobCommandPtr = *(nint*)mi;
            Melon<Core>.Logger.Msg($"[JobSwap] SetJOBCOMMAND resolved @ 0x{_setJobCommandPtr:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"[JobSwap] SetJOBCOMMAND resolve failed: {ex.Message}");
        }
    }

    // ─────────────────────────────────────────
    // Hook implementation
    // ─────────────────────────────────────────

    private static void SetJOBID_Hook(nint instance, int newJobId, nint methodInfo)
    {
        try
        {
            // 1. Read old JOBID before the original call changes it
            int oldJobId = *(int*)(instance + OFF_CharacterState_JOBID);

            // 2. Read the current sub-command ID (secondary job command)
            //    m_JobCommandState is a pointer to a JobCommandState object
            nint subCmdStatePtr = *(nint*)(instance + OFF_CharacterState_JobCommandState);
            int subCmdId = 0;
            if (subCmdStatePtr != 0)
                subCmdId = *(int*)(subCmdStatePtr + OFF_JobCommandState_ID);

            // 3. Look up old job's JCID from JobTable
            int oldJCID = GetJobJCID(oldJobId);

            // 4. Look up new job's JCID from JobTable
            int newJCID = GetJobJCID(newJobId);

            if (_logCount < MaxLogLines)
            {
                Melon<Core>.Logger.Msg(
                    $"[JobSwap] SetJOBID: old={oldJobId}(JCID={oldJCID}) -> new={newJobId}(JCID={newJCID}), subCmd={subCmdId}");
                _logCount++;
            }

            // 5. Call the original SetJOBID
            _setJobIdHook.Trampoline(instance, newJobId, methodInfo);

            // 6. Check if the sub-command duplicates the new job's command
            //    If so, swap it to the old job's command
            if (newJCID > 0 && subCmdId == newJCID && oldJCID > 0 && oldJCID != newJCID)
            {
                if (_logCount < MaxLogLines)
                {
                    Melon<Core>.Logger.Msg(
                        $"[JobSwap] Sub-command {subCmdId} matches new job — swapping to old job's command {oldJCID}");
                    _logCount++;
                }

                // Create a new JobCommandState for the old job's command
                nint newSubCmdState = CallJobCommandStateCreate(oldJCID);
                if (newSubCmdState != 0)
                {
                    // Set it as the sub-command
                    CallSetJOBCOMMAND(instance, newSubCmdState);

                    if (_logCount < MaxLogLines)
                    {
                        Melon<Core>.Logger.Msg($"[JobSwap] Swap complete: sub-command now {oldJCID}");
                        _logCount++;
                    }
                }
                else if (_logCount < MaxLogLines)
                {
                    Melon<Core>.Logger.Warning("[JobSwap] JobCommandState.Create returned null");
                    _logCount++;
                }
            }
        }
        catch (System.Exception ex)
        {
            if (_logCount < MaxLogLines)
            {
                Melon<Core>.Logger.Warning($"[JobSwap] Hook exception: {ex.Message}");
                _logCount++;
            }

            // Make sure the original still runs if our logic threw before calling it
            try { _setJobIdHook.Trampoline(instance, newJobId, methodInfo); } catch { }
        }
    }

    // ─────────────────────────────────────────
    // Native call helpers
    // ─────────────────────────────────────────

    /// <summary>
    /// Call JobTable.GetParam(jobId, false) and read JCID from the returned object.
    /// Returns 0 on failure.
    /// </summary>
    private static int GetJobJCID(int jobId)
    {
        if (_jobTableGetParamPtr == 0) return 0;
        try
        {
            var fn = (delegate* unmanaged[Cdecl]<int, byte, nint, nint>)_jobTableGetParamPtr;
            nint jobTableObj = fn(jobId, 0, _jobTableGetParamMethodInfo);
            if (jobTableObj == 0) return 0;
            return *(int*)(jobTableObj + OFF_JobTable_JCID);
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>
    /// Call JobCommandState.Create(id) to allocate a new JobCommandState.
    /// Returns the pointer, or 0 on failure.
    /// </summary>
    private static nint CallJobCommandStateCreate(int id)
    {
        if (_jobCommandStateCreatePtr == 0) return 0;
        try
        {
            var fn = (delegate* unmanaged[Cdecl]<int, nint, nint>)_jobCommandStateCreatePtr;
            return fn(id, _jobCommandStateCreateMethodInfo);
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>
    /// Call CharacterState.SetJOBCOMMAND(instance, jobCommandState).
    /// </summary>
    private static void CallSetJOBCOMMAND(nint instance, nint jobCommandState)
    {
        if (_setJobCommandPtr == 0) return;
        try
        {
            var fn = (delegate* unmanaged[Cdecl]<nint, nint, nint, void>)_setJobCommandPtr;
            fn(instance, jobCommandState, _setJobCommandMethodInfo);
        }
        catch
        {
            // Silently fail — don't crash the game
        }
    }
}
