using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// BP system — periodic field-write approach.
///
/// Instead of hooking SetBP/GetBP (which miss recovery writes that go directly
/// to BtlHelper_CommandCtrl.m_nBP), we hook AddBPByTeam and write extra BP
/// directly to each character's field after the original +1 recovery runs.
///
/// Key structures (verified via Ghidra):
///   BtlChara+0x140 = BtlHelper_CommandCtrl ptr
///   BtlHelper_CommandCtrl+0x18 = m_nBP (current BP, int)
///   BtlHelper_CommandCtrl+0x1C = m_nBaseBP (base BP, int)
///   BtlCharaManager+0x20 = IL2CPP array of BtlChara
///     array+0x18 = length (int), array+0x20 = first element (nint)
///   BtlChara+0x2C = m_team (0=player, 1=enemy)
/// </summary>
public static unsafe class NativeBPPatch
{
    // void AddBPByTeam(this BtlCharaManager, int team, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_AddBPByTeam(nint instance, int team, nint methodInfo);

    // bool IsEnableBrave(int partyindex, BtlLayoutCtrl*, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate byte d_IsEnableBrave(int partyindex, nint pBtlLayoutCtrl, nint methodInfo);

    private static NativeHook<d_AddBPByTeam> _addBPHook;
    private static NativeHook<d_IsEnableBrave> _braveHook;

    private static d_AddBPByTeam _pAddBP;
    private static d_IsEnableBrave _pBrave;

    public static void Apply()
    {
        Hook(typeof(Il2Cpp.BtlCharaManager),
            "NativeMethodInfoPtr_AddBPByTeam_Public_Void_Int32_0",
            "AddBPByTeam", ref _pAddBP, AddBPByTeam_Hook, out _addBPHook);

        Hook(typeof(Il2Cpp.gfc),
            "NativeMethodInfoPtr_IsEnableBrave_Public_Static_Boolean_Int32_BtlLayoutCtrl_0",
            "IsEnableBrave", ref _pBrave, IsEnableBrave_Hook, out _braveHook);
    }

    private static void Hook<T>(System.Type type, string fieldName, string name,
        ref T pinned, T hookDelegate, out NativeHook<T> hook) where T : System.Delegate
    {
        hook = default;
        try
        {
            var field = type.GetField(fieldName,
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Melon<Core>.Logger.Warning($"{name}: field not found"); return; }
            var mi = (nint)field.GetValue(null);
            if (mi == 0) return;
            var native = *(nint*)mi;
            pinned = hookDelegate;
            var hookPtr = Marshal.GetFunctionPointerForDelegate(pinned);
            hook = new NativeHook<T>(native, hookPtr);
            hook.Attach();
            Melon<Core>.Logger.Msg($"{name}: native hook @ 0x{native:X}");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"{name}: {ex.Message}");
        }
    }

    private static int _addBPLog = 0;

    private static void AddBPByTeam_Hook(nint instance, int team, nint methodInfo)
    {
        try
        {
            // Always call original first — it adds +1 BP via SetBP(GetBP()+1)
            _addBPHook.Trampoline(instance, team, methodInfo);

            if (!Core.BpModEnabled.Value || Core.BpPerTurn.Value <= 1)
                return;

            int extra = Core.BpPerTurn.Value - 1; // how many extra BP beyond the +1 already added
            int limit = Core.BpLimitOverride.Value;

            // instance = BtlCharaManager, +0x20 = IL2CPP array of BtlChara
            nint arrayPtr = *(nint*)(instance + 0x20);
            if (arrayPtr == 0) return;

            int length = *(int*)(arrayPtr + 0x18);
            if (length <= 0 || length > 64) return; // sanity check

            for (int i = 0; i < length; i++)
            {
                nint chara = *(nint*)(arrayPtr + 0x20 + i * 8); // sizeof(nint) = 8 on x64
                if (chara == 0) continue;

                // Check m_team matches the team parameter
                int charaTeam = *(int*)(chara + 0x2C);
                if (charaTeam != team) continue;

                // Read current BP from BtlHelper_CommandCtrl
                nint cmdCtrl = *(nint*)(chara + 0x140);
                if (cmdCtrl == 0) continue;

                int currentBP = *(int*)(cmdCtrl + 0x18);

                // Add extra BP, clamped to limit
                int newBP = System.Math.Min(currentBP + extra, limit);
                if (newBP != currentBP)
                {
                    *(int*)(cmdCtrl + 0x18) = newBP;  // m_nBP
                    *(int*)(cmdCtrl + 0x1C) = newBP;  // m_nBaseBP
                }

                _addBPLog++;
                if (_addBPLog <= 10)
                    Melon<Core>.Logger.Msg($"[BP] AddBPByTeam: chara[{i}] team={team} BP {currentBP} -> {newBP} (limit {limit})");
            }
        }
        catch
        {
            try { _addBPHook.Trampoline(instance, team, methodInfo); } catch { }
        }
    }

    private static byte IsEnableBrave_Hook(int partyindex, nint pBtlLayoutCtrl, nint methodInfo)
    {
        try
        {
            // Pass through to original — no extension needed for now
            return _braveHook.Trampoline(partyindex, pBtlLayoutCtrl, methodInfo);
        }
        catch { return 0; }
    }
}
