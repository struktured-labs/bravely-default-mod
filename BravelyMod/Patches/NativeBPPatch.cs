using System.Diagnostics;
using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// BP system patches — combines two approaches:
///
/// 1. **Memory patching** — Overwrites hardcoded constants in GameAssembly.dll's
///    SetBP and IsEnableBrave functions at runtime via VirtualProtect + direct byte writes.
///    This changes the caps the game engine enforces internally:
///      SetBP:         maxBP literal 3→9, floor literal -4→-9
///      IsEnableBrave:  action cap 4→10, BP floor check -5→-10 (encoded as -4→-9 after dec)
///
/// 2. **AddBPByTeam hook** — Adds extra BP per turn beyond the vanilla +1 recovery.
///    Writes directly to BtlHelper_CommandCtrl.m_nBP / m_nBaseBP fields.
///
/// Assembly analysis (x86-64, from Ghidra/objdump):
///
///   SetBP @ VA 0x18099F1B0:
///     +0x86: 8d 56 03          lea 0x3(%rsi),%edx     ; maxBP = ability_flag + 3
///     +0x95: 41 8d 48 fc       lea -0x4(%r8),%ecx     ; floor = -4
///     Patch: byte at +0x88 (the 0x03) and byte at +0x98 (the 0xFC)
///
///   IsEnableBrave @ VA 0x1805BBFE0:
///     +0x1E0: ff c8             dec %eax
///     +0x1E2: 83 f8 fc          cmp $-4,%eax           ; encodes "remainingBP > -5"
///     +0x1E8: 83 ff 04          cmp $4,%edi            ; action count < 4
///     Patch: byte at +0x1E4 (the 0xFC) and byte at +0x1EA (the 0x04)
/// </summary>
public static unsafe class NativeBPPatch
{
    // ── Hook delegates ──────────────────────────────────────────────

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

    // ── VirtualProtect P/Invoke (Windows/Wine) ──────────────────────

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(nint lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);

    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_READ = 0x20;

    // ── RVA offsets (from GameAssembly.dll image base) ──────────────
    // === THREE SetBP locations (all have hardcoded 0x03 for BP cap) ===

    // 1. ReadyAP (BtlCharaPlayer) — THE CRITICAL ONE: per-turn BP recovery cap
    //    ADD R14D, 0x3 at VA 0x18098FCDE, the 0x03 byte is at 0x18098FCE1
    private const long RVA_ReadyAP_MaxBP = 0x98FCE1;
    private const byte OLD_ReadyAP_MaxBP = 0x03;
    private const byte NEW_ReadyAP_MaxBP = 0x09;

    // 2. BtlCharaPlayer::SetBP — player override SetBP clamp
    //    LEA EDX, [RSI+0x3] at VA 0x18098FFC6, the 0x03 byte is at 0x18098FFC8
    private const long RVA_PlayerSetBP_MaxBP = 0x98FFC8;
    private const byte OLD_PlayerSetBP_MaxBP = 0x03;
    private const byte NEW_PlayerSetBP_MaxBP = 0x09;

    // 3. BtlChara::SetBP (base) — non-player fallback
    private const long RVA_SetBP_MaxBP = 0x99F238;
    private const byte OLD_SetBP_MaxBP = 0x03;
    private const byte NEW_SetBP_MaxBP = 0x09;

    // SetBP floor: -4 → -9 (base class)
    private const long RVA_SetBP_Floor = 0x99F248;
    private const byte OLD_SetBP_Floor = 0xFC;
    private const byte NEW_SetBP_Floor = 0xF7;

    // IsEnableBrave: BP floor check
    private const long RVA_Brave_BPFloor = 0x5BC1C4;
    private const byte OLD_Brave_BPFloor = 0xFC;
    private const byte NEW_Brave_BPFloor = 0xF7;

    // IsEnableBrave: action cap 4 → 10
    private const long RVA_Brave_ActionCap = 0x5BC1CA;
    private const byte OLD_Brave_ActionCap = 0x04;
    private const byte NEW_Brave_ActionCap = 0x0A;

    // ── Public entry point ──────────────────────────────────────────

    public static void Apply()
    {
        // Apply memory patches to hardcoded constants
        ApplyMemoryPatches();

        // Hook AddBPByTeam for extra BP per turn
        Hook(typeof(Il2Cpp.BtlCharaManager),
            "NativeMethodInfoPtr_AddBPByTeam_Public_Void_Int32_0",
            "AddBPByTeam", ref _pAddBP, AddBPByTeam_Hook, out _addBPHook);

        // Hook IsEnableBrave as passthrough (memory patch handles the constant change)
        Hook(typeof(Il2Cpp.gfc),
            "NativeMethodInfoPtr_IsEnableBrave_Public_Static_Boolean_Int32_BtlLayoutCtrl_0",
            "IsEnableBrave", ref _pBrave, IsEnableBrave_Hook, out _braveHook);
    }

    // ── Memory patching ─────────────────────────────────────────────

    private static void ApplyMemoryPatches()
    {
        try
        {
            nint dllBase = FindGameAssemblyBase();
            if (dllBase == 0)
            {
                Melon<Core>.Logger.Warning("[BP-Patch] Could not find GameAssembly.dll base address");
                return;
            }

            Melon<Core>.Logger.Msg($"[BP-Patch] GameAssembly.dll base: 0x{dllBase:X}");

            int patched = 0;

            // THE critical patch: ReadyAP per-turn recovery cap
            patched += PatchByte(dllBase, RVA_ReadyAP_MaxBP, OLD_ReadyAP_MaxBP, NEW_ReadyAP_MaxBP,
                "ReadyAP maxBP (3→9) [CRITICAL]") ? 1 : 0;

            // Player SetBP override clamp
            patched += PatchByte(dllBase, RVA_PlayerSetBP_MaxBP, OLD_PlayerSetBP_MaxBP, NEW_PlayerSetBP_MaxBP,
                "PlayerSetBP maxBP (3→9)") ? 1 : 0;

            // Base SetBP clamp (non-player fallback)
            patched += PatchByte(dllBase, RVA_SetBP_MaxBP, OLD_SetBP_MaxBP, NEW_SetBP_MaxBP,
                "BaseSetBP maxBP (3→9)") ? 1 : 0;
            patched += PatchByte(dllBase, RVA_SetBP_Floor, OLD_SetBP_Floor, NEW_SetBP_Floor,
                "SetBP floor (-4→-9)") ? 1 : 0;

            // IsEnableBrave limits
            patched += PatchByte(dllBase, RVA_Brave_BPFloor, OLD_Brave_BPFloor, NEW_Brave_BPFloor,
                "IsEnableBrave BP floor (-5→-10)") ? 1 : 0;
            patched += PatchByte(dllBase, RVA_Brave_ActionCap, OLD_Brave_ActionCap, NEW_Brave_ActionCap,
                "IsEnableBrave action cap (4→10)") ? 1 : 0;

            Melon<Core>.Logger.Msg($"[BP-Patch] Memory patches applied: {patched}/6");
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"[BP-Patch] Memory patching failed: {ex.Message}");
        }
    }

    private static nint FindGameAssemblyBase()
    {
        try
        {
            var proc = Process.GetCurrentProcess();
            foreach (ProcessModule mod in proc.Modules)
            {
                if (mod.ModuleName != null &&
                    mod.ModuleName.Equals("GameAssembly.dll", System.StringComparison.OrdinalIgnoreCase))
                {
                    return mod.BaseAddress;
                }
            }
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"[BP-Patch] Module enumeration failed: {ex.Message}");
        }
        return 0;
    }

    private static bool PatchByte(nint dllBase, long rva, byte expected, byte replacement, string label)
    {
        nint addr = dllBase + (nint)rva;
        byte* ptr = (byte*)addr;

        // Verify the expected byte before patching
        byte current = *ptr;
        if (current != expected)
        {
            Melon<Core>.Logger.Warning(
                $"[BP-Patch] {label}: expected 0x{expected:X2} at 0x{addr:X} but found 0x{current:X2} — skipping");
            return false;
        }

        // Make page writable
        if (!VirtualProtect(addr, 4, PAGE_EXECUTE_READWRITE, out uint oldProtect))
        {
            Melon<Core>.Logger.Warning(
                $"[BP-Patch] {label}: VirtualProtect failed at 0x{addr:X}");
            return false;
        }

        // Write the patched byte
        *ptr = replacement;

        // Verify the write
        byte verify = *ptr;
        if (verify != replacement)
        {
            Melon<Core>.Logger.Warning(
                $"[BP-Patch] {label}: write verification failed (wrote 0x{replacement:X2}, read 0x{verify:X2})");
            VirtualProtect(addr, 4, oldProtect, out _);
            return false;
        }

        // Restore protection
        VirtualProtect(addr, 4, oldProtect, out _);

        Melon<Core>.Logger.Msg(
            $"[BP-Patch] {label}: patched 0x{expected:X2} → 0x{replacement:X2} at 0x{addr:X}");
        return true;
    }

    // ── Hook setup helper ───────────────────────────────────────────

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

    // ── AddBPByTeam hook (+2/turn via field write) ──────────────────

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

    // ── IsEnableBrave hook (passthrough — memory patch handles constants) ──

    private static byte IsEnableBrave_Hook(int partyindex, nint pBtlLayoutCtrl, nint methodInfo)
    {
        try
        {
            return _braveHook.Trampoline(partyindex, pBtlLayoutCtrl, methodInfo);
        }
        catch { return 0; }
    }
}
