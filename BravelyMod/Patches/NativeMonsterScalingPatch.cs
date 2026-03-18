using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;

namespace BravelyMod.Patches;

/// <summary>
/// Monster/Boss stat scaling. Hooks CalcBtlCharaStatus (virtual Slot 138) on
/// BtlChara + 3 boss overrides, plus CalcBtlCharaStatusBoss for Orthros.
/// After the original computes BtlCharaParameter, scales fields by configured multipliers.
///
/// BtlChara.m_type (0x1C): 0=player, 1=monster, 2=boss
/// BtlChara.m_parameter (0x108): BtlCharaParameter instance
/// </summary>
public static unsafe class NativeMonsterScalingPatch
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_CalcStatus(nint instance, byte isInit, byte noJobInit, nint methodInfo);

    // Base BtlChara virtual
    private static NativeHook<d_CalcStatus> _baseHook;
    private static d_CalcStatus _pinnedBase;

    // BtlBossOrthrosClone override
    private static NativeHook<d_CalcStatus> _orthrosCloneHook;
    private static d_CalcStatus _pinnedOrthrosClone;

    // BtlBossRusalka override
    private static NativeHook<d_CalcStatus> _rusalkaHook;
    private static d_CalcStatus _pinnedRusalka;

    // BtlBossOrthros.CalcBtlCharaStatusBoss (non-virtual, separate method)
    private static NativeHook<d_CalcStatus> _orthrosBossHook;
    private static d_CalcStatus _pinnedOrthrosBoss;

    private static int _logCount;
    private const int MaxLogs = 20;

    // RVAs from Ghidra (image base 0x180000000)
    private const long RVA_BASE          = 0x996850;  // BtlChara$$CalcBtlCharaStatus
    private const long RVA_ORTHROS_CLONE = 0x9883B0;  // BtlBossOrthrosClone$$CalcBtlCharaStatus
    private const long RVA_RUSALKA      = 0x9946E0;  // BtlBossRusalka$$CalcBtlCharaStatus
    private const long RVA_ORTHROS_BOSS = 0x98BFE0;  // BtlBossOrthros$$CalcBtlCharaStatusBoss

    public static void Apply()
    {
        Log($"Applying monster scaling hooks (enabled={Core.MonsterScalingEnabled.Value})");

        // Try reflection first, fall back to RVA
        bool ok = false;
        ok |= HookReflection<d_CalcStatus>(
            typeof(Il2Cpp.BtlChara),
            "NativeMethodInfoPtr_CalcBtlCharaStatus_Public_Virtual_New_Void_Boolean_Boolean_0",
            Hook_Base, ref _pinnedBase, ref _baseHook, "BtlChara.CalcBtlCharaStatus");

        if (!ok)
            ok |= HookRVA(RVA_BASE, Hook_Base, ref _pinnedBase, ref _baseHook, "BtlChara.CalcBtlCharaStatus (RVA)");

        // Boss overrides — try reflection, fall back to RVA
        TryHookType("BtlBossOrthrosClone",
            "NativeMethodInfoPtr_CalcBtlCharaStatus_Public_Override_Void_Boolean_Boolean_0",
            RVA_ORTHROS_CLONE, Hook_OrthrosClone, ref _pinnedOrthrosClone, ref _orthrosCloneHook,
            "BtlBossOrthrosClone.CalcBtlCharaStatus");

        TryHookType("BtlBossRusalka",
            "NativeMethodInfoPtr_CalcBtlCharaStatus_Public_Override_Void_Boolean_Boolean_0",
            RVA_RUSALKA, Hook_Rusalka, ref _pinnedRusalka, ref _rusalkaHook,
            "BtlBossRusalka.CalcBtlCharaStatus");

        // Orthros boss-specific calc (non-virtual, separate method name)
        TryHookType("BtlBossOrthros",
            "NativeMethodInfoPtr_CalcBtlCharaStatusBoss_Public_Void_Boolean_Boolean_0",
            RVA_ORTHROS_BOSS, Hook_OrthrosBoss, ref _pinnedOrthrosBoss, ref _orthrosBossHook,
            "BtlBossOrthros.CalcBtlCharaStatusBoss");

        Log("Monster scaling hooks applied");
    }

    // ── Hook implementations ──────────────────────────────────────────

    private static void Hook_Base(nint inst, byte isInit, byte noJobInit, nint mi)
    {
        try { _baseHook.Trampoline(inst, isInit, noJobInit, mi); } catch { return; }
        if (isInit != 0) ScaleStats(inst);
    }

    private static void Hook_OrthrosClone(nint inst, byte isInit, byte noJobInit, nint mi)
    {
        try { _orthrosCloneHook.Trampoline(inst, isInit, noJobInit, mi); } catch { return; }
        if (isInit != 0) ScaleStats(inst);
    }

    private static void Hook_Rusalka(nint inst, byte isInit, byte noJobInit, nint mi)
    {
        try { _rusalkaHook.Trampoline(inst, isInit, noJobInit, mi); } catch { return; }
        if (isInit != 0) ScaleStats(inst);
    }

    private static void Hook_OrthrosBoss(nint inst, byte isInit, byte noJobInit, nint mi)
    {
        try { _orthrosBossHook.Trampoline(inst, isInit, noJobInit, mi); } catch { return; }
        if (isInit != 0) ScaleStats(inst);
    }

    // ── Stat scaling logic ────────────────────────────────────────────

    private static void ScaleStats(nint btlChara)
    {
        try
        {
            int charaType = *(int*)(btlChara + 0x1C); // m_type
            if (charaType == 0) return; // player — never touch

            nint param = *(nint*)(btlChara + 0x108); // m_parameter
            if (param == 0) return;

            bool isBoss = (charaType == 2);
            float hp   = isBoss ? Core.BossHpMult.Value   : Core.MonsterHpMult.Value;
            float atk  = isBoss ? Core.BossAtkMult.Value  : Core.MonsterAtkMult.Value;
            float def  = isBoss ? Core.BossDefMult.Value  : Core.MonsterDefMult.Value;
            float matk = isBoss ? Core.BossMAtkMult.Value : Core.MonsterMAtkMult.Value;
            float mdef = isBoss ? Core.BossMDefMult.Value : Core.MonsterMDefMult.Value;
            float spd  = isBoss ? Core.BossSpeedMult.Value: Core.MonsterSpeedMult.Value;
            float rwd  = isBoss ? Core.BossRewardMult.Value : Core.MonsterRewardMult.Value;

            // HP/MP
            ScaleInt(param + 0x88, hp);  // hp (current)
            ScaleInt(param + 0x94, hp);  // hpMax
            ScaleInt(param + 0x98, hp);  // mpMax
            // Also scale current mp to match mpMax ratio
            ScaleInt(param + 0x90, hp);  // mp (current)

            // Attack array (int[] at 0xD8)
            nint atkArr = *(nint*)(param + 0xD8);
            if (atkArr != 0)
            {
                int len = *(int*)(atkArr + 0x18);
                for (int i = 0; i < len && i < 8; i++)
                    ScaleInt(atkArr + 0x20 + i * 4, atk);
            }

            // Physical stats
            ScaleInt(param + 0xE0, def);  // deffence
            ScaleInt(param + 0xE4, matk); // magicAttack
            ScaleInt(param + 0xE8, mdef); // magicDeffence
            ScaleInt(param + 0xEC, atk);  // strength
            ScaleInt(param + 0xF0, def);  // stamina
            ScaleInt(param + 0xF4, matk); // intelligence
            ScaleInt(param + 0xF8, mdef); // mind

            // Speed stats
            ScaleInt(param + 0xFC, spd);  // dexterity
            ScaleInt(param + 0x100, spd); // agility
            ScaleInt(param + 0x104, spd); // actSpeed
            ScaleInt(param + 0x11C, spd); // criticalRate

            // Rewards
            ScaleInt(param + 0x158, rwd); // getEXP
            ScaleInt(param + 0x15C, rwd); // getGIL
            ScaleInt(param + 0x160, rwd); // getJobEXP

            _logCount++;
            if (_logCount <= MaxLogs)
            {
                string tag = isBoss ? "Boss" : "Monster";
                int hpVal = *(int*)(param + 0x94);
                int atkVal = *(int*)(param + 0xE0);
                Log($"[{tag}] Scaled: HP={hpVal} DEF={atkVal} (hp={hp}x atk={atk}x def={def}x spd={spd}x)");
            }
        }
        catch (System.Exception ex)
        {
            _logCount++;
            if (_logCount <= 5) Warn($"ScaleStats error: {ex.Message}");
        }
    }

    private static void ScaleInt(nint addr, float mult)
    {
        if (System.Math.Abs(mult - 1.0f) < 0.001f) return;
        int* p = (int*)addr;
        int val = (int)(*p * mult);
        if (val < 0) val = 0;
        *p = val;
    }

    // ── Hook helpers ──────────────────────────────────────────────────

    private static void TryHookType(string typeName, string fieldName, long rva,
        d_CalcStatus hookFn, ref d_CalcStatus pinned, ref NativeHook<d_CalcStatus> hook, string label)
    {
        // Try reflection
        try
        {
            var type = System.Type.GetType($"Il2Cpp.{typeName}, Assembly-CSharp");
            if (type != null)
            {
                if (HookReflection<d_CalcStatus>(type, fieldName, hookFn, ref pinned, ref hook, label))
                    return;
            }
        }
        catch { }

        // Fall back to RVA
        HookRVA(rva, hookFn, ref pinned, ref hook, $"{label} (RVA)");
    }

    private static bool HookReflection<T>(System.Type type, string fieldName,
        T hookFn, ref T pinned, ref NativeHook<T> hook, string label) where T : System.Delegate
    {
        try
        {
            var field = type.GetField(fieldName,
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (field == null) { Log($"{label}: field not found"); return false; }

            var mi = (nint)field.GetValue(null);
            if (mi == 0) { Log($"{label}: null MethodInfo"); return false; }

            var native = *(nint*)mi;
            pinned = hookFn;
            hook = new NativeHook<T>(native, Marshal.GetFunctionPointerForDelegate(pinned));
            hook.Attach();
            Log($"{label} hooked @ 0x{native:X}");
            return true;
        }
        catch (System.Exception ex) { Log($"{label}: {ex.Message}"); return false; }
    }

    private static bool HookRVA(long rva, d_CalcStatus hookFn,
        ref d_CalcStatus pinned, ref NativeHook<d_CalcStatus> hook, string label)
    {
        try
        {
            var proc = System.Diagnostics.Process.GetCurrentProcess();
            foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
            {
                if (mod.ModuleName != null &&
                    mod.ModuleName.Equals("GameAssembly.dll", System.StringComparison.OrdinalIgnoreCase))
                {
                    nint addr = mod.BaseAddress + (nint)rva;
                    pinned = hookFn;
                    hook = new NativeHook<d_CalcStatus>(addr, Marshal.GetFunctionPointerForDelegate(pinned));
                    hook.Attach();
                    Log($"{label} hooked @ 0x{addr:X}");
                    return true;
                }
            }
        }
        catch (System.Exception ex) { Log($"{label}: RVA failed: {ex.Message}"); }
        return false;
    }

    private static void Log(string msg) => Melon<Core>.Logger.Msg($"[MonsterScaling] {msg}");
    private static void Warn(string msg) => Melon<Core>.Logger.Warning($"[MonsterScaling] {msg}");
}
