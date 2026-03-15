using MelonLoader;

namespace BravelyMod.AutoBattle;

/// <summary>
/// Reads battle state from IL2CPP pointers via unsafe pointer chasing.
/// All offsets are from Ghidra analysis of GameAssembly.dll.
/// </summary>
public static unsafe class BattleState
{
    // ── Offsets ──────────────────────────────────────────────
    // BtlLayoutCtrl -> BtlCharaManager
    private const int OFF_LAYOUT_CHARA_MGR = 0x218;

    // BtlCharaManager -> character array (Il2CppArrayBase)
    private const int OFF_MGR_CHARA_ARRAY = 0x20;

    // Il2CppArray: length at 0x18, first element at 0x20
    private const int OFF_ARRAY_LENGTH = 0x18;
    private const int OFF_ARRAY_DATA = 0x20;

    // BtlChara fields
    private const int OFF_CHARA_INDEX = 0x20;   // m_index (int)
    private const int OFF_CHARA_TEAM = 0x2C;    // m_team (int, 0=player, 1=enemy)

    // BtlChara.GetParameter() -> field at 0x108 -> BtlCharaParameter
    private const int OFF_CHARA_PARAM_FIELD = 0x108;

    // BtlCharaParameter fields
    private const int OFF_PARAM_HP = 0x88;
    private const int OFF_PARAM_MP = 0x90;
    private const int OFF_PARAM_HPMAX = 0x94;
    private const int OFF_PARAM_MPMAX = 0x98;

    /// <summary>
    /// Build a <see cref="BattleSnapshot"/> from a BtlLayoutCtrl instance pointer.
    /// Returns null if pointer chasing fails at any step.
    /// </summary>
    public static BattleSnapshot? ReadBattleState(nint btlLayoutCtrl)
    {
        try
        {
            if (btlLayoutCtrl == 0) return null;

            // BtlLayoutCtrl -> BtlCharaManager
            nint charaMgr = *(nint*)(btlLayoutCtrl + OFF_LAYOUT_CHARA_MGR);
            if (charaMgr == 0)
            {
                Melon<Core>.Logger.Warning("[AutoBattle] BtlCharaManager is null");
                return null;
            }

            // BtlCharaManager -> character array pointer
            nint charaArray = *(nint*)(charaMgr + OFF_MGR_CHARA_ARRAY);
            if (charaArray == 0)
            {
                Melon<Core>.Logger.Warning("[AutoBattle] Character array is null");
                return null;
            }

            int arrayLen = *(int*)(charaArray + OFF_ARRAY_LENGTH);
            if (arrayLen <= 0 || arrayLen > 20)
            {
                Melon<Core>.Logger.Warning($"[AutoBattle] Suspicious array length: {arrayLen}");
                return null;
            }

            var players = new List<CharacterSnapshot>();
            var enemies = new List<CharacterSnapshot>();

            for (int i = 0; i < arrayLen; i++)
            {
                nint charaPtr = *(nint*)(charaArray + OFF_ARRAY_DATA + i * sizeof(nint));
                if (charaPtr == 0) continue;

                var snap = ReadCharacter(charaPtr);
                if (snap == null) continue;

                if (snap.Value.Team == 0)
                    players.Add(snap.Value);
                else
                    enemies.Add(snap.Value);
            }

            return new BattleSnapshot(players.ToArray(), enemies.ToArray());
        }
        catch (System.Exception ex)
        {
            Melon<Core>.Logger.Warning($"[AutoBattle] ReadBattleState failed: {ex.Message}");
            return null;
        }
    }

    private static CharacterSnapshot? ReadCharacter(nint charaPtr)
    {
        try
        {
            int index = *(int*)(charaPtr + OFF_CHARA_INDEX);
            int team = *(int*)(charaPtr + OFF_CHARA_TEAM);

            // Read parameter block
            nint paramPtr = *(nint*)(charaPtr + OFF_CHARA_PARAM_FIELD);
            int hp = 0, hpMax = 0, mp = 0, mpMax = 0;
            if (paramPtr != 0)
            {
                hp = *(int*)(paramPtr + OFF_PARAM_HP);
                mp = *(int*)(paramPtr + OFF_PARAM_MP);
                hpMax = *(int*)(paramPtr + OFF_PARAM_HPMAX);
                mpMax = *(int*)(paramPtr + OFF_PARAM_MPMAX);
            }

            bool isDead = hp <= 0;

            return new CharacterSnapshot(index, team, hp, hpMax, mp, mpMax, bp: 0, isDead);
        }
        catch
        {
            return null;
        }
    }
}
