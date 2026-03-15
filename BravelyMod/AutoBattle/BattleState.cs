using MelonLoader;

namespace BravelyMod.AutoBattle;

/// <summary>
/// Reads battle state from IL2CPP pointers via unsafe pointer chasing.
/// All offsets verified against il2cpp dump.cs and Ghidra decompilation of GameAssembly.dll.
/// </summary>
public static unsafe class BattleState
{
    // ── Offsets (verified via dump.cs + Ghidra) ────────────────

    // BtlLayoutCtrl -> BtlCharaManager  (dump.cs line: private BtlCharaManager m_pBtlCharaManager; // 0x218)
    private const int OFF_LAYOUT_CHARA_MGR = 0x218;

    // BtlCharaManager -> BtlChara[] m_battleCharaPtrArray  (dump.cs: 0x20)
    private const int OFF_MGR_CHARA_ARRAY = 0x20;

    // IL2CPP managed array layout (64-bit):
    //   0x00  klass*    (8 bytes)
    //   0x08  monitor*  (8 bytes)
    //   0x10  bounds*   (8 bytes, NULL for single-dim)
    //   0x18  max_length (nint, but low 4 bytes suffice)
    //   0x20  elements[0] ...
    private const int OFF_ARRAY_LENGTH = 0x18;
    private const int OFF_ARRAY_DATA   = 0x20;

    // BtlChara fields (dump.cs offsets, verified by Ghidra)
    private const int OFF_CHARA_IS_READY = 0x18;  // bool m_isReady
    private const int OFF_CHARA_INDEX    = 0x20;   // int m_index
    private const int OFF_CHARA_TEAM     = 0x2C;   // int m_team (0=player, 1=enemy)

    // BtlChara.m_parameter -> BtlCharaParameter (class reference at 0x108)
    // Confirmed by Ghidra: GetParameter() returns *(param_1 + 0x108)
    private const int OFF_CHARA_PARAM = 0x108;

    // BtlChara.m_ap -> BtlActionPoint (class reference at 0x148)
    private const int OFF_CHARA_AP = 0x148;

    // BtlChara.m_pStatusManager -> BtlStatusManager (class reference at 0x150)
    private const int OFF_CHARA_STATUS_MGR = 0x150;

    // BtlActionPoint.m_ap (int at 0x10)
    private const int OFF_AP_VALUE = 0x10;

    // BtlStatusManager.m_statusFlag (uint at 0x44) — bitmask of BTLDEF.CharaStatusFlag
    private const int OFF_STATUS_FLAG = 0x44;

    // BtlCharaParameter fields (dump.cs offsets)
    private const int OFF_PARAM_HP    = 0x88;
    private const int OFF_PARAM_MP    = 0x90;
    private const int OFF_PARAM_HPMAX = 0x94;
    private const int OFF_PARAM_MPMAX = 0x98;

    // Ghidra: GetBtlChara checks idx < 0x0E (14 max characters)
    private const int MAX_CHARA_COUNT = 14;

    /// <summary>
    /// Build a <see cref="BattleSnapshot"/> from a BtlLayoutCtrl instance pointer.
    /// Returns null if pointer chasing fails at any step.
    /// </summary>
    public static BattleSnapshot? ReadBattleState(nint btlLayoutCtrl)
    {
        try
        {
            if (btlLayoutCtrl == 0) return null;

            // Validate IL2CPP object: klass pointer at offset 0 must be non-null
            nint klass = *(nint*)btlLayoutCtrl;
            if (klass == 0) return null;

            // BtlLayoutCtrl -> BtlCharaManager
            nint charaMgr = *(nint*)(btlLayoutCtrl + OFF_LAYOUT_CHARA_MGR);
            if (charaMgr == 0)
            {
                Melon<Core>.Logger.Warning("[AutoBattle] BtlCharaManager is null");
                return null;
            }

            // Validate BtlCharaManager is a valid IL2CPP object
            if (*(nint*)charaMgr == 0) return null;

            // BtlCharaManager -> character array pointer
            nint charaArray = *(nint*)(charaMgr + OFF_MGR_CHARA_ARRAY);
            if (charaArray == 0)
            {
                Melon<Core>.Logger.Warning("[AutoBattle] Character array is null");
                return null;
            }

            // Validate array object
            if (*(nint*)charaArray == 0) return null;

            int arrayLen = *(int*)(charaArray + OFF_ARRAY_LENGTH);
            if (arrayLen <= 0 || arrayLen > MAX_CHARA_COUNT)
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

                // Validate IL2CPP object
                if (*(nint*)charaPtr == 0) continue;

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
            int team  = *(int*)(charaPtr + OFF_CHARA_TEAM);

            // Sanity: index should be in [0, MAX_CHARA_COUNT), team should be 0 or 1
            if (index < 0 || index >= MAX_CHARA_COUNT) return null;
            if (team < 0 || team > 1) return null;

            // Read parameter block
            nint paramPtr = *(nint*)(charaPtr + OFF_CHARA_PARAM);
            int hp = 0, hpMax = 0, mp = 0, mpMax = 0;
            if (paramPtr != 0 && *(nint*)paramPtr != 0)
            {
                hp    = *(int*)(paramPtr + OFF_PARAM_HP);
                mp    = *(int*)(paramPtr + OFF_PARAM_MP);
                hpMax = *(int*)(paramPtr + OFF_PARAM_HPMAX);
                mpMax = *(int*)(paramPtr + OFF_PARAM_MPMAX);

                // Sanity: reject obviously bad values
                if (hpMax < 0 || hpMax > 999999 || mpMax < 0 || mpMax > 999999)
                    return null;
            }

            // Read BP from BtlActionPoint
            int bp = 0;
            nint apPtr = *(nint*)(charaPtr + OFF_CHARA_AP);
            if (apPtr != 0 && *(nint*)apPtr != 0)
            {
                bp = *(int*)(apPtr + OFF_AP_VALUE);
                // BP in Bravely Default ranges from -4 to +4 typically
                if (bp < -10 || bp > 10) bp = 0;
            }

            // Read status flags from BtlStatusManager
            uint statusFlags = 0;
            nint statusMgr = *(nint*)(charaPtr + OFF_CHARA_STATUS_MGR);
            if (statusMgr != 0 && *(nint*)statusMgr != 0)
            {
                statusFlags = *(uint*)(statusMgr + OFF_STATUS_FLAG);
            }

            bool isDead = hp <= 0;

            return new CharacterSnapshot(index, team, hp, hpMax, mp, mpMax, bp, statusFlags, isDead);
        }
        catch
        {
            return null;
        }
    }
}
