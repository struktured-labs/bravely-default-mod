namespace BravelyMod.AutoBattle;

/// <summary>
/// Pure C# rule evaluation engine for conditional autobattle.
/// No IL2CPP dependencies — operates on <see cref="CharacterSnapshot"/> and <see cref="BattleSnapshot"/>.
/// Rules are evaluated top-to-bottom; first match wins.
/// Each rule can produce multiple actions (multi-brave).
///
/// DSL format: "conditions → actions"
///   e.g. "HP &lt; 30% &amp; Foes = 1 → Cure Self, Atk Strong x2"
/// </summary>

// ──────────────────────────────────────────────────────────────
// Snapshots — plain data read from the battle state reader
// ──────────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────
// Status flag bitmask — mirrors BTLDEF.CharaStatusFlag from IL2CPP
// ──────────────────────────────────────────────────────────────

[System.Flags]
public enum StatusFlag : uint
{
    None       = 0,
    Poison     = 1,
    Blind      = 2,
    Silence    = 4,
    Sleep      = 8,
    Paralysis  = 16,
    Fear       = 32,
    Berserk    = 64,
    Confuse    = 128,
    Charm      = 256,
    Doom       = 512,       // SENKOKU (death sentence)
    Reverse    = 1024,
    Death      = 2048,
    Stop       = 4096,
    Love       = 8192,
    Freeze     = 16384,
    Regen      = 32768,
    Reflect    = 65536,
    Reraise    = 131072,
    Jump       = 262144,

    /// <summary>All ailments that are curable bad statuses (not buffs like Regen/Reflect/Reraise).</summary>
    AllBadStatus = Poison | Blind | Silence | Sleep | Paralysis | Fear
                 | Berserk | Confuse | Charm | Doom | Stop | Freeze,
}

public readonly struct CharacterSnapshot
{
    public readonly int Index;
    public readonly int Team;          // 0 = player, 1 = enemy
    public readonly int Hp;
    public readonly int HpMax;
    public readonly int Mp;
    public readonly int MpMax;
    public readonly int Bp;
    public readonly StatusFlag StatusFlags;
    public readonly bool IsDead;

    public float HpPercent => HpMax > 0 ? Hp * 100f / HpMax : 0f;
    public float MpPercent => MpMax > 0 ? Mp * 100f / MpMax : 0f;

    /// <summary>True if the character has any curable bad status ailment.</summary>
    public bool HasBadStatus => (StatusFlags & StatusFlag.AllBadStatus) != 0;

    /// <summary>True if the character has a specific status flag.</summary>
    public bool HasStatus(StatusFlag flag) => (StatusFlags & flag) != 0;

    /// <summary>True if the character needs healing: HP below max or has a bad status.</summary>
    public bool NeedsHealing => !IsDead && (Hp < HpMax || HasBadStatus);

    /// <summary>
    /// Healing priority score — higher means more urgent.
    /// Factors in HP deficit and status ailments.
    /// </summary>
    public float HealPriority
    {
        get
        {
            if (IsDead) return 0f;
            float hpDeficit = HpMax > 0 ? (1f - (float)Hp / HpMax) * 100f : 0f;
            // Each bad status adds 25 points of urgency
            int statusCount = 0;
            uint flags = (uint)(StatusFlags & StatusFlag.AllBadStatus);
            while (flags != 0) { statusCount += (int)(flags & 1); flags >>= 1; }
            return hpDeficit + statusCount * 25f;
        }
    }

    public CharacterSnapshot(int index, int team, int hp, int hpMax, int mp, int mpMax, int bp, uint statusFlags, bool isDead)
    {
        Index = index;
        Team = team;
        Hp = hp;
        HpMax = hpMax;
        Mp = mp;
        MpMax = mpMax;
        Bp = bp;
        StatusFlags = (StatusFlag)statusFlags;
        IsDead = isDead;
    }
}

public readonly struct BattleSnapshot
{
    public readonly CharacterSnapshot[] Players;
    public readonly CharacterSnapshot[] Enemies;
    public readonly int TurnNumber;

    public int AliveEnemyCount
    {
        get
        {
            int count = 0;
            foreach (var e in Enemies)
                if (!e.IsDead) count++;
            return count;
        }
    }

    public int AlivePlayerCount
    {
        get
        {
            int count = 0;
            foreach (var p in Players)
                if (!p.IsDead) count++;
            return count;
        }
    }

    /// <summary>Count of alive players who have at least one bad status ailment.</summary>
    public int StatusAilmentPlayerCount
    {
        get
        {
            int count = 0;
            foreach (var p in Players)
                if (!p.IsDead && p.HasBadStatus) count++;
            return count;
        }
    }

    /// <summary>True if any alive player needs healing (HP deficit or bad status).</summary>
    public bool AnyPlayerNeedsHealing
    {
        get
        {
            foreach (var p in Players)
                if (p.NeedsHealing) return true;
            return false;
        }
    }

    /// <summary>
    /// Find the ally who most urgently needs healing (highest HealPriority).
    /// Returns the index into the Players array, or -1 if nobody needs healing.
    /// </summary>
    public int MostUrgentHealTargetIndex
    {
        get
        {
            int bestIdx = -1;
            float bestPriority = 0f;
            for (int i = 0; i < Players.Length; i++)
            {
                if (Players[i].IsDead) continue;
                float p = Players[i].HealPriority;
                if (p > bestPriority)
                {
                    bestPriority = p;
                    bestIdx = Players[i].Index;
                }
            }
            return bestIdx;
        }
    }

    public BattleSnapshot(CharacterSnapshot[] players, CharacterSnapshot[] enemies, int turnNumber = 1)
    {
        Players = players;
        Enemies = enemies;
        TurnNumber = turnNumber;
    }
}

// ──────────────────────────────────────────────────────────────
// Conditions
// ──────────────────────────────────────────────────────────────

public enum CompareOp { Less, LessOrEqual, Equal, GreaterOrEqual, Greater, NotEqual }

public enum ConditionType
{
    Always, HpPercent, MpPercent, EnemyCount, AllyCount, BpValue, TurnNumber,
    /// <summary>True if self has any bad status ailment.</summary>
    HasStatus,
    /// <summary>True if any alive ally has a bad status ailment. Value = threshold count (compare op applied).</summary>
    AllyStatusCount,
    /// <summary>True if any alive ally needs healing (HP deficit or bad status). Always-true style, no value.</summary>
    AnyAllyNeedsHeal,
}

public class Condition
{
    public ConditionType Type { get; set; }
    public CompareOp Op { get; set; }
    public float Value { get; set; }

    public Condition() { }

    public Condition(ConditionType type, CompareOp op, float value)
    {
        Type = type;
        Op = op;
        Value = value;
    }

    public static Condition Always() => new(ConditionType.Always, CompareOp.Equal, 0);
    public static Condition HpBelow(float pct) => new(ConditionType.HpPercent, CompareOp.Less, pct);
    public static Condition MpBelow(float pct) => new(ConditionType.MpPercent, CompareOp.Less, pct);
    public static Condition EnemyCountEquals(int n) => new(ConditionType.EnemyCount, CompareOp.Equal, n);
    public static Condition HasStatus() => new(ConditionType.HasStatus, CompareOp.Greater, 0);
    public static Condition AllyStatusCount(int n) => new(ConditionType.AllyStatusCount, CompareOp.GreaterOrEqual, n);
    public static Condition AnyAllyNeedsHeal() => new(ConditionType.AnyAllyNeedsHeal, CompareOp.Equal, 0);

    public bool Evaluate(CharacterSnapshot self, BattleSnapshot battle)
    {
        return Type switch
        {
            ConditionType.Always => true,
            ConditionType.HpPercent => Compare(self.HpPercent, Op, Value),
            ConditionType.MpPercent => Compare(self.MpPercent, Op, Value),
            ConditionType.EnemyCount => Compare(battle.AliveEnemyCount, Op, Value),
            ConditionType.AllyCount => Compare(battle.AlivePlayerCount, Op, Value),
            ConditionType.BpValue => Compare(self.Bp, Op, Value),
            ConditionType.TurnNumber => Compare(battle.TurnNumber, Op, Value),
            ConditionType.HasStatus => self.HasBadStatus,
            ConditionType.AllyStatusCount => Compare(battle.StatusAilmentPlayerCount, Op, Value),
            ConditionType.AnyAllyNeedsHeal => battle.AnyPlayerNeedsHealing,
            _ => false,
        };
    }

    private static bool Compare(float lhs, CompareOp op, float rhs) => op switch
    {
        CompareOp.Less => lhs < rhs,
        CompareOp.LessOrEqual => lhs <= rhs,
        CompareOp.Equal => System.Math.Abs(lhs - rhs) < 0.01f,
        CompareOp.GreaterOrEqual => lhs >= rhs,
        CompareOp.Greater => lhs > rhs,
        CompareOp.NotEqual => System.Math.Abs(lhs - rhs) >= 0.01f,
        _ => false,
    };

    /// <summary>
    /// Compact string for command plate preview, e.g. "HP&lt;30%" or "Foes=1" or "" (Always).
    /// </summary>
    public string ToShortString()
    {
        string opStr = Op switch
        {
            CompareOp.Less => "<",
            CompareOp.LessOrEqual => "<=",
            CompareOp.Equal => "=",
            CompareOp.GreaterOrEqual => ">=",
            CompareOp.Greater => ">",
            CompareOp.NotEqual => "!=",
            _ => "?"
        };

        return Type switch
        {
            ConditionType.Always => "",
            ConditionType.HpPercent => $"HP{opStr}{Value:0}%",
            ConditionType.MpPercent => $"MP{opStr}{Value:0}%",
            ConditionType.EnemyCount => $"Foes{opStr}{Value:0}",
            ConditionType.AllyCount => $"Allies{opStr}{Value:0}",
            ConditionType.BpValue => $"BP{opStr}{Value:0}",
            ConditionType.TurnNumber => $"Turn{opStr}{Value:0}",
            ConditionType.HasStatus => "Status",
            ConditionType.AllyStatusCount => $"AllyStatus{opStr}{Value:0}",
            ConditionType.AnyAllyNeedsHeal => "NeedHeal",
            _ => "?"
        };
    }
}

// ──────────────────────────────────────────────────────────────
// Actions
// ──────────────────────────────────────────────────────────────

public enum ActionType { Attack, Ability, Item, Guard, Default }

public enum TargetSelector
{
    WeakestEnemy, StrongestEnemy, Self, WeakestAlly, RandomEnemy,
    /// <summary>Targets the ally most in need of healing (highest HealPriority score).</summary>
    MostHurtAlly,
}

public class BattleAction
{
    public ActionType Type { get; set; }
    public TargetSelector Target { get; set; }
    public int AbilityId { get; set; }   // for Ability/Item actions
    public int ItemId { get; set; }

    public BattleAction() { }

    public BattleAction(ActionType type, TargetSelector target, int abilityId = 0, int itemId = 0)
    {
        Type = type;
        Target = target;
        AbilityId = abilityId;
        ItemId = itemId;
    }

    public static BattleAction AttackWeakest() => new(ActionType.Attack, TargetSelector.WeakestEnemy);
    public static BattleAction AttackStrongest() => new(ActionType.Attack, TargetSelector.StrongestEnemy);
    public static BattleAction AttackRandom() => new(ActionType.Attack, TargetSelector.RandomEnemy);
    public static BattleAction AbilityOnSelf(int abilityId) => new(ActionType.Ability, TargetSelector.Self, abilityId);
    public static BattleAction AbilityOnAlly(int abilityId) => new(ActionType.Ability, TargetSelector.WeakestAlly, abilityId);
    public static BattleAction AbilityOnFoe(int abilityId) => new(ActionType.Ability, TargetSelector.WeakestEnemy, abilityId);
    public static BattleAction ItemOnSelf(int itemId) => new(ActionType.Item, TargetSelector.Self, itemId: itemId);
    public static BattleAction ItemOnAlly(int itemId) => new(ActionType.Item, TargetSelector.WeakestAlly, itemId: itemId);
    public static BattleAction GuardSelf() => new(ActionType.Guard, TargetSelector.Self);
    public static BattleAction DefaultAction() => new(ActionType.Default, TargetSelector.WeakestEnemy);
    /// <summary>Heal the most hurt/statused ally with a given ability (e.g., Cure=1, Esuna, etc.).</summary>
    public static BattleAction HealMostHurt(int abilityId) => new(ActionType.Ability, TargetSelector.MostHurtAlly, abilityId);
    /// <summary>Use an item on the most hurt/statused ally.</summary>
    public static BattleAction ItemOnMostHurt(int itemId) => new(ActionType.Item, TargetSelector.MostHurtAlly, itemId: itemId);

    /// <summary>
    /// Compact action label for command plate preview, e.g. "Atk Weak", "Cure", "Guard".
    /// </summary>
    public string ToShortString()
    {
        string targetStr = Target switch
        {
            TargetSelector.WeakestEnemy => " Weak",
            TargetSelector.StrongestEnemy => " Strong",
            TargetSelector.Self => " Self",
            TargetSelector.WeakestAlly => " Ally",
            TargetSelector.RandomEnemy => " Rnd",
            TargetSelector.MostHurtAlly => " Hurt",
            _ => ""
        };

        return Type switch
        {
            ActionType.Attack => $"Atk{targetStr}",
            ActionType.Ability => AbilityId > 0 ? $"Abl#{AbilityId}{targetStr}" : $"Ability{targetStr}",
            ActionType.Item => ItemId > 0 ? $"Itm#{ItemId}{targetStr}" : $"Item{targetStr}",
            ActionType.Guard => "Guard",
            ActionType.Default => "Default",
            _ => "?"
        };
    }
}

// ──────────────────────────────────────────────────────────────
// Rules and Profiles
// ──────────────────────────────────────────────────────────────

/// <summary>
/// A single rule: all conditions must be true (AND) for the actions to fire.
/// A rule can have multiple actions (multi-brave / multi-action per turn).
/// </summary>
public class Rule
{
    public List<Condition> Conditions { get; set; } = new();
    public List<BattleAction> Actions { get; set; } = new();

    /// <summary>
    /// The original DSL string this rule was parsed from (for display / re-serialization).
    /// </summary>
    public string DslSource { get; set; }

    public Rule() { }

    public Rule(List<BattleAction> actions, params Condition[] conditions)
    {
        Actions = actions;
        Conditions = new List<Condition>(conditions);
    }

    /// <summary>Convenience: single-action rule.</summary>
    public Rule(BattleAction action, params Condition[] conditions)
        : this(new List<BattleAction> { action }, conditions) { }

    public bool Evaluate(CharacterSnapshot self, BattleSnapshot battle)
    {
        foreach (var cond in Conditions)
            if (!cond.Evaluate(self, battle))
                return false;
        return true;
    }

    /// <summary>
    /// Compact rule summary for command plate preview.
    /// Format: "condition &amp; condition → action, action x2"
    /// Examples: "HP&lt;30% → Cure Self", "Foes=1 → Atk Strong x4", "→ Atk Weak x3"
    /// </summary>
    public string ToShortString()
    {
        var condParts = new List<string>();
        foreach (var cond in Conditions)
        {
            var s = cond.ToShortString();
            if (!string.IsNullOrEmpty(s))
                condParts.Add(s);
        }

        string condStr = condParts.Count > 0 ? string.Join(" & ", condParts) : "";

        // Group consecutive identical actions with xN
        var actionParts = new List<string>();
        if (Actions.Count > 0)
        {
            string current = Actions[0].ToShortString();
            int count = 1;
            for (int i = 1; i < Actions.Count; i++)
            {
                string next = Actions[i].ToShortString();
                if (next == current)
                {
                    count++;
                }
                else
                {
                    actionParts.Add(count > 1 ? $"{current} x{count}" : current);
                    current = next;
                    count = 1;
                }
            }
            actionParts.Add(count > 1 ? $"{current} x{count}" : current);
        }
        else
        {
            actionParts.Add("?");
        }

        string actionStr = string.Join(", ", actionParts);
        return $"{condStr}\u2192{actionStr}";
    }
}

/// <summary>
/// A named profile containing an ordered list of rules.
/// First matching rule wins (top-to-bottom, OR between rules).
/// </summary>
public class RuleProfile
{
    public string Name { get; set; }
    public List<Rule> Rules { get; set; } = new();

    public RuleProfile() { }
    public RuleProfile(string name) { Name = name; }

    /// <summary>
    /// Evaluate rules for a character. Returns the action list of the first matching rule, or null.
    /// </summary>
    public List<BattleAction> Evaluate(CharacterSnapshot self, BattleSnapshot battle)
    {
        foreach (var rule in Rules)
            if (rule.Evaluate(self, battle))
                return rule.Actions;
        return null;
    }
}

/// <summary>
/// Resolved action with concrete target index, ready for command submission.
/// </summary>
public readonly struct ResolvedAction
{
    public readonly ActionType Type;
    public readonly int TargetIndex;
    public readonly bool IsTargetEnemy;
    public readonly int AbilityId;
    public readonly int ItemId;

    public ResolvedAction(ActionType type, int targetIndex, bool isTargetEnemy, int abilityId = 0, int itemId = 0)
    {
        Type = type;
        TargetIndex = targetIndex;
        IsTargetEnemy = isTargetEnemy;
        AbilityId = abilityId;
        ItemId = itemId;
    }
}

/// <summary>
/// Top-level engine: holds profiles and resolves targets.
/// </summary>
public class RuleEngine
{
    /// <summary>
    /// Per-character-index profile. Null means "use DefaultProfile".
    /// </summary>
    public RuleProfile[] CharacterProfiles { get; set; } = new RuleProfile[4];

    /// <summary>
    /// Fallback profile used when a character has no assigned profile.
    /// </summary>
    public RuleProfile DefaultProfile { get; set; }

    /// <summary>
    /// All loaded profiles by name (populated by ProfileConfig.LoadInto).
    /// </summary>
    public Dictionary<string, RuleProfile> AllProfiles { get; } = new();

    /// <summary>
    /// Ordered list of profile names for cycling in the UI.
    /// </summary>
    public List<string> ProfileNames { get; } = new();

    /// <summary>
    /// Index of the currently active profile within <see cref="ProfileNames"/>.
    /// </summary>
    public int ActiveProfileIndex { get; set; }

    /// <summary>
    /// Cycle to the next profile and return its name.
    /// Also updates DefaultProfile to the newly selected profile.
    /// </summary>
    public string CycleProfile()
    {
        if (ProfileNames.Count == 0) return "(none)";
        ActiveProfileIndex = (ActiveProfileIndex + 1) % ProfileNames.Count;
        var name = ProfileNames[ActiveProfileIndex];
        if (AllProfiles.TryGetValue(name, out var profile))
            DefaultProfile = profile;
        return name;
    }

    /// <summary>
    /// Get the name of the current active profile.
    /// </summary>
    public string ActiveProfileName =>
        ProfileNames.Count > 0 && ActiveProfileIndex < ProfileNames.Count
            ? ProfileNames[ActiveProfileIndex]
            : "(none)";

    /// <summary>
    /// Per-character profile index tracking for cycling in the UI.
    /// Mirrors <see cref="CharacterProfiles"/> but tracks which index in <see cref="ProfileNames"/>
    /// each character slot is currently set to.
    /// </summary>
    private readonly int[] _characterProfileIndices = new int[4];

    /// <summary>
    /// Initialize per-character profile indices from the current CharacterProfiles assignments.
    /// Call after LoadInto populates CharacterProfiles.
    /// </summary>
    public void SyncCharacterProfileIndices()
    {
        for (int i = 0; i < _characterProfileIndices.Length; i++)
        {
            var profile = CharacterProfiles[i];
            if (profile != null && ProfileNames.Contains(profile.Name))
            {
                _characterProfileIndices[i] = ProfileNames.IndexOf(profile.Name);
            }
            else
            {
                // Default to the active profile index
                _characterProfileIndices[i] = ActiveProfileIndex;
            }
        }
    }

    /// <summary>
    /// Cycle the profile for a specific character slot (0-3).
    /// Returns the new profile name for that character.
    /// </summary>
    public string CycleProfileForCharacter(int charIndex)
    {
        if (ProfileNames.Count == 0) return "(none)";
        if (charIndex < 0 || charIndex >= _characterProfileIndices.Length) return "(none)";

        _characterProfileIndices[charIndex] = (_characterProfileIndices[charIndex] + 1) % ProfileNames.Count;
        var name = ProfileNames[_characterProfileIndices[charIndex]];
        if (AllProfiles.TryGetValue(name, out var profile))
            CharacterProfiles[charIndex] = profile;
        return name;
    }

    /// <summary>
    /// Get the profile name currently assigned to a character slot.
    /// </summary>
    public string GetProfileNameForCharacter(int charIndex)
    {
        if (charIndex < 0 || charIndex >= CharacterProfiles.Length) return "(default)";
        var profile = CharacterProfiles[charIndex];
        return profile?.Name ?? DefaultProfile?.Name ?? "(none)";
    }

    /// <summary>
    /// Get the current assignments as an ordered list of profile names (for YAML serialization).
    /// </summary>
    public List<string> GetAssignmentsList()
    {
        var result = new List<string>();
        for (int i = 0; i < CharacterProfiles.Length; i++)
        {
            var profile = CharacterProfiles[i];
            result.Add(profile?.Name ?? DefaultProfile?.Name ?? "Default");
        }
        return result;
    }

    public RuleEngine()
    {
        DefaultProfile = CreateDefaultProfile();
    }

    /// <summary>
    /// Get the effective profile for a character index (per-character override or default).
    /// Returns null only if no profiles are configured at all.
    /// </summary>
    public RuleProfile GetProfileForCharacter(int charIndex)
    {
        if (charIndex >= 0 && charIndex < CharacterProfiles.Length)
        {
            var assigned = CharacterProfiles[charIndex];
            if (assigned != null) return assigned;
        }
        return DefaultProfile;
    }

    /// <summary>
    /// Evaluate rules for a given player character and resolve all actions to concrete targets.
    /// Returns null if no rule matched (caller should fall back to original behavior).
    /// </summary>
    public List<ResolvedAction> EvaluateForCharacter(int charaIndex, BattleSnapshot battle)
    {
        if (charaIndex < 0 || charaIndex >= battle.Players.Length)
            return null;

        var self = battle.Players[charaIndex];
        if (self.IsDead) return null;

        var profile = (charaIndex < CharacterProfiles.Length ? CharacterProfiles[charaIndex] : null)
                      ?? DefaultProfile;
        if (profile == null) return null;

        var actions = profile.Evaluate(self, battle);
        if (actions == null || actions.Count == 0) return null;

        var resolved = new List<ResolvedAction>();
        foreach (var action in actions)
        {
            var r = ResolveTarget(action, self, battle);
            if (r != null)
                resolved.Add(r.Value);
        }

        return resolved.Count > 0 ? resolved : null;
    }

    private static ResolvedAction? ResolveTarget(BattleAction action, CharacterSnapshot self, BattleSnapshot battle)
    {
        switch (action.Target)
        {
            case TargetSelector.Self:
                return new ResolvedAction(action.Type, self.Index, false, action.AbilityId, action.ItemId);

            case TargetSelector.WeakestEnemy:
            {
                int idx = FindEnemy(battle, weakest: true);
                return idx >= 0 ? new ResolvedAction(action.Type, idx, true, action.AbilityId, action.ItemId) : null;
            }

            case TargetSelector.StrongestEnemy:
            {
                int idx = FindEnemy(battle, weakest: false);
                return idx >= 0 ? new ResolvedAction(action.Type, idx, true, action.AbilityId, action.ItemId) : null;
            }

            case TargetSelector.WeakestAlly:
            {
                int idx = FindAlly(battle, weakest: true, excludeIndex: self.Index);
                if (idx < 0) idx = self.Index; // fallback to self
                return new ResolvedAction(action.Type, idx, false, action.AbilityId, action.ItemId);
            }

            case TargetSelector.RandomEnemy:
            {
                int idx = FindEnemy(battle, weakest: true); // just pick weakest as deterministic fallback
                return idx >= 0 ? new ResolvedAction(action.Type, idx, true, action.AbilityId, action.ItemId) : null;
            }

            case TargetSelector.MostHurtAlly:
            {
                int idx = battle.MostUrgentHealTargetIndex;
                if (idx < 0) idx = self.Index; // nobody needs healing, fallback to self
                return new ResolvedAction(action.Type, idx, false, action.AbilityId, action.ItemId);
            }

            default:
                return null;
        }
    }

    private static int FindEnemy(BattleSnapshot battle, bool weakest)
    {
        int bestIdx = -1;
        int bestHp = weakest ? int.MaxValue : int.MinValue;
        foreach (var e in battle.Enemies)
        {
            if (e.IsDead) continue;
            if ((weakest && e.Hp < bestHp) || (!weakest && e.Hp > bestHp))
            {
                bestHp = e.Hp;
                bestIdx = e.Index;
            }
        }
        return bestIdx;
    }

    private static int FindAlly(BattleSnapshot battle, bool weakest, int excludeIndex)
    {
        int bestIdx = -1;
        int bestHp = weakest ? int.MaxValue : int.MinValue;
        foreach (var p in battle.Players)
        {
            if (p.IsDead || p.Index == excludeIndex) continue;
            if ((weakest && p.Hp < bestHp) || (!weakest && p.Hp > bestHp))
            {
                bestHp = p.Hp;
                bestIdx = p.Index;
            }
        }
        return bestIdx;
    }

    // ── Default profile (hardcoded fallback) ────────────────────

    public static RuleProfile CreateDefaultProfile()
    {
        var profile = new RuleProfile("Default");
        profile.Rules.Add(new Rule(
            BattleAction.AttackWeakest(),
            Condition.Always()));
        return profile;
    }
}
