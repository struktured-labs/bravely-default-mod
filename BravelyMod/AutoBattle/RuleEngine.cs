namespace BravelyMod.AutoBattle;

/// <summary>
/// Pure C# rule evaluation engine for conditional autobattle.
/// No IL2CPP dependencies — operates on <see cref="CharacterSnapshot"/> and <see cref="BattleSnapshot"/>.
/// Rules are evaluated top-to-bottom; first match wins.
/// </summary>

// ──────────────────────────────────────────────────────────────
// Snapshots — plain data read from the battle state reader
// ──────────────────────────────────────────────────────────────

public readonly struct CharacterSnapshot
{
    public readonly int Index;
    public readonly int Team;          // 0 = player, 1 = enemy
    public readonly int Hp;
    public readonly int HpMax;
    public readonly int Mp;
    public readonly int MpMax;
    public readonly int Bp;
    public readonly bool IsDead;

    public float HpPercent => HpMax > 0 ? Hp * 100f / HpMax : 0f;
    public float MpPercent => MpMax > 0 ? Mp * 100f / MpMax : 0f;

    public CharacterSnapshot(int index, int team, int hp, int hpMax, int mp, int mpMax, int bp, bool isDead)
    {
        Index = index;
        Team = team;
        Hp = hp;
        HpMax = hpMax;
        Mp = mp;
        MpMax = mpMax;
        Bp = bp;
        IsDead = isDead;
    }
}

public readonly struct BattleSnapshot
{
    public readonly CharacterSnapshot[] Players;
    public readonly CharacterSnapshot[] Enemies;

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

    public BattleSnapshot(CharacterSnapshot[] players, CharacterSnapshot[] enemies)
    {
        Players = players;
        Enemies = enemies;
    }
}

// ──────────────────────────────────────────────────────────────
// Conditions
// ──────────────────────────────────────────────────────────────

public enum CompareOp { Less, LessOrEqual, Equal, GreaterOrEqual, Greater, NotEqual }

public enum ConditionType { Always, HpPercent, MpPercent, EnemyCount, AllyCount, BpValue }

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
}

// ──────────────────────────────────────────────────────────────
// Actions
// ──────────────────────────────────────────────────────────────

public enum ActionType { Attack, Ability, Item, Guard, Default }

public enum TargetSelector { WeakestEnemy, StrongestEnemy, Self, WeakestAlly, RandomEnemy }

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
    public static BattleAction AbilityOnSelf(int abilityId) => new(ActionType.Ability, TargetSelector.Self, abilityId);
    public static BattleAction GuardSelf() => new(ActionType.Guard, TargetSelector.Self);
}

// ──────────────────────────────────────────────────────────────
// Rules and Profiles
// ──────────────────────────────────────────────────────────────

/// <summary>
/// A single rule: all conditions must be true (AND) for the action to fire.
/// </summary>
public class Rule
{
    public string Name { get; set; }
    public List<Condition> Conditions { get; set; } = new();
    public BattleAction Action { get; set; }

    public Rule() { }

    public Rule(string name, BattleAction action, params Condition[] conditions)
    {
        Name = name;
        Action = action;
        Conditions = new List<Condition>(conditions);
    }

    public bool Evaluate(CharacterSnapshot self, BattleSnapshot battle)
    {
        foreach (var cond in Conditions)
            if (!cond.Evaluate(self, battle))
                return false;
        return true;
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
    /// Evaluate rules for a character. Returns the action of the first matching rule, or null.
    /// </summary>
    public BattleAction Evaluate(CharacterSnapshot self, BattleSnapshot battle)
    {
        foreach (var rule in Rules)
            if (rule.Evaluate(self, battle))
                return rule.Action;
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

    public RuleEngine()
    {
        DefaultProfile = CreateDefaultProfile();
    }

    /// <summary>
    /// Evaluate rules for a given player character and resolve the action to a concrete target.
    /// Returns null if no rule matched (caller should fall back to original behavior).
    /// </summary>
    public ResolvedAction? EvaluateForCharacter(int charaIndex, BattleSnapshot battle)
    {
        if (charaIndex < 0 || charaIndex >= battle.Players.Length)
            return null;

        var self = battle.Players[charaIndex];
        if (self.IsDead) return null;

        var profile = (charaIndex < CharacterProfiles.Length ? CharacterProfiles[charaIndex] : null)
                      ?? DefaultProfile;
        if (profile == null) return null;

        var action = profile.Evaluate(self, battle);
        if (action == null) return null;

        return ResolveTarget(action, self, battle);
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

    // ── MVP hardcoded profile ───────────────────────────────
    // 1. HP < 30% -> Cure on self (ability ID 0x01 = White Magic: Cure)
    // 2. enemy count == 1 -> attack strongest
    // 3. always -> attack weakest

    public static RuleProfile CreateDefaultProfile()
    {
        var profile = new RuleProfile("Default");
        profile.Rules.Add(new Rule(
            "Low HP -> Cure self",
            BattleAction.AbilityOnSelf(0x01),
            Condition.HpBelow(30)));
        profile.Rules.Add(new Rule(
            "Single enemy -> Attack strongest",
            BattleAction.AttackStrongest(),
            Condition.EnemyCountEquals(1)));
        profile.Rules.Add(new Rule(
            "Fallback -> Attack weakest",
            BattleAction.AttackWeakest(),
            Condition.Always()));
        return profile;
    }
}
