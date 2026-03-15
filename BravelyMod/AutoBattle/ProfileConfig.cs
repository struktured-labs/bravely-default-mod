using System.Text.RegularExpressions;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using MelonLoader;

namespace BravelyMod.AutoBattle;

/// <summary>
/// YAML config with concise DSL for autobattle rule profiles.
/// Pure C# — no IL2CPP dependencies.
///
/// DSL format per rule line: "conditions → actions"
///   Conditions: empty = Always, joined with &amp;
///   Actions: comma-separated, xN suffix for repeats
///
/// Examples:
///   "→ Atk Weak x4"
///   "HP &lt; 30% → Cure Self"
///   "BP &gt; 2 &amp; HP &gt; 50% → Atk Strong x4"
///   "Foes = 1 → Atk Strong x4"
///   "HP &lt; 50% → Cure Ally, Atk Strong x2"
/// </summary>

// ──────────────────────────────────────────────────────────────
// YAML DTO — simple string-list profiles
// ──────────────────────────────────────────────────────────────

public class AutoBattleConfigDto
{
    [YamlMember(Alias = "activeProfile")]
    public string ActiveProfile { get; set; } = "Attack 4x";

    /// <summary>
    /// Profile name -> list of DSL rule strings.
    /// </summary>
    [YamlMember(Alias = "profiles")]
    public Dictionary<string, List<string>> Profiles { get; set; } = new();

    /// <summary>
    /// Ordered list of profile names, one per character slot (index 0-3).
    /// </summary>
    [YamlMember(Alias = "assignments")]
    public List<string> Assignments { get; set; } = new();
}

// ──────────────────────────────────────────────────────────────
// ProfileConfig — load / save / parse DSL
// ──────────────────────────────────────────────────────────────

public static class ProfileConfig
{
    private static readonly ISerializer YamlSerializer = new SerializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .ConfigureDefaultValuesHandling(DefaultValuesHandling.OmitDefaults)
        .Build();

    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    /// <summary>
    /// Load profiles from a YAML file and configure the given <see cref="RuleEngine"/>.
    /// If the file doesn't exist, writes a default config and uses that.
    /// </summary>
    public static void LoadInto(string path, RuleEngine engine)
    {
        AutoBattleConfigDto dto;
        if (File.Exists(path))
        {
            try
            {
                string yaml = File.ReadAllText(path);
                dto = YamlDeserializer.Deserialize<AutoBattleConfigDto>(yaml);
                if (dto == null)
                {
                    Melon<Core>.Logger.Warning("[AutoBattle] Config deserialized to null, using defaults");
                    dto = GetDefaultConfig();
                    Save(path, dto);
                }
                else
                {
                    Melon<Core>.Logger.Msg($"[AutoBattle] Loaded config from {path}");
                }
            }
            catch (Exception ex)
            {
                Melon<Core>.Logger.Warning($"[AutoBattle] Failed to parse config: {ex.Message}");
                Melon<Core>.Logger.Warning("[AutoBattle] Using default config (original file preserved)");
                dto = GetDefaultConfig();
            }
        }
        else
        {
            Melon<Core>.Logger.Msg("[AutoBattle] No config file found, creating default");
            dto = GetDefaultConfig();
            Save(path, dto);
        }

        ApplyToEngine(dto, engine);
    }

    /// <summary>
    /// Serialize the given config DTO to YAML and write to disk.
    /// </summary>
    public static void Save(string path, AutoBattleConfigDto dto)
    {
        try
        {
            string dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            string yaml = YamlSerializer.Serialize(dto);
            File.WriteAllText(path, yaml);
            Melon<Core>.Logger.Msg($"[AutoBattle] Config saved to {path}");
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[AutoBattle] Failed to save config: {ex.Message}");
        }
    }

    /// <summary>
    /// Build the default config DTO with the DSL format.
    /// </summary>
    public static AutoBattleConfigDto GetDefaultConfig()
    {
        return new AutoBattleConfigDto
        {
            ActiveProfile = "Attack 4x",
            Profiles = new Dictionary<string, List<string>>
            {
                ["Attack 4x"] = new List<string>
                {
                    "\u2192 Atk Weak x4"
                },
                ["Healer"] = new List<string>
                {
                    "HP < 30% \u2192 Cure Self",
                    "\u2192 Atk Weak"
                },
                ["Boss Fight"] = new List<string>
                {
                    "HP < 50% \u2192 Cure Ally, Atk Strong x2",
                    "Foes = 1 \u2192 Atk Strong x4",
                    "\u2192 Atk Weak x3"
                },
                ["Nuke"] = new List<string>
                {
                    "BP > 2 & HP > 50% \u2192 Atk Strong x4",
                    "\u2192 Atk Weak"
                },
                ["Default"] = new List<string>()
            },
            Assignments = new List<string> { "Attack 4x", "Attack 4x", "Healer", "Attack 4x" }
        };
    }

    // ──────────────────────────────────────────────────────────
    // DSL Parser
    // ──────────────────────────────────────────────────────────

    // Arrow variants: Unicode →, ASCII ->, =>
    private static readonly string[] ArrowSeparators = { "\u2192", "->", "=>" };

    /// <summary>
    /// Parse a single DSL rule string into a <see cref="Rule"/>.
    /// Format: "conditions → actions" or just "→ actions" (always-true).
    /// </summary>
    public static Rule ParseRule(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            // Empty line = always attack weakest (single action)
            return new Rule(BattleAction.AttackWeakest(), Condition.Always()) { DslSource = line };
        }

        string condPart = "";
        string actionPart = line.Trim();

        // Find the arrow separator
        foreach (var arrow in ArrowSeparators)
        {
            int idx = line.IndexOf(arrow, StringComparison.Ordinal);
            if (idx >= 0)
            {
                condPart = line.Substring(0, idx).Trim();
                actionPart = line.Substring(idx + arrow.Length).Trim();
                break;
            }
        }

        // Parse conditions
        var conditions = new List<Condition>();
        if (string.IsNullOrWhiteSpace(condPart))
        {
            conditions.Add(Condition.Always());
        }
        else
        {
            // Split on & (with optional whitespace)
            var condTokens = condPart.Split('&');
            foreach (var token in condTokens)
            {
                var trimmed = token.Trim();
                if (!string.IsNullOrEmpty(trimmed))
                    conditions.Add(ParseCondition(trimmed));
            }
            if (conditions.Count == 0)
                conditions.Add(Condition.Always());
        }

        // Parse actions
        var actions = ParseActions(actionPart);
        if (actions.Count == 0)
            actions.Add(BattleAction.AttackWeakest());

        var rule = new Rule { Conditions = conditions, Actions = actions, DslSource = line };
        return rule;
    }

    /// <summary>
    /// Parse a condition string like "HP &lt; 30%", "Foes = 1", "BP &gt; 2".
    /// </summary>
    public static Condition ParseCondition(string text)
    {
        text = text.Trim();

        // Match patterns like: STAT OP VALUE[%]
        // e.g. "HP < 30%", "Foes = 1", "BP > 2", "Turn = 1", "Allies < 3"
        var match = Regex.Match(text, @"^(\w+)\s*(<=|>=|!=|<|>|=)\s*(\d+\.?\d*)(%?)$");
        if (!match.Success)
        {
            Melon<Core>.Logger.Warning($"[AutoBattle] Could not parse condition: '{text}', treating as Always");
            return Condition.Always();
        }

        string stat = match.Groups[1].Value.ToLowerInvariant();
        string opStr = match.Groups[2].Value;
        float value = float.Parse(match.Groups[3].Value);
        bool isPercent = match.Groups[4].Value == "%";

        var op = ParseCompareOp(opStr);

        var condType = stat switch
        {
            "hp" => ConditionType.HpPercent,
            "mp" => ConditionType.MpPercent,
            "bp" => ConditionType.BpValue,
            "foes" or "foe" or "enemies" or "enemy" => ConditionType.EnemyCount,
            "allies" or "ally" => ConditionType.AllyCount,
            "turn" or "turns" => ConditionType.TurnNumber,
            _ => ConditionType.Always,
        };

        if (condType == ConditionType.Always)
        {
            Melon<Core>.Logger.Warning($"[AutoBattle] Unknown condition stat: '{stat}', treating as Always");
        }

        return new Condition(condType, op, value);
    }

    /// <summary>
    /// Parse the action-list portion: "Atk Weak x4" or "Cure Ally, Atk Strong x2".
    /// Returns a flat list of BattleAction (repeats expanded).
    /// </summary>
    public static List<BattleAction> ParseActions(string text)
    {
        var result = new List<BattleAction>();
        if (string.IsNullOrWhiteSpace(text)) return result;

        // Split on comma
        var parts = text.Split(',');
        foreach (var part in parts)
        {
            var trimmed = part.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;

            // Check for xN repeat suffix (e.g. "Atk Weak x4", "Cure Self x2")
            int repeatCount = 1;
            var repeatMatch = Regex.Match(trimmed, @"\s+x(\d+)$", RegexOptions.IgnoreCase);
            if (repeatMatch.Success)
            {
                repeatCount = int.Parse(repeatMatch.Groups[1].Value);
                trimmed = trimmed.Substring(0, repeatMatch.Index).Trim();
            }

            var action = ParseSingleAction(trimmed);
            for (int i = 0; i < repeatCount; i++)
                result.Add(action);
        }

        return result;
    }

    /// <summary>
    /// Parse a single action token like "Atk Weak", "Cure Self", "Abl 5 Foe", "Guard", "Default".
    /// </summary>
    public static BattleAction ParseSingleAction(string text)
    {
        text = text.Trim();
        string lower = text.ToLowerInvariant();

        // Guard
        if (lower == "guard" || lower == "defend")
            return BattleAction.GuardSelf();

        // Default
        if (lower == "default")
            return BattleAction.DefaultAction();

        // Attack variants: "Atk Weak", "Atk Strong", "Atk Random", "Atk Rnd"
        if (lower.StartsWith("atk") || lower.StartsWith("attack"))
        {
            string rest = Regex.Replace(text, @"^(?:atk|attack)\s*", "", RegexOptions.IgnoreCase).Trim().ToLowerInvariant();
            var target = rest switch
            {
                "weak" or "weakest" => TargetSelector.WeakestEnemy,
                "strong" or "strongest" => TargetSelector.StrongestEnemy,
                "random" or "rnd" => TargetSelector.RandomEnemy,
                _ => TargetSelector.WeakestEnemy,
            };
            return new BattleAction(ActionType.Attack, target);
        }

        // Cure variants: "Cure Self", "Cure Ally" (shorthand for Abl 1 Self/Ally)
        if (lower.StartsWith("cure"))
        {
            string rest = Regex.Replace(text, @"^cure\s*", "", RegexOptions.IgnoreCase).Trim().ToLowerInvariant();
            var target = rest switch
            {
                "self" or "me" => TargetSelector.Self,
                "ally" or "allies" or "friend" => TargetSelector.WeakestAlly,
                _ => TargetSelector.Self,
            };
            return new BattleAction(ActionType.Ability, target, abilityId: 1);
        }

        // Ability: "Abl N Target" e.g. "Abl 5 Foe", "Abl 3 Self"
        var ablMatch = Regex.Match(text, @"^(?:abl|ability)\s+(\d+)\s+(\w+)$", RegexOptions.IgnoreCase);
        if (ablMatch.Success)
        {
            int id = int.Parse(ablMatch.Groups[1].Value);
            var target = ParseTargetWord(ablMatch.Groups[2].Value);
            return new BattleAction(ActionType.Ability, target, abilityId: id);
        }

        // Item: "Item N Target" e.g. "Item 1 Self", "Item 2 Ally"
        var itemMatch = Regex.Match(text, @"^item\s+(\d+)\s+(\w+)$", RegexOptions.IgnoreCase);
        if (itemMatch.Success)
        {
            int id = int.Parse(itemMatch.Groups[1].Value);
            var target = ParseTargetWord(itemMatch.Groups[2].Value);
            return new BattleAction(ActionType.Item, target, itemId: id);
        }

        Melon<Core>.Logger.Warning($"[AutoBattle] Could not parse action: '{text}', defaulting to Atk Weak");
        return BattleAction.AttackWeakest();
    }

    private static TargetSelector ParseTargetWord(string word)
    {
        return (word ?? "").Trim().ToLowerInvariant() switch
        {
            "self" or "me" => TargetSelector.Self,
            "ally" or "allies" or "friend" => TargetSelector.WeakestAlly,
            "foe" or "foes" or "enemy" or "enemies" or "weak" => TargetSelector.WeakestEnemy,
            "strong" or "strongest" => TargetSelector.StrongestEnemy,
            "random" or "rnd" => TargetSelector.RandomEnemy,
            _ => TargetSelector.WeakestEnemy,
        };
    }

    private static CompareOp ParseCompareOp(string s) => (s ?? "").Trim() switch
    {
        "<" => CompareOp.Less,
        "<=" => CompareOp.LessOrEqual,
        "=" or "==" => CompareOp.Equal,
        ">=" => CompareOp.GreaterOrEqual,
        ">" => CompareOp.Greater,
        "!=" => CompareOp.NotEqual,
        _ => CompareOp.Equal,
    };

    // ──────────────────────────────────────────────────────────
    // DTO -> domain conversion
    // ──────────────────────────────────────────────────────────

    private static void ApplyToEngine(AutoBattleConfigDto dto, RuleEngine engine)
    {
        // Build named profiles from DSL strings
        var profiles = new Dictionary<string, RuleProfile>();
        foreach (var (name, ruleLines) in dto.Profiles)
        {
            var profile = new RuleProfile(name);
            if (ruleLines != null)
            {
                foreach (var line in ruleLines)
                {
                    try
                    {
                        var rule = ParseRule(line);
                        profile.Rules.Add(rule);
                    }
                    catch (Exception ex)
                    {
                        Melon<Core>.Logger.Warning($"[AutoBattle] Failed to parse rule '{line}' in profile '{name}': {ex.Message}");
                    }
                }
            }
            profiles[name] = profile;
            Melon<Core>.Logger.Msg($"[AutoBattle] Profile '{name}': {profile.Rules.Count} rules");
        }

        // Populate the engine's profile catalog for UI cycling
        engine.AllProfiles.Clear();
        engine.ProfileNames.Clear();
        foreach (var (name, profile) in profiles)
        {
            engine.AllProfiles[name] = profile;
            engine.ProfileNames.Add(name);
        }

        // Set default/active profile
        int activeIdx = 0;
        if (dto.ActiveProfile != null && profiles.TryGetValue(dto.ActiveProfile, out var defaultProfile))
        {
            engine.DefaultProfile = defaultProfile;
            activeIdx = engine.ProfileNames.IndexOf(dto.ActiveProfile);
            if (activeIdx < 0) activeIdx = 0;
        }
        else if (profiles.Count > 0)
        {
            engine.DefaultProfile = profiles.Values.First();
            Melon<Core>.Logger.Warning($"[AutoBattle] Active profile '{dto.ActiveProfile}' not found, using '{engine.DefaultProfile.Name}'");
        }
        engine.ActiveProfileIndex = activeIdx;

        // Assign per-character profiles from ordered list
        for (int i = 0; i < engine.CharacterProfiles.Length; i++)
        {
            engine.CharacterProfiles[i] = null; // reset to default
        }

        if (dto.Assignments != null)
        {
            for (int i = 0; i < dto.Assignments.Count && i < engine.CharacterProfiles.Length; i++)
            {
                string profileName = dto.Assignments[i];
                if (string.IsNullOrWhiteSpace(profileName)) continue;

                if (profiles.TryGetValue(profileName, out var assignedProfile))
                {
                    engine.CharacterProfiles[i] = assignedProfile;
                    Melon<Core>.Logger.Msg($"[AutoBattle] Slot {i} -> profile '{profileName}'");
                }
                else
                {
                    Melon<Core>.Logger.Warning($"[AutoBattle] Slot {i} references unknown profile '{profileName}', using default");
                }
            }
        }
    }
}
