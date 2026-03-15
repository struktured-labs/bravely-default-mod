using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using MelonLoader;

namespace BravelyMod.AutoBattle;

/// <summary>
/// YAML-serializable config for autobattle rule profiles.
/// Pure C# — no IL2CPP dependencies.
/// </summary>

// ──────────────────────────────────────────────────────────────
// YAML DTOs — flat structures that map 1:1 to the YAML schema
// ──────────────────────────────────────────────────────────────

public class ConditionDto
{
    [YamlMember(Alias = "type")]
    public string Type { get; set; } = "Always";

    [YamlMember(Alias = "op", DefaultValuesHandling = DefaultValuesHandling.OmitNull)]
    public string Op { get; set; }

    [YamlMember(Alias = "value", DefaultValuesHandling = DefaultValuesHandling.OmitDefaults)]
    public float Value { get; set; }
}

public class ActionDto
{
    [YamlMember(Alias = "type")]
    public string Type { get; set; } = "Attack";

    [YamlMember(Alias = "target")]
    public string Target { get; set; } = "WeakestEnemy";

    [YamlMember(Alias = "id", DefaultValuesHandling = DefaultValuesHandling.OmitDefaults)]
    public int Id { get; set; }

    [YamlMember(Alias = "itemId", DefaultValuesHandling = DefaultValuesHandling.OmitDefaults)]
    public int ItemId { get; set; }
}

public class RuleDto
{
    [YamlMember(Alias = "conditions")]
    public List<ConditionDto> Conditions { get; set; } = new();

    [YamlMember(Alias = "action")]
    public ActionDto Action { get; set; } = new();
}

public class ProfileDto
{
    [YamlMember(Alias = "rules")]
    public List<RuleDto> Rules { get; set; } = new();
}

public class AutoBattleConfigDto
{
    /// <summary>
    /// Default profile name used for any character without an explicit assignment.
    /// </summary>
    [YamlMember(Alias = "activeProfile")]
    public string ActiveProfile { get; set; } = "Grind Mode";

    [YamlMember(Alias = "profiles")]
    public Dictionary<string, ProfileDto> Profiles { get; set; } = new();

    /// <summary>
    /// Maps character slot index (as string key "0"-"3") to a profile name.
    /// </summary>
    [YamlMember(Alias = "assignments")]
    public Dictionary<string, string> Assignments { get; set; } = new();
}

// ──────────────────────────────────────────────────────────────
// ProfileConfig — load / save / convert
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
    /// Build the default config DTO with Grind Mode and Boss Fight profiles.
    /// </summary>
    public static AutoBattleConfigDto GetDefaultConfig()
    {
        var dto = new AutoBattleConfigDto
        {
            ActiveProfile = "Grind Mode",
            Profiles = new Dictionary<string, ProfileDto>
            {
                ["Grind Mode"] = new ProfileDto
                {
                    Rules = new List<RuleDto>
                    {
                        new()
                        {
                            Conditions = new List<ConditionDto>
                            {
                                new() { Type = "HpBelow", Value = 30 }
                            },
                            Action = new ActionDto { Type = "Ability", Id = 1, Target = "Self" }
                        },
                        new()
                        {
                            Conditions = new List<ConditionDto>
                            {
                                new() { Type = "Always" }
                            },
                            Action = new ActionDto { Type = "Attack", Target = "WeakestEnemy" }
                        }
                    }
                },
                ["Boss Fight"] = new ProfileDto
                {
                    Rules = new List<RuleDto>
                    {
                        new()
                        {
                            Conditions = new List<ConditionDto>
                            {
                                new() { Type = "HpBelow", Value = 50 }
                            },
                            Action = new ActionDto { Type = "Ability", Id = 1, Target = "WeakestAlly" }
                        },
                        new()
                        {
                            Conditions = new List<ConditionDto>
                            {
                                new() { Type = "EnemyCount", Op = "==", Value = 1 }
                            },
                            Action = new ActionDto { Type = "Attack", Target = "StrongestEnemy" }
                        },
                        new()
                        {
                            Conditions = new List<ConditionDto>
                            {
                                new() { Type = "Always" }
                            },
                            Action = new ActionDto { Type = "Attack", Target = "WeakestEnemy" }
                        }
                    }
                }
            },
            Assignments = new Dictionary<string, string>
            {
                ["0"] = "Grind Mode",
                ["1"] = "Grind Mode",
                ["2"] = "Boss Fight",
                ["3"] = "Grind Mode",
            }
        };
        return dto;
    }

    // ──────────────────────────────────────────────────────────
    // DTO -> domain conversion
    // ──────────────────────────────────────────────────────────

    private static void ApplyToEngine(AutoBattleConfigDto dto, RuleEngine engine)
    {
        // Build named profiles
        var profiles = new Dictionary<string, RuleProfile>();
        foreach (var (name, profileDto) in dto.Profiles)
        {
            var profile = ConvertProfile(name, profileDto);
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

        // Set default profile
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

        // Assign per-character profiles
        for (int i = 0; i < engine.CharacterProfiles.Length; i++)
        {
            engine.CharacterProfiles[i] = null; // reset to default
        }

        foreach (var (slotStr, profileName) in dto.Assignments)
        {
            if (!int.TryParse(slotStr, out int slot)) continue;
            if (slot < 0 || slot >= engine.CharacterProfiles.Length) continue;

            if (profiles.TryGetValue(profileName, out var assignedProfile))
            {
                engine.CharacterProfiles[slot] = assignedProfile;
                Melon<Core>.Logger.Msg($"[AutoBattle] Slot {slot} -> profile '{profileName}'");
            }
            else
            {
                Melon<Core>.Logger.Warning($"[AutoBattle] Slot {slot} references unknown profile '{profileName}', using default");
            }
        }
    }

    private static RuleProfile ConvertProfile(string name, ProfileDto dto)
    {
        var profile = new RuleProfile(name);
        foreach (var ruleDto in dto.Rules)
        {
            var conditions = new List<Condition>();
            foreach (var condDto in ruleDto.Conditions)
            {
                conditions.Add(ConvertCondition(condDto));
            }

            var action = ConvertAction(ruleDto.Action);
            var rule = new Rule("", action, conditions.ToArray());
            profile.Rules.Add(rule);
        }
        return profile;
    }

    private static Condition ConvertCondition(ConditionDto dto)
    {
        var condType = ParseConditionType(dto.Type);
        var op = ParseCompareOp(dto.Op);
        return new Condition(condType, op, dto.Value);
    }

    private static BattleAction ConvertAction(ActionDto dto)
    {
        var actionType = ParseActionType(dto.Type);
        var target = ParseTargetSelector(dto.Target);
        return new BattleAction(actionType, target, dto.Id, dto.ItemId);
    }

    // ──────────────────────────────────────────────────────────
    // String <-> Enum parsing (case-insensitive)
    // ──────────────────────────────────────────────────────────

    private static ConditionType ParseConditionType(string s) => (s ?? "").ToLowerInvariant() switch
    {
        "always" => ConditionType.Always,
        "hppercent" or "hpbelow" => ConditionType.HpPercent,
        "mppercent" or "mpbelow" => ConditionType.MpPercent,
        "enemycount" => ConditionType.EnemyCount,
        "allycount" => ConditionType.AllyCount,
        "bpvalue" or "bp" => ConditionType.BpValue,
        _ => ConditionType.Always,
    };

    private static CompareOp ParseCompareOp(string s) => (s ?? "").Trim() switch
    {
        "<" or "lt" or "less" => CompareOp.Less,
        "<=" or "le" or "lessorequal" => CompareOp.LessOrEqual,
        "==" or "=" or "eq" or "equal" => CompareOp.Equal,
        ">=" or "ge" or "greaterorequal" => CompareOp.GreaterOrEqual,
        ">" or "gt" or "greater" => CompareOp.Greater,
        "!=" or "ne" or "notequal" => CompareOp.NotEqual,
        _ => CompareOp.Equal,
    };

    private static ActionType ParseActionType(string s) => (s ?? "").ToLowerInvariant() switch
    {
        "attack" => ActionType.Attack,
        "ability" => ActionType.Ability,
        "item" => ActionType.Item,
        "guard" => ActionType.Guard,
        "default" => ActionType.Default,
        _ => ActionType.Attack,
    };

    private static TargetSelector ParseTargetSelector(string s) => (s ?? "").ToLowerInvariant() switch
    {
        "weakestenemy" => TargetSelector.WeakestEnemy,
        "strongestenemy" => TargetSelector.StrongestEnemy,
        "self" => TargetSelector.Self,
        "weakestally" => TargetSelector.WeakestAlly,
        "randomenemy" => TargetSelector.RandomEnemy,
        _ => TargetSelector.WeakestEnemy,
    };
}
