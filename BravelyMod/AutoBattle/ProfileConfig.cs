using System.Text.Json;
using System.Text.Json.Serialization;
using MelonLoader;

namespace BravelyMod.AutoBattle;

/// <summary>
/// JSON-serializable config for autobattle rule profiles.
/// Pure C# — no IL2CPP dependencies.
/// </summary>

// ──────────────────────────────────────────────────────────────
// JSON DTOs — flat structures that map 1:1 to the JSON schema
// ──────────────────────────────────────────────────────────────

public class ConditionDto
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "Always";

    [JsonPropertyName("op")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string Op { get; set; }

    [JsonPropertyName("value")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public float Value { get; set; }
}

public class ActionDto
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "Attack";

    [JsonPropertyName("target")]
    public string Target { get; set; } = "WeakestEnemy";

    [JsonPropertyName("abilityId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int AbilityId { get; set; }

    [JsonPropertyName("itemId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int ItemId { get; set; }
}

public class RuleDto
{
    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string Name { get; set; }

    [JsonPropertyName("conditions")]
    public List<ConditionDto> Conditions { get; set; } = new();

    [JsonPropertyName("action")]
    public ActionDto Action { get; set; } = new();
}

public class ProfileDto
{
    [JsonPropertyName("rules")]
    public List<RuleDto> Rules { get; set; } = new();
}

public class AutoBattleConfigDto
{
    [JsonPropertyName("profiles")]
    public Dictionary<string, ProfileDto> Profiles { get; set; } = new();

    /// <summary>
    /// Maps character slot index (as string key "0"-"3") to a profile name.
    /// </summary>
    [JsonPropertyName("assignments")]
    public Dictionary<string, string> Assignments { get; set; } = new();

    /// <summary>
    /// Default profile name used for any character without an explicit assignment.
    /// </summary>
    [JsonPropertyName("activeProfile")]
    public string ActiveProfile { get; set; } = "Grind Mode";
}

// ──────────────────────────────────────────────────────────────
// ProfileConfig — load / save / convert
// ──────────────────────────────────────────────────────────────

public static class ProfileConfig
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>
    /// Load profiles from a JSON file and configure the given <see cref="RuleEngine"/>.
    /// If the file doesn't exist, writes a default config and uses that.
    /// </summary>
    public static void LoadInto(string path, RuleEngine engine)
    {
        AutoBattleConfigDto dto;
        if (File.Exists(path))
        {
            try
            {
                string json = File.ReadAllText(path);
                dto = JsonSerializer.Deserialize<AutoBattleConfigDto>(json, JsonOpts);
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
    /// Serialize the given config DTO to JSON and write to disk.
    /// </summary>
    public static void Save(string path, AutoBattleConfigDto dto)
    {
        try
        {
            string dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            string json = JsonSerializer.Serialize(dto, JsonOpts);
            File.WriteAllText(path, json);
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
                            Name = "Low HP -> Cure self",
                            Conditions = new List<ConditionDto>
                            {
                                new() { Type = "HpPercent", Op = "<", Value = 30 }
                            },
                            Action = new ActionDto { Type = "Ability", AbilityId = 1, Target = "Self" }
                        },
                        new()
                        {
                            Name = "Single enemy -> Attack strongest",
                            Conditions = new List<ConditionDto>
                            {
                                new() { Type = "EnemyCount", Op = "==", Value = 1 }
                            },
                            Action = new ActionDto { Type = "Attack", Target = "StrongestEnemy" }
                        },
                        new()
                        {
                            Name = "Fallback -> Attack weakest",
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
                            Name = "Low HP -> Cure weakest ally",
                            Conditions = new List<ConditionDto>
                            {
                                new() { Type = "HpPercent", Op = "<", Value = 50 }
                            },
                            Action = new ActionDto { Type = "Ability", AbilityId = 1, Target = "WeakestAlly" }
                        },
                        new()
                        {
                            Name = "Single enemy -> Attack strongest",
                            Conditions = new List<ConditionDto>
                            {
                                new() { Type = "EnemyCount", Op = "==", Value = 1 }
                            },
                            Action = new ActionDto { Type = "Attack", Target = "StrongestEnemy" }
                        },
                        new()
                        {
                            Name = "Fallback -> Attack weakest",
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

        // Set default profile
        if (dto.ActiveProfile != null && profiles.TryGetValue(dto.ActiveProfile, out var defaultProfile))
        {
            engine.DefaultProfile = defaultProfile;
        }
        else if (profiles.Count > 0)
        {
            engine.DefaultProfile = profiles.Values.First();
            Melon<Core>.Logger.Warning($"[AutoBattle] Active profile '{dto.ActiveProfile}' not found, using '{engine.DefaultProfile.Name}'");
        }

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
            var rule = new Rule(ruleDto.Name ?? "", action, conditions.ToArray());
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
        return new BattleAction(actionType, target, dto.AbilityId, dto.ItemId);
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
