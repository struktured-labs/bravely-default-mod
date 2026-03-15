using MelonLoader;
using HarmonyLib;

[assembly: MelonInfo(typeof(BravelyMod.Core), "BravelyMod", "0.2.0", "struktured")]
[assembly: MelonGame("SquareEnix", "BDFFHD")]

namespace BravelyMod;

public class Core : MelonMod
{
    public static MelonPreferences_Category Config { get; private set; }

    // === Feature toggles (all persisted to MelonPreferences.cfg) ===

    // EXP/JP/Gold
    public static MelonPreferences_Entry<bool> ExpBoostEnabled { get; private set; }
    public static MelonPreferences_Entry<float> ExpMultiplier { get; private set; }
    public static MelonPreferences_Entry<float> JexpMultiplier { get; private set; }
    public static MelonPreferences_Entry<float> GoldMultiplier { get; private set; }

    // Damage
    public static MelonPreferences_Entry<bool> DamageCapEnabled { get; private set; }
    public static MelonPreferences_Entry<int> DamageCapOverride { get; private set; }

    // BP
    public static MelonPreferences_Entry<bool> BpModEnabled { get; private set; }
    public static MelonPreferences_Entry<int> BpLimitOverride { get; private set; }
    public static MelonPreferences_Entry<int> BpPerTurn { get; private set; }

    // Battle speed
    public static MelonPreferences_Entry<bool> SpeedModEnabled { get; private set; }
    public static MelonPreferences_Entry<float> BattleSpeedMultiplier { get; private set; }

    // Colony
    public static MelonPreferences_Entry<bool> ColonyModEnabled { get; private set; }
    public static MelonPreferences_Entry<float> ColonySpeedMultiplier { get; private set; }

    // Scene skip
    public static MelonPreferences_Entry<bool> ForceSceneSkip { get; private set; }

    // Support ability cost
    public static MelonPreferences_Entry<bool> SupportCostModEnabled { get; private set; }
    public static MelonPreferences_Entry<int> SupportCostOverride { get; private set; }

    // Walk speed
    public static MelonPreferences_Entry<bool> WalkSpeedModEnabled { get; private set; }
    public static MelonPreferences_Entry<float> WalkSpeedMultiplier { get; private set; }

    private static bool _initialized = false;
    private static HarmonyLib.Harmony _harmony;

    public override void OnInitializeMelon() => InitializeIfNeeded();
    public override void OnEarlyInitializeMelon() => InitializeIfNeeded();

    private void InitializeIfNeeded()
    {
        if (_initialized) return;
        _initialized = true;

        Config = MelonPreferences.CreateCategory("BravelyMod", "Bravely Mod Settings");

        // Each feature: enable toggle + value(s)
        ExpBoostEnabled = Config.CreateEntry("ExpBoostEnabled", true, "Enable EXP/JP/Gold multiplier");
        ExpMultiplier = Config.CreateEntry("ExpMultiplier", 10.0f, "EXP Multiplier");
        JexpMultiplier = Config.CreateEntry("JexpMultiplier", 1000.0f, "JP Multiplier");
        GoldMultiplier = Config.CreateEntry("GoldMultiplier", 10.0f, "Gold Multiplier");

        DamageCapEnabled = Config.CreateEntry("DamageCapEnabled", true, "Enable damage cap removal");
        DamageCapOverride = Config.CreateEntry("DamageCapOverride", 999999, "Damage Cap Override");

        BpModEnabled = Config.CreateEntry("BpModEnabled", true, "Enable BP modifications");
        BpLimitOverride = Config.CreateEntry("BpLimitOverride", 9, "BP Limit Override");
        BpPerTurn = Config.CreateEntry("BpPerTurn", 2, "BP gained per turn (vanilla=1)");

        SpeedModEnabled = Config.CreateEntry("SpeedModEnabled", true, "Enable battle speed mod");
        BattleSpeedMultiplier = Config.CreateEntry("BattleSpeedMultiplier", 2.0f, "Battle Speed Multiplier (applied on top of in-game speed)");

        ColonyModEnabled = Config.CreateEntry("ColonyModEnabled", true, "Enable colony speed mod");
        ColonySpeedMultiplier = Config.CreateEntry("ColonySpeedMultiplier", 10.0f, "Colony Speed Multiplier");

        ForceSceneSkip = Config.CreateEntry("ForceSceneSkip", true, "Force scene skip always available");

        SupportCostModEnabled = Config.CreateEntry("SupportCostModEnabled", true, "Enable support ability cost override");
        SupportCostOverride = Config.CreateEntry("SupportCostOverride", 1, "Support ability equip cost (vanilla=1-4)");

        WalkSpeedModEnabled = Config.CreateEntry("WalkSpeedModEnabled", true, "Enable speed walk (skip trotter)");
        WalkSpeedMultiplier = Config.CreateEntry("WalkSpeedMultiplier", 2.5f, "Walk/dash speed multiplier (applied on top of dash)");

        // Native hooks (these actually work on Unity 6 IL2CPP)
        LoggerInstance.Msg("Applying native hooks...");
        if (ExpBoostEnabled.Value)
        {
            Patches.NativeExpPatch.Apply();
            Patches.NativeResultDisplayPatch.Apply();
        }
        if (SupportCostModEnabled.Value)
            Patches.NativeSupportCostPatch.Apply();
        if (BpModEnabled.Value)
            Patches.NativeBPPatch.Apply();
        Patches.NativeBuffPatch.Apply();
        if (WalkSpeedModEnabled.Value)
            Patches.NativeSpeedWalkPatch.Apply();
        Patches.NativeAutoBattlePatch.Apply();
        // Button swap disabled — use Steam Input controller config instead
        // Patches.NativeButtonSwapPatch.Apply();
        if (SpeedModEnabled.Value)
            Patches.NativeBattleSpeedPatch.Apply();

        // Harmony patches (registered but may not intercept on Unity 6 — keeping for future compat)
        _harmony = new HarmonyLib.Harmony("com.struktured.bravelymod");
        var patchTypes = new System.Type[]
        {
            typeof(Patches.BPPatch),
            typeof(Patches.SpeedPatch),
            typeof(Patches.SkipPatch),
            typeof(Patches.ColonyPatch),
            typeof(Patches.DamagePatch),
        };
        int ok = 0;
        foreach (var t in patchTypes)
        {
            try
            {
                _harmony.PatchAll(t);
                LoggerInstance.Msg($"  Harmony: {t.Name}");
                ok++;
            }
            catch (System.Exception ex)
            {
                LoggerInstance.Warning($"  Harmony failed: {t.Name}: {ex.Message}");
            }
        }
        LoggerInstance.Msg($"Harmony: {ok}/{patchTypes.Length} registered.");

        LoggerInstance.Msg("BravelyMod v0.2.0 initialized!");
        LoggerInstance.Msg($"  EXP boost: {(ExpBoostEnabled.Value ? $"x{ExpMultiplier.Value}" : "OFF")}");
        LoggerInstance.Msg($"  JP boost:  {(ExpBoostEnabled.Value ? $"x{JexpMultiplier.Value}" : "OFF")}");
        LoggerInstance.Msg($"  Gold boost:{(ExpBoostEnabled.Value ? $"x{GoldMultiplier.Value}" : "OFF")}");
        LoggerInstance.Msg($"  Damage cap:{(DamageCapEnabled.Value ? $"{DamageCapOverride.Value}" : "OFF")}");
        LoggerInstance.Msg($"  BP limit:  {(BpModEnabled.Value ? $"{BpLimitOverride.Value}" : "OFF")}");
        LoggerInstance.Msg($"  BP/turn:   {BpPerTurn.Value}");
        LoggerInstance.Msg($"  Speed:     {(SpeedModEnabled.Value ? $"x{BattleSpeedMultiplier.Value}" : "OFF")}");
        LoggerInstance.Msg($"  Colony:    {(ColonyModEnabled.Value ? $"x{ColonySpeedMultiplier.Value}" : "OFF")}");
        LoggerInstance.Msg($"  Scene skip:{ForceSceneSkip.Value}");
        LoggerInstance.Msg($"  Support$:  {(SupportCostModEnabled.Value ? $"{SupportCostOverride.Value}" : "OFF")}");
        LoggerInstance.Msg($"  WalkSpeed: {(WalkSpeedModEnabled.Value ? $"x{WalkSpeedMultiplier.Value}" : "OFF")}");
        LoggerInstance.Msg("Edit UserData/MelonPreferences.cfg to toggle features.");
    }

    public override void OnUpdate()
    {
        InitializeIfNeeded();
    }
}
