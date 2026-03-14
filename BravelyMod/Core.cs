using MelonLoader;
using HarmonyLib;

[assembly: MelonInfo(typeof(BravelyMod.Core), "BravelyMod", "0.1.0", "struktured")]
[assembly: MelonGame("SquareEnix", "BDFFHD")]

namespace BravelyMod;

public class Core : MelonMod
{
    public static MelonPreferences_Category Config { get; private set; }

    // Multipliers
    public static MelonPreferences_Entry<float> ExpMultiplier { get; private set; }
    public static MelonPreferences_Entry<float> JexpMultiplier { get; private set; }
    public static MelonPreferences_Entry<float> GoldMultiplier { get; private set; }

    // Damage
    public static MelonPreferences_Entry<int> DamageCapOverride { get; private set; }

    // BP
    public static MelonPreferences_Entry<int> BpLimitOverride { get; private set; }

    // Battle speed
    public static MelonPreferences_Entry<float> BattleSpeedMultiplier { get; private set; }

    // Colony
    public static MelonPreferences_Entry<float> ColonySpeedMultiplier { get; private set; }

    // Scene skip
    public static MelonPreferences_Entry<bool> ForceSceneSkip { get; private set; }

    // Toggle states (runtime, not persisted)
    public static bool ExpBoostEnabled { get; set; } = true;
    public static bool DamageCapEnabled { get; set; } = true;

    private static bool _initialized = false;
    private static HarmonyLib.Harmony _harmony;

    public override void OnInitializeMelon()
    {
        InitializeIfNeeded();
    }

    // Called by MelonLoader even without support module
    public override void OnEarlyInitializeMelon()
    {
        InitializeIfNeeded();
    }

    private void InitializeIfNeeded()
    {
        if (_initialized) return;
        _initialized = true;

        Config = MelonPreferences.CreateCategory("BravelyMod", "Bravely Mod Settings");

        ExpMultiplier = Config.CreateEntry("ExpMultiplier", 10.0f, "EXP Multiplier");
        JexpMultiplier = Config.CreateEntry("JexpMultiplier", 10.0f, "JP Multiplier");
        GoldMultiplier = Config.CreateEntry("GoldMultiplier", 10.0f, "Gold Multiplier");
        DamageCapOverride = Config.CreateEntry("DamageCapOverride", 999999, "Damage Cap Override");
        BpLimitOverride = Config.CreateEntry("BpLimitOverride", 9, "BP Limit Override");
        BattleSpeedMultiplier = Config.CreateEntry("BattleSpeedMultiplier", 1.0f, "Battle Speed Multiplier");
        ColonySpeedMultiplier = Config.CreateEntry("ColonySpeedMultiplier", 10.0f, "Colony Speed Multiplier");
        ForceSceneSkip = Config.CreateEntry("ForceSceneSkip", true, "Force Scene Skip Enabled");

        // Native hooks — bypass broken Harmony IL2CPP detours on Unity 6
        LoggerInstance.Msg("Applying native hooks...");
        Patches.NativeExpPatch.Apply();

        // Also try Harmony patches (may work for some methods)
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
        LoggerInstance.Msg($"Harmony: {ok}/{patchTypes.Length} patch classes applied.");

        LoggerInstance.Msg("BravelyMod initialized!");
        LoggerInstance.Msg($"  EXP x{ExpMultiplier.Value}, JP x{JexpMultiplier.Value}, Gold x{GoldMultiplier.Value}");
        LoggerInstance.Msg($"  Damage cap: {DamageCapOverride.Value}");
        LoggerInstance.Msg($"  BP limit: {BpLimitOverride.Value}");
        LoggerInstance.Msg($"  Colony speed: x{ColonySpeedMultiplier.Value}");
        LoggerInstance.Msg($"  Scene skip: {ForceSceneSkip.Value}");
    }

    public override void OnUpdate()
    {
        // Ensure init even if early/normal init didn't fire
        InitializeIfNeeded();
        HandleHotkeys();
    }

    private void HandleHotkeys()
    {
        if (!_initialized) return;

        // F1-F4: Battle speed presets
        if (UnityEngine.Input.GetKeyDown(UnityEngine.KeyCode.F1))
        {
            BattleSpeedMultiplier.Value = 1.0f;
            LoggerInstance.Msg("Battle speed: 1x (normal)");
        }
        else if (UnityEngine.Input.GetKeyDown(UnityEngine.KeyCode.F2))
        {
            BattleSpeedMultiplier.Value = 2.0f;
            LoggerInstance.Msg("Battle speed: 2x");
        }
        else if (UnityEngine.Input.GetKeyDown(UnityEngine.KeyCode.F3))
        {
            BattleSpeedMultiplier.Value = 4.0f;
            LoggerInstance.Msg("Battle speed: 4x");
        }
        else if (UnityEngine.Input.GetKeyDown(UnityEngine.KeyCode.F4))
        {
            BattleSpeedMultiplier.Value = 8.0f;
            LoggerInstance.Msg("Battle speed: 8x");
        }

        // F5: Toggle EXP boost
        if (UnityEngine.Input.GetKeyDown(UnityEngine.KeyCode.F5))
        {
            ExpBoostEnabled = !ExpBoostEnabled;
            LoggerInstance.Msg($"EXP boost: {(ExpBoostEnabled ? "ON" : "OFF")}");
        }

        // F6: Toggle damage cap removal
        if (UnityEngine.Input.GetKeyDown(UnityEngine.KeyCode.F6))
        {
            DamageCapEnabled = !DamageCapEnabled;
            LoggerInstance.Msg($"Damage cap removal: {(DamageCapEnabled ? "ON" : "OFF")}");
        }
    }
}
