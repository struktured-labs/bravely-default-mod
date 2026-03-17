using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;
using MelonLoader.Utils;
using Il2CppInterop.Runtime;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using CriPlayer = Il2CppCriWare.CriAtomExPlayer;

namespace BravelyMod.Patches;

/// <summary>
/// Hooks BGM playback to replace BGM cues with custom HCA files.
/// Hooks SoundInterface.PlayBGM (universal funnel for ALL BGM: overworld, town, dungeon, battle)
/// and BtlSoundManager.PlayBGM (battle-specific, calls SoundInterface under the hood).
/// Config: UserData/BravelyMod_Music.yaml
/// </summary>
public static unsafe class NativeMusicPatch
{
    public class MusicConfig
    {
        [YamlMember(Alias = "overrides")]
        public Dictionary<string, string> Overrides { get; set; } = new();
    }

    private static string ConfigPath =>
        System.IO.Path.Combine(MelonEnvironment.UserDataDirectory, "BravelyMod_Music.yaml");

    // cue name -> absolute HCA path
    private static Dictionary<string, string> _overrides = new();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_PlayBGM(nint instance, nint pFilename, byte loopFlag, int fadeFrame, nint methodInfo);

    // void StopBGM(this BtlSoundManager, int fadeFrame, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_StopBGM(nint instance, int fadeFrame, nint methodInfo);

    // void SoundInterface.StopBGM(this, string filename, int fadeFrame, MethodInfo*)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void d_SoundInterfaceStopBGM(nint instance, nint pFilename, int fadeFrame, nint methodInfo);

    // SoundInstance SoundInterface.PlayBGM(this, string filename, bool loopFlag, int fadeFrame, float offsetMS, MethodInfo*)
    // This is the universal funnel: CruiseGame.PlayBGM, BgmEntry.Unit.Play, BGM_SE_Pause_PlayBGM,
    // and BtlSoundManager.PlayBGM all call SoundInterface.PlayBGM internally.
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_SoundInterfacePlayBGM(nint instance, nint pFilename, byte loopFlag, int fadeFrame, float offsetMS, nint methodInfo);

    private static NativeHook<d_PlayBGM> _playBGMHook;
    private static d_PlayBGM _pinnedDelegate;

    private static NativeHook<d_SoundInterfacePlayBGM> _soundInterfaceHook;
    private static d_SoundInterfacePlayBGM _pinnedSoundInterface;

    private static NativeHook<d_StopBGM> _stopBGMHook;
    private static d_StopBGM _pinnedStopDelegate;

    private static NativeHook<d_SoundInterfaceStopBGM> _siStopBGMHook;
    private static d_SoundInterfaceStopBGM _pinnedSiStopDelegate;

    private static CriPlayer _customPlayer;
    private static bool _customPlaying;
    private static int _logCount;

    public static void Apply()
    {
        try
        {
            LoadConfig();

            if (_overrides.Count == 0)
            {
                Melon<Core>.Logger.Msg("[Music] No overrides configured");
                return;
            }

            // Hook BtlSoundManager.PlayBGM
            var field = typeof(Il2Cpp.BtlSoundManager).GetField(
                "NativeMethodInfoPtr_PlayBGM_Public_SoundInstance_String_Boolean_Int32_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

            if (field == null) { Melon<Core>.Logger.Warning("[Music] PlayBGM field not found"); return; }

            var methodInfoPtr = (nint)field.GetValue(null);
            if (methodInfoPtr == 0) return;

            var nativePtr = *(nint*)methodInfoPtr;
            Melon<Core>.Logger.Msg($"[Music] BtlSoundManager.PlayBGM native @ 0x{nativePtr:X}");

            _pinnedDelegate = PlayBGM_Hook;
            _playBGMHook = new NativeHook<d_PlayBGM>(nativePtr, Marshal.GetFunctionPointerForDelegate(_pinnedDelegate));
            _playBGMHook.Attach();
            Melon<Core>.Logger.Msg("[Music] PlayBGM hook attached!");

            // Hook SoundInterface.PlayBGM - the universal funnel for ALL BGM playback
            // (overworld, town, dungeon, battle all flow through here)
            try
            {
                var siField = typeof(Il2Cpp.SoundInterface).GetField(
                    "NativeMethodInfoPtr_PlayBGM_Public_SoundInstance_String_Boolean_Int32_Single_0",
                    System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
                if (siField != null)
                {
                    var siMi = (nint)siField.GetValue(null);
                    if (siMi != 0)
                    {
                        var siNative = *(nint*)siMi;
                        _pinnedSoundInterface = SoundInterfacePlayBGM_Hook;
                        _soundInterfaceHook = new NativeHook<d_SoundInterfacePlayBGM>(siNative, Marshal.GetFunctionPointerForDelegate(_pinnedSoundInterface));
                        _soundInterfaceHook.Attach();
                        Melon<Core>.Logger.Msg($"[Music] SoundInterface.PlayBGM hook @ 0x{siNative:X}");
                    }
                }
                else
                {
                    Melon<Core>.Logger.Warning("[Music] SoundInterface.PlayBGM field not found!");
                }
            }
            catch (Exception ex)
            {
                Melon<Core>.Logger.Warning($"[Music] SoundInterface hook failed: {ex.Message}");
            }

            // Hook BtlSoundManager.StopBGM to stop custom player when battle ends
            var stopField = typeof(Il2Cpp.BtlSoundManager).GetField(
                "NativeMethodInfoPtr_StopBGM_Public_Void_Int32_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            if (stopField != null)
            {
                var stopMi = (nint)stopField.GetValue(null);
                if (stopMi != 0)
                {
                    var stopNative = *(nint*)stopMi;
                    _pinnedStopDelegate = StopBGM_Hook;
                    _stopBGMHook = new NativeHook<d_StopBGM>(stopNative, Marshal.GetFunctionPointerForDelegate(_pinnedStopDelegate));
                    _stopBGMHook.Attach();
                    Melon<Core>.Logger.Msg("[Music] BtlSoundManager.StopBGM hook attached!");
                }
            }

            // Hook SoundInterface.StopBGM to stop custom player on overworld BGM transitions
            try
            {
                var siStopField = typeof(Il2Cpp.SoundInterface).GetField(
                    "NativeMethodInfoPtr_StopBGM_Public_Void_String_Int32_0",
                    System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
                if (siStopField != null)
                {
                    var siStopMi = (nint)siStopField.GetValue(null);
                    if (siStopMi != 0)
                    {
                        var siStopNative = *(nint*)siStopMi;
                        _pinnedSiStopDelegate = SoundInterfaceStopBGM_Hook;
                        _siStopBGMHook = new NativeHook<d_SoundInterfaceStopBGM>(siStopNative, Marshal.GetFunctionPointerForDelegate(_pinnedSiStopDelegate));
                        _siStopBGMHook.Attach();
                        Melon<Core>.Logger.Msg($"[Music] SoundInterface.StopBGM hook @ 0x{siStopNative:X}");
                    }
                }
            }
            catch (Exception ex)
            {
                Melon<Core>.Logger.Warning($"[Music] SoundInterface.StopBGM hook failed: {ex.Message}");
            }
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[Music] Hook failed: {ex}");
        }
    }

    private static void StopBGM_Hook(nint instance, int fadeFrame, nint methodInfo)
    {
        try
        {
            StopCustomPlayer();
            _stopBGMHook.Trampoline(instance, fadeFrame, methodInfo);
        }
        catch
        {
            try { _stopBGMHook.Trampoline(instance, fadeFrame, methodInfo); } catch { }
        }
    }

    /// <summary>
    /// Reload music overrides from disk. Called by the web config server after saving.
    /// Clears existing overrides and re-reads the YAML config file.
    /// </summary>
    public static void ReloadConfig()
    {
        _overrides.Clear();
        LoadConfig();
        Melon<Core>.Logger.Msg($"[Music] Config reloaded: {_overrides.Count} overrides active");
    }

    private static void LoadConfig()
    {
        var streamingAssets = UnityEngine.Application.streamingAssetsPath;

        try
        {
            if (System.IO.File.Exists(ConfigPath))
            {
                var yaml = System.IO.File.ReadAllText(ConfigPath);
                var deserializer = new DeserializerBuilder()
                    .WithNamingConvention(CamelCaseNamingConvention.Instance)
                    .IgnoreUnmatchedProperties()
                    .Build();
                var config = deserializer.Deserialize<MusicConfig>(yaml);
                if (config?.Overrides != null)
                {
                    foreach (var kv in config.Overrides)
                    {
                        var absPath = System.IO.Path.Combine(streamingAssets, kv.Value);
                        if (System.IO.File.Exists(absPath))
                        {
                            _overrides[kv.Key] = absPath;
                            Melon<Core>.Logger.Msg($"[Music] Override: {kv.Key} -> {kv.Value}");
                        }
                        else
                        {
                            Melon<Core>.Logger.Warning($"[Music] HCA not found: {absPath}");
                        }
                    }
                }
            }
            else
            {
                // Create default config with all 85 BDIO_BGM.acb cues documented
                var defaultYaml = @"# Bravely Default: Flying Fairy HD - Music Override Configuration
# Place custom HCA audio files in StreamingAssets/CustomBGM/
# Uncomment a line and set the path to override that BGM cue.
# See Config/music_template.yaml for full documentation.

overrides:
  # === Battle Music ===
  bgmbtl_01: CustomBGM/battle-melody-2.hca  # Normal battle (most encounters)
  # bgmbtl_02:   # Boss battle
  # bgmbtl_03:   # Asterisk holder battle
  # bgmbtl_04:   # Special battle 1 (scripted boss phase)
  # bgmbtl_05:   # Special battle 2 (scripted boss phase)
  # bgmbtl_06:   # Special battle 3 (scripted boss phase)
  # bgmbtl_07:   # Special battle 4 (scripted boss phase)
  # bgmbtl_08:   # Victory fanfare / battle results
  # bgmbtl_09:   # Battle results variant
  # bgmbtl_10:   # Rare encounter battle
  # bgmbtl_11:   # Late-game battle 1
  # bgmbtl_12:   # Late-game battle 2
  # bgmbtl_13:   # Late-game battle 3
  # bgmbtl_14:   # Late-game battle 4
  # bgmbtl_15:   # Endgame battle
  # bgmbtl_16:   # Final boss / special endgame

  # === Field / Overworld ===
  # bgmfld_01:   # Overworld theme (Caldisla region)
  # bgmfld_02:   # Overworld variant 2
  # bgmfld_03:   # Overworld variant 3
  # bgmfld_04:   # Overworld variant 4 (airship)

  # === Towns ===
  # bgmtwn_01:   # Caldisla / Ancheim towns
  # bgmtwn_02:   # Florem region
  # bgmtwn_03:   # Grandship / Hartschild
  # bgmtwn_04:   # Eisenberg towns
  # bgmtwn_05:   # Eternia region
  # bgmtwn_06:   # Special town
  # bgmtwn_07:   # Yulyana / Sage's town
  # bgmtwn_08:   # Town variant 8

  # === Dungeons ===
  # bgmdgn_01:   # Ruins / Lontano Villa
  # bgmdgn_02:   # Temples / Caves
  # bgmdgn_03:   # Harena Ruins / misc
  # bgmdgn_04:   # Dungeon 4
  # bgmdgn_05:   # Endgame dungeon
  # bgmdgn_07:   # Special dungeon

  # === Events / Cutscenes ===
  # bgmevt_01:   # Prologue / story intro
  # bgmevt_02:   # Emotional scene
  # bgmevt_03:   # Tension / drama
  # bgmevt_04:   # Plot event
  # bgmevt_05:   # Revelation
  # bgmevt_06:   # Conflict
  # bgmevt_07:   # Sorrow / loss
  # bgmevt_08:   # Hope / resolve
  # bgmevt_09:   # Climax buildup
  # bgmevt_10:   # Finale moments
  # bgmevt_12:   # Special scene
  # bgmevt_13:   # Event 13 (JP voice)
  # bgmevt_13_en: # Event 13 (EN voice)
  # bgmevt_14:   # Endgame event

  # === System / Menu ===
  # bgmsys_01:   # Title screen / silence
  # bgmsys_02:   # System 2
  # bgmsys_03:   # System 3
  # bgmsys_04:   # System 4
  # bgmsys_05:   # Menu related
  # bgmsys_06:   # System 6
  # bgmsys_07:   # Save/load screen
  # bgmsys_08:   # Game over
  # bgmsys_09:   # Configuration
  # bgmsys_10:   # System 10
  # bgmsys_11:   # System 11
  # bgmsys_12:   # System 12
  # bgmsys_13:   # System 13
  # bgmsys_14:   # System 14
  # bgmsys_15:   # System 15
  # bgmsys_16:   # System 16
  # bgmsys_17:   # System 17
  # bgmsys_18:   # System 18
  # bgmsys_19:   # System 19
  # bgmsys_20:   # System 20
  # bgmsys_21:   # System 21
  # bgmsys_22:   # System 22
";
                System.IO.File.WriteAllText(ConfigPath, defaultYaml);
                Melon<Core>.Logger.Msg($"[Music] Created default config with all cues: {ConfigPath}");

                // Apply default
                var absPath = System.IO.Path.Combine(streamingAssets, "CustomBGM/battle-melody-2.hca");
                if (System.IO.File.Exists(absPath))
                    _overrides["bgmbtl_01"] = absPath;
            }
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[Music] Config load failed: {ex.Message}");
        }
    }

    private static nint PlayBGM_Hook(nint instance, nint pFilename, byte loopFlag, int fadeFrame, nint methodInfo)
    {
        try
        {
            string filename = pFilename != 0 ? IL2CPP.Il2CppStringToManaged(pFilename) : null;

            _logCount++;
            if (_logCount <= 10)
                Melon<Core>.Logger.Msg($"[Music] PlayBGM: '{filename}' loop={loopFlag}");

            if (filename != null && _overrides.TryGetValue(filename, out var hcaPath))
            {
                Melon<Core>.Logger.Msg($"[Music] Intercepting {filename} -> custom HCA");
                return PlayCustomHCA(hcaPath);
            }

            StopCustomPlayer();
            return _playBGMHook.Trampoline(instance, pFilename, loopFlag, fadeFrame, methodInfo);
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[Music] Hook error: {ex.Message}");
            try { return _playBGMHook.Trampoline(instance, pFilename, loopFlag, fadeFrame, methodInfo); }
            catch { return 0; }
        }
    }

    private static nint SoundInterfacePlayBGM_Hook(nint instance, nint pFilename, byte loopFlag, int fadeFrame, float offsetMS, nint methodInfo)
    {
        try
        {
            string filename = pFilename != 0 ? IL2CPP.Il2CppStringToManaged(pFilename) : null;

            _logCount++;
            if (_logCount <= 20)
                Melon<Core>.Logger.Msg($"[Music] SoundInterface.PlayBGM: '{filename}' loop={loopFlag} fade={fadeFrame} offset={offsetMS}");

            if (filename != null && _overrides.TryGetValue(filename, out var hcaPath))
            {
                Melon<Core>.Logger.Msg($"[Music] Intercepting (SoundInterface) {filename} -> custom HCA");
                StopCustomPlayer();
                PlayCustomHCA(hcaPath);
                // Skip original playback — return null SoundInstance
                return 0;
            }

            StopCustomPlayer();
            return _soundInterfaceHook.Trampoline(instance, pFilename, loopFlag, fadeFrame, offsetMS, methodInfo);
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[Music] SoundInterface hook error: {ex.Message}");
            try { return _soundInterfaceHook.Trampoline(instance, pFilename, loopFlag, fadeFrame, offsetMS, methodInfo); }
            catch { return 0; }
        }
    }

    private static string _currentHcaPath;
    private static Il2CppCriWare.CriAtomExPlayback _currentPlayback;

    /// <summary>Check if custom music stopped and restart it (poor man's loop)</summary>
    public static void CheckLoop()
    {
        try
        {
            if (_customPlaying && _customPlayer != null && _currentHcaPath != null)
            {
                var status = _customPlayer.GetStatus();
                // CriAtomExPlayer.Status: Stop=0, Prep=1, Playing=2, PlayEnd=3, Error=4
                if ((int)status >= 3) // PlayEnd or Error
                {
                    _customPlayer.SetFile(null, _currentHcaPath);
                    _customPlayer.SetVolume(0.55f);
                    _currentPlayback = _customPlayer.Start();
                }
            }
        }
        catch { }
    }

    private static nint PlayCustomHCA(string hcaPath)
    {
        try
        {
            StopCustomPlayer();
            _currentHcaPath = hcaPath;
            _customPlayer = new CriPlayer(256, 1);
            if (_customPlayer == null || !_customPlayer.isAvailable) return 0;

            _customPlayer.SetFile(null, hcaPath);
            _customPlayer.SetVolume(0.55f);
            var playback = _customPlayer.Start();
            _customPlaying = true;
            Melon<Core>.Logger.Msg($"[Music] Custom playback started (id={playback.id})");
            return 0;
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[Music] Custom playback failed: {ex}");
            return 0;
        }
    }

    private static void StopCustomPlayer()
    {
        try
        {
            if (_customPlayer != null && _customPlaying)
            {
                _customPlayer.Stop(false);
                _customPlaying = false;
            }
            if (_customPlayer != null)
            {
                _customPlayer.Dispose();
                _customPlayer = null;
            }
        }
        catch
        {
            _customPlayer = null;
            _customPlaying = false;
        }
    }
}
