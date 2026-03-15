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
/// Hooks BtlSoundManager.PlayBGM to replace BGM cues with custom HCA files.
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

    private static NativeHook<d_PlayBGM> _playBGMHook;
    private static d_PlayBGM _pinnedDelegate;

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
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[Music] Hook failed: {ex}");
        }
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
                // Create default config
                var config = new MusicConfig
                {
                    Overrides = new Dictionary<string, string>
                    {
                        ["bgmbtl_01"] = "CustomBGM/battle-melody-2.hca"
                    }
                };
                var serializer = new SerializerBuilder()
                    .WithNamingConvention(CamelCaseNamingConvention.Instance)
                    .Build();
                System.IO.File.WriteAllText(ConfigPath, serializer.Serialize(config));
                Melon<Core>.Logger.Msg($"[Music] Created default config: {ConfigPath}");

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

    private static nint PlayCustomHCA(string hcaPath)
    {
        try
        {
            StopCustomPlayer();
            _customPlayer = new CriPlayer(256, 1);
            if (_customPlayer == null || !_customPlayer.isAvailable) return 0;

            _customPlayer.SetFile(null, hcaPath);
            _customPlayer.SetVolume(1.0f);
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
