using System;
using System.Runtime.InteropServices;
using MelonLoader;
using MelonLoader.NativeUtils;
using Il2CppInterop.Runtime;
using CriPlayer = Il2CppCriWare.CriAtomExPlayer;

namespace BravelyMod.Patches;

/// <summary>
/// Hooks BtlSoundManager.PlayBGM to replace bgmbtl_01 (normal battle music)
/// with a custom HCA file played via CriAtomExPlayer.SetFile.
/// </summary>
public static unsafe class NativeMusicPatch
{
    // Target cue name to intercept
    private const string TARGET_CUE = "bgmbtl_01";

    // Path relative to StreamingAssets
    private const string CUSTOM_HCA_RELATIVE = "CustomBGM/battle-melody-2.hca";

    // BtlSoundManager.PlayBGM(string _pFilename, bool _loopFlag, int _fadeFrame) -> SoundInstance
    // IL2CPP native: nint(nint instance, nint il2cppString, byte loopFlag, int fadeFrame, nint methodInfo)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint d_PlayBGM(nint instance, nint pFilename, byte loopFlag, int fadeFrame, nint methodInfo);

    private static NativeHook<d_PlayBGM> _playBGMHook;
    private static d_PlayBGM _pinnedDelegate;

    // Our custom CriAtomExPlayer for file-based playback
    private static CriPlayer _customPlayer;
    private static bool _customPlaying;
    private static int _logCount;

    // Resolved absolute path to the HCA file
    private static string _hcaAbsolutePath;

    public static void Apply()
    {
        try
        {
            // Resolve the absolute path to the HCA file
            _hcaAbsolutePath = System.IO.Path.Combine(
                UnityEngine.Application.streamingAssetsPath,
                CUSTOM_HCA_RELATIVE);

            if (!System.IO.File.Exists(_hcaAbsolutePath))
            {
                Melon<Core>.Logger.Warning($"[Music] HCA file not found: {_hcaAbsolutePath}");
                return;
            }

            Melon<Core>.Logger.Msg($"[Music] Custom HCA: {_hcaAbsolutePath}");

            // Hook BtlSoundManager.PlayBGM
            var field = typeof(Il2Cpp.BtlSoundManager).GetField(
                "NativeMethodInfoPtr_PlayBGM_Public_SoundInstance_String_Boolean_Int32_0",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

            if (field == null)
            {
                Melon<Core>.Logger.Warning("[Music] PlayBGM method info field not found");
                return;
            }

            var methodInfoPtr = (nint)field.GetValue(null);
            if (methodInfoPtr == 0)
            {
                Melon<Core>.Logger.Warning("[Music] PlayBGM method info ptr is null");
                return;
            }

            var nativePtr = *(nint*)methodInfoPtr;
            Melon<Core>.Logger.Msg($"[Music] BtlSoundManager.PlayBGM native @ 0x{nativePtr:X}");

            _pinnedDelegate = PlayBGM_Hook;
            _playBGMHook = new NativeHook<d_PlayBGM>(
                nativePtr,
                Marshal.GetFunctionPointerForDelegate(_pinnedDelegate));
            _playBGMHook.Attach();

            Melon<Core>.Logger.Msg("[Music] PlayBGM hook attached!");
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[Music] Hook failed: {ex}");
        }
    }

    private static nint PlayBGM_Hook(nint instance, nint pFilename, byte loopFlag, int fadeFrame, nint methodInfo)
    {
        try
        {
            // Read the Il2Cpp string to get the filename
            string filename = null;
            if (pFilename != 0)
            {
                filename = IL2CPP.Il2CppStringToManaged(pFilename);
            }

            _logCount++;
            if (_logCount <= 10)
                Melon<Core>.Logger.Msg($"[Music] PlayBGM called: '{filename}' loop={loopFlag} fade={fadeFrame}");

            if (filename != null && filename.Contains(TARGET_CUE))
            {
                Melon<Core>.Logger.Msg($"[Music] Intercepting {TARGET_CUE} -> custom HCA");
                return PlayCustomHCA(loopFlag != 0, fadeFrame);
            }
            else
            {
                // Not our target -- stop custom player if it was playing, then call original
                StopCustomPlayer();
                return _playBGMHook.Trampoline(instance, pFilename, loopFlag, fadeFrame, methodInfo);
            }
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[Music] PlayBGM hook error: {ex.Message}");
            try { return _playBGMHook.Trampoline(instance, pFilename, loopFlag, fadeFrame, methodInfo); }
            catch { return 0; }
        }
    }

    private static nint PlayCustomHCA(bool loop, int fadeFrame)
    {
        try
        {
            // Stop any existing custom playback
            StopCustomPlayer();

            // Create a new CriAtomExPlayer with enough path buffer
            // maxPath=256, maxPathStrings=1
            _customPlayer = new CriPlayer(256, 1);

            if (_customPlayer == null || !_customPlayer.isAvailable)
            {
                Melon<Core>.Logger.Warning("[Music] Failed to create CriAtomExPlayer");
                return 0;
            }

            // SetFile with null binder = load from filesystem
            _customPlayer.SetFile(null, _hcaAbsolutePath);

            // Set volume to match typical BGM level
            _customPlayer.SetVolume(1.0f);

            // Start playback
            var playback = _customPlayer.Start();
            _customPlaying = true;

            Melon<Core>.Logger.Msg($"[Music] Custom HCA playback started (playback id={playback.id})");

            // Return 0 (null SoundInstance) - the caller (BtlSoundManager) will store this
            // in m_hDefaultBGM. A null is safe since the game checks for it.
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
                Melon<Core>.Logger.Msg("[Music] Stopped custom player");
            }

            if (_customPlayer != null)
            {
                _customPlayer.Dispose();
                _customPlayer = null;
            }
        }
        catch (Exception ex)
        {
            Melon<Core>.Logger.Warning($"[Music] Error stopping custom player: {ex.Message}");
            _customPlayer = null;
            _customPlaying = false;
        }
    }
}
