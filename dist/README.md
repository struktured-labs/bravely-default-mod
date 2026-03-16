# BravelyMod v0.5.9 — BRAVELY DEFAULT: Flying Fairy HD Remaster Mod

A comprehensive MelonLoader mod for **Bravely Default: Flying Fairy HD** (Steam) that
adds quality-of-life enhancements and a browser-based configuration UI.

## Features

- **EXP / JP / Gold multipliers** — configurable boost for grinding
- **Damage cap removal** — raise the 9999 cap to 999999+
- **BP limit override** — increase Brave Point cap and BP gained per turn
- **Battle speed multiplier** — stack on top of the in-game speed toggle
- **Colony speed multiplier** — rebuild Norende faster
- **Walk/dash speed multiplier** — move faster on the overworld and in dungeons
- **Force scene skip** — always-available cutscene skip
- **Support ability cost override** — equip more support abilities
- **Custom battle music** — replace any BGM cue with your own audio files
- **Job swap shortcut** — quick job changes in battle menus
- **Brave submenu patch** — improved Brave command menu
- **Live web config UI** — edit all settings at `http://localhost:8888` while the game runs
- **Music upload from browser** — drag-and-drop audio conversion to HCA via companion server

## Requirements

| Requirement | Version |
|---|---|
| Steam | Latest |
| Bravely Default: Flying Fairy HD | Steam release |
| MelonLoader | **v0.7.2+ nightly** (net6 branch) |
| .NET 6 Runtime | Bundled on Windows; manual on Linux |

## Installation

### Quick Install (Recommended)

**Linux:**
```bash
chmod +x install.sh
./install.sh
```

**Windows (PowerShell as Administrator):**
```
install.bat
```

### Manual Installation

#### Step 1: Install MelonLoader

1. Download **MelonLoader v0.7.2+ nightly** from:
   https://github.com/LavaGang/MelonLoader/releases
   - Get the `MelonLoader.x64.zip` package

2. Extract the contents into your BDFFHD game directory:
   - **Windows:** `C:\Program Files (x86)\Steam\steamapps\common\BDFFHD\`
   - **Linux:** `~/.steam/debian-installation/steamapps/common/BDFFHD/`

   After extraction you should see:
   ```
   BDFFHD/
     MelonLoader/
     version.dll
     dobby.dll
     ...
   ```

3. **(Linux/Proton only)** Set Steam launch options for BDFFHD:
   ```
   WINEDLLOVERRIDES="version=n,b" %command%
   ```
   Right-click BDFFHD in Steam > Properties > General > Launch Options.

4. **First launch:** Start the game once. MelonLoader will generate unhollowed
   assemblies in `MelonLoader/Il2CppAssemblies/`. The first launch takes a few
   minutes and the game may appear to hang — this is normal. Close the game after
   it finishes loading.

5. **(Linux/Proton only)** Install .NET 6 runtime into MelonLoader:
   ```bash
   GAME_DIR="$HOME/.steam/debian-installation/steamapps/common/BDFFHD"
   mkdir -p "$GAME_DIR/MelonLoader/dotnet"
   curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- \
       --channel 6.0 --runtime dotnet --install-dir "$GAME_DIR/MelonLoader/dotnet"
   ```

#### Step 2: Install Mod Files

Copy these files to the `Mods/` folder in your game directory:

```
BDFFHD/
  Mods/
    BravelyMod.dll
    YamlDotNet.dll
```

Create the `Mods/` folder if it doesn't exist.

#### Step 3: Launch the Game

Start BDFFHD from Steam. You should see MelonLoader output in the console/log
confirming BravelyMod loaded.

## Web Configuration UI

Once the game is running with the mod, open your browser to:

```
http://localhost:8888
```

From here you can:
- Toggle any mod feature on/off
- Adjust multipliers and limits in real time
- Edit autobattle profiles (YAML)
- Edit music override configuration
- Upload custom music files (requires the music conversion server)

Changes take effect immediately — no restart required.

## Configuration Files

BravelyMod stores configuration in the game's `UserData/` directory:

| File | Purpose |
|---|---|
| `MelonPreferences.cfg` | All feature toggles and numeric settings |
| `BravelyMod_AutoBattle.yaml` | Autobattle AI profiles |
| `BravelyMod_Music.yaml` | Custom BGM override mappings |

Edit these files directly or use the web UI.

## Custom Music Setup (Optional)

You can replace any in-game BGM with custom audio files.

### Using the Web UI (Easiest)

1. Start the music conversion server:
   - **Linux:** `./scripts/start_music_server.sh`
   - **Windows:** `scripts\start_music_server.bat`

2. Open `http://localhost:8888` in your browser

3. Go to the Music tab and drag-and-drop audio files (MP3, WAV, OGG, FLAC)

4. The server converts them to HCA format and places them in
   `StreamingAssets/CustomBGM/`

5. Assign converted files to BGM cue names in the Music config

### Using the Command Line

```bash
./scripts/convert_music.sh ~/music/my_battle_theme.mp3 my-custom-battle
```

This converts the file and places it in `CustomBGM/`. Then edit
`UserData/BravelyMod_Music.yaml`:

```yaml
overrides:
  bgmbtl_01: CustomBGM/my-custom-battle.hca
```

### Music Server Requirements

The music conversion server requires:
- Python 3.10+
- ffmpeg (system package)
- PyCriCodecs (`pip install PyCriCodecs`)

On Linux with the project venv, `uv run python scripts/music_server.py` handles
dependencies automatically.

## Troubleshooting

### MelonLoader doesn't load
- Verify `version.dll` is in the game root directory
- **Linux:** Confirm Steam launch options are set:
  `WINEDLLOVERRIDES="version=n,b" %command%`
- Check `MelonLoader/Latest.log` for errors

### Mod doesn't appear in game
- Verify `BravelyMod.dll` and `YamlDotNet.dll` are both in the `Mods/` folder
- Check `MelonLoader/Latest.log` for load errors
- Ensure MelonLoader completed its first-run assembly generation

### .NET 6 errors on Linux/Proton
- Install the .NET 6 runtime into `MelonLoader/dotnet/`:
  ```bash
  curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- \
      --channel 6.0 --runtime dotnet \
      --install-dir "$HOME/.steam/debian-installation/steamapps/common/BDFFHD/MelonLoader/dotnet"
  ```

### Web UI not loading
- The game must be running with the mod loaded
- Check that port 8888 is not blocked by a firewall
- Check `MelonLoader/Latest.log` for HTTP listener errors

### Music conversion fails
- Ensure `ffmpeg` is installed and in your PATH
- Ensure PyCriCodecs is installed: `pip install PyCriCodecs`
- Check the music server log for detailed error messages

### Game crashes on startup
- Try removing all mods from `Mods/` and launching once to re-generate assemblies
- Update to the latest MelonLoader nightly
- On Linux, verify Proton compatibility (Proton Experimental recommended)

## File Structure

```
BDFFHD/                          (game root directory)
  version.dll                    (MelonLoader bootstrap)
  MelonLoader/                   (MelonLoader runtime)
    dotnet/                      (Linux only: .NET 6 runtime)
    Il2CppAssemblies/            (generated on first launch)
    Latest.log                   (mod log output)
  Mods/
    BravelyMod.dll               (this mod)
    YamlDotNet.dll               (YAML dependency)
  UserData/
    MelonPreferences.cfg         (mod settings)
    BravelyMod_AutoBattle.yaml   (autobattle config)
    BravelyMod_Music.yaml        (music overrides)
  BDFFHD_Data/
    StreamingAssets/
      CustomBGM/                 (your custom HCA audio files)
```

## License

This mod is provided as-is for personal use with a legally purchased copy of
Bravely Default: Flying Fairy HD on Steam.

## Credits

- **struktured** — mod development
- **MelonLoader** — mod framework (LavaGang)
- **Il2CppInterop** — IL2CPP unhollowing
- **YamlDotNet** — YAML parsing
- **PyCriCodecs** — CriWare HCA audio encoding
