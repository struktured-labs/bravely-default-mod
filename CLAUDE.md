# Bravely Default: Flying Fairy HD — Modding Project

## Game
- **Steam app ID:** 2833580
- **Install path:** `~/.steam/debian-installation/steamapps/common/BDFFHD/`
- **Engine:** Unity 6 (6000.0.37f1), IL2CPP, Denuvo anti-tamper
- **Binary:** `GameAssembly.dll` (361MB x86-64)

## Modding Stack
- **MelonLoader v0.7.2** — runtime injection after Denuvo unpack
- **Harmony** — C# method patching (prefix/postfix hooks)
- **BravelyMod** — our mod in `BravelyMod/`, .NET 6 class library
- **Launch options:** `WINEDLLOVERRIDES="version=n,b" %command%`

## Build & Deploy
```bash
dotnet build BravelyMod/        # auto-deploys to game Mods/ folder
steam steam://rungameid/2833580  # launch with MelonLoader
```

## Rules

### C# / MelonLoader
- Target `net6.0` with `<Nullable>disable</Nullable>` — Il2Cppmscorlib breaks nullable attributes
- Reference unhollowed assemblies from `MelonLoader/Il2CppAssemblies/`, NOT from NuGet
- Game types live under the `Il2Cpp.` namespace (e.g., `Il2Cpp.BtlActionCalc`)
- Use `[HarmonyPatch(typeof(Il2Cpp.ClassName), nameof(Il2Cpp.ClassName.MethodName))]` for patches
- Prefix returns `bool` (false = skip original), Postfix uses `ref __result` to modify return values
- Config via `MelonPreferences` — persists to `UserData/MelonPreferences.cfg`

### Ghidra
- Project: `tmp/ghidra_projects/bdffhd`
- Always use Ghidra MCP tools (`mcp__ghidra__*`), never parse the binary manually
- IL2CPP method names use `$$` separator: `ClassName$$MethodName`
- String literals are metadata tokens (e.g., `StringLiteral_16192`) — extract via `global-metadata.dat`

### Data Files
- `.btb`/`.spb`/`.txb` etc. — BTBF format, parse with `arcanist.btbf.parser`
- `.btb2`/`.tbl2` — Brotli-compressed (NOT encrypted), decompress with `arcanist.btbf.crypto.Btb2File`
- The `Aesutil` class in the binary is for the UGC profanity filter only, not game data

### Python
- Use `uv run` for all Python commands (packages are in `.venv`)
- Toolkit: `arcanist` package, CLI: `btbf info/dump/dump-all`

### Testing
- Check `MelonLoader/Latest.log` after each launch to verify mod loaded
- Look for "BravelyMod initialized!" and "X Mods loaded" in the log
- If patches fail, MelonLoader logs the exception — check for HarmonyException

### Headless Testing (Xvfb + Vulkan on RTX 3090)
- **Full test:** `./scripts/test_mod.sh` — restores save, launches on `:99`, validates all hooks, screenshots, reports pass/fail
- **Headless launch only:** `./scripts/headless_launch.sh` — launches game on `:99` without fullscreen
- **Vulkan confirmed working** on Xvfb with NVIDIA RTX 3090
- Save backup at `tmp/save_backup/`, restored to Wine prefix before each test run
- Save destination: `~/.steam/.../compatdata/2833580/pfx/drive_c/users/steamuser/Documents/My Games/BRAVELY DEFAULT/Steam/76561198080785161/`
- Screenshots saved to `tmp/test_screenshots/`, results to `tmp/test_results/`
- **Do NOT start Xvfb or launch headless while the user may be playing** — always ask first
- Flags: `--no-xvfb` (reuse running Xvfb), `--skip-save-restore`, `--keep-alive`, `--timeout N`
