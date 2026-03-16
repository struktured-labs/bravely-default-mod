#!/usr/bin/env bash
# install.sh — BravelyMod installer for Linux (Steam/Proton)
#
# Downloads MelonLoader, installs mod DLLs, sets up .NET 6 runtime.
# Run from the directory containing this script.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#   ./install.sh /path/to/BDFFHD   # override game directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Configuration ---

MELONLOADER_VERSION="v0.7.2"
MELONLOADER_ZIP_URL="https://github.com/LavaGang/MelonLoader/releases/latest/download/MelonLoader.x64.zip"
DOTNET_INSTALL_URL="https://dot.net/v1/dotnet-install.sh"
DOTNET_CHANNEL="6.0"

# Common Steam library paths to search
STEAM_LIBRARY_PATHS=(
    "$HOME/.steam/debian-installation/steamapps/common/BDFFHD"
    "$HOME/.steam/steam/steamapps/common/BDFFHD"
    "$HOME/.local/share/Steam/steamapps/common/BDFFHD"
)

# --- Functions ---

log()  { echo -e "\033[1;32m[BravelyMod]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARNING]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }

detect_game_dir() {
    for path in "${STEAM_LIBRARY_PATHS[@]}"; do
        if [[ -d "$path" && -f "$path/BDFFHD.exe" ]]; then
            echo "$path"
            return 0
        fi
    done

    # Search for additional Steam library folders
    local libraryfolders="$HOME/.steam/debian-installation/steamapps/libraryfolders.vdf"
    if [[ -f "$libraryfolders" ]]; then
        while IFS= read -r line; do
            local dir
            dir="$(echo "$line" | grep -oP '"path"\s+"\K[^"]+' || true)"
            if [[ -n "$dir" && -d "$dir/steamapps/common/BDFFHD" ]]; then
                echo "$dir/steamapps/common/BDFFHD"
                return 0
            fi
        done < "$libraryfolders"
    fi

    return 1
}

# --- Main ---

echo ""
echo "============================================"
echo "  BravelyMod v0.5.9 Installer (Linux)"
echo "============================================"
echo ""

# Determine game directory
if [[ $# -ge 1 ]]; then
    GAME_DIR="$1"
else
    log "Auto-detecting BDFFHD installation..."
    if GAME_DIR="$(detect_game_dir)"; then
        log "Found: $GAME_DIR"
    else
        echo ""
        echo "Could not auto-detect BDFFHD installation."
        echo "Common locations:"
        echo "  ~/.steam/debian-installation/steamapps/common/BDFFHD/"
        echo "  ~/.local/share/Steam/steamapps/common/BDFFHD/"
        echo ""
        read -rp "Enter your BDFFHD game directory: " GAME_DIR
    fi
fi

# Validate
if [[ ! -d "$GAME_DIR" ]]; then
    err "Directory not found: $GAME_DIR"
fi

if [[ ! -f "$GAME_DIR/BDFFHD.exe" ]]; then
    warn "BDFFHD.exe not found in $GAME_DIR — are you sure this is the right directory?"
    read -rp "Continue anyway? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy] ]] || exit 1
fi

log "Game directory: $GAME_DIR"
echo ""

# --- Step 1: MelonLoader ---

if [[ -f "$GAME_DIR/version.dll" && -d "$GAME_DIR/MelonLoader" ]]; then
    log "MelonLoader already installed. Skipping download."
else
    log "Downloading MelonLoader..."

    ML_ZIP="$SCRIPT_DIR/MelonLoader.x64.zip"
    if command -v curl &>/dev/null; then
        curl -sSL -o "$ML_ZIP" "$MELONLOADER_ZIP_URL"
    elif command -v wget &>/dev/null; then
        wget -q -O "$ML_ZIP" "$MELONLOADER_ZIP_URL"
    else
        err "Neither curl nor wget found. Install one and retry."
    fi

    log "Extracting MelonLoader to game directory..."
    unzip -qo "$ML_ZIP" -d "$GAME_DIR"
    rm -f "$ML_ZIP"

    if [[ -f "$GAME_DIR/version.dll" ]]; then
        log "MelonLoader installed successfully."
    else
        err "MelonLoader extraction failed — version.dll not found."
    fi
fi

# --- Step 2: .NET 6 Runtime ---

DOTNET_DIR="$GAME_DIR/MelonLoader/dotnet"

if [[ -f "$DOTNET_DIR/dotnet" ]]; then
    log ".NET 6 runtime already installed. Skipping."
else
    log "Installing .NET 6 runtime for MelonLoader (Linux/Proton)..."
    mkdir -p "$DOTNET_DIR"

    if command -v curl &>/dev/null; then
        curl -sSL "$DOTNET_INSTALL_URL" | bash -s -- \
            --channel "$DOTNET_CHANNEL" \
            --runtime dotnet \
            --install-dir "$DOTNET_DIR"
    else
        err "curl is required to install .NET 6 runtime."
    fi

    if [[ -f "$DOTNET_DIR/dotnet" ]]; then
        log ".NET 6 runtime installed."
    else
        warn ".NET 6 runtime installation may have failed. Check $DOTNET_DIR"
    fi
fi

# --- Step 3: Install Mod DLLs ---

MODS_DIR="$GAME_DIR/Mods"
mkdir -p "$MODS_DIR"

log "Installing mod files to $MODS_DIR..."

for dll in BravelyMod.dll YamlDotNet.dll; do
    if [[ -f "$SCRIPT_DIR/Mods/$dll" ]]; then
        cp "$SCRIPT_DIR/Mods/$dll" "$MODS_DIR/$dll"
        log "  Installed: $dll"
    else
        err "Missing file: $SCRIPT_DIR/Mods/$dll"
    fi
done

# --- Step 4: Create CustomBGM directory ---

STREAMING_ASSETS="$GAME_DIR/BDFFHD_Data/StreamingAssets"
CUSTOM_BGM="$STREAMING_ASSETS/CustomBGM"

if [[ -d "$STREAMING_ASSETS" ]]; then
    mkdir -p "$CUSTOM_BGM"
    log "CustomBGM directory: $CUSTOM_BGM"
else
    warn "StreamingAssets not found at $STREAMING_ASSETS"
    warn "Custom music directory will be created on first game launch."
fi

# --- Done ---

echo ""
echo "============================================"
echo "  Installation complete!"
echo "============================================"
echo ""
echo "IMPORTANT: Set Steam launch options for BDFFHD:"
echo ""
echo '  WINEDLLOVERRIDES="version=n,b" %command%'
echo ""
echo "  (Right-click BDFFHD in Steam > Properties > General > Launch Options)"
echo ""
echo "First launch:"
echo "  1. Start BDFFHD from Steam"
echo "  2. MelonLoader will generate assemblies (takes a few minutes)"
echo "  3. Once loaded, open http://localhost:8888 for the config UI"
echo ""
echo "To use custom music conversion, run:"
echo "  ./scripts/start_music_server.sh"
echo ""
