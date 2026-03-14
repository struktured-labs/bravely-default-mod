#!/usr/bin/env bash
# Setup MelonLoader v0.6.6 for BDFFHD (Steam/Proton)
#
# Usage: ./scripts/setup_melonloader.sh [GAME_DIR]
#
# After setup:
#   1. Set Steam launch options: WINEDLLOVERRIDES="version=n,b" %command%
#   2. Launch game once to generate unhollowed assemblies
#   3. Build BravelyMod: dotnet build BravelyMod/
#   4. DLL auto-copies to Mods/ folder

set -euo pipefail

MELON_VERSION="v0.7.2"
MELON_URL="https://github.com/LavaGang/MelonLoader/releases/download/${MELON_VERSION}/MelonLoader.x64.zip"

GAME_DIR="${1:-$HOME/.steam/debian-installation/steamapps/common/BDFFHD}"

if [[ ! -d "$GAME_DIR" ]]; then
    echo "ERROR: Game directory not found: $GAME_DIR"
    echo "Usage: $0 [GAME_DIR]"
    exit 1
fi

if [[ ! -f "$GAME_DIR/BDFFHD.exe" ]]; then
    echo "ERROR: BDFFHD.exe not found in $GAME_DIR"
    exit 1
fi

echo "=== MelonLoader ${MELON_VERSION} Setup for BDFFHD ==="
echo "Game dir: $GAME_DIR"

# Download MelonLoader
TMPDIR="$(dirname "$0")/../tmp"
mkdir -p "$TMPDIR"
MELON_ZIP="$TMPDIR/MelonLoader.x64.zip"

if [[ ! -f "$MELON_ZIP" ]]; then
    echo "Downloading MelonLoader ${MELON_VERSION}..."
    curl -L -o "$MELON_ZIP" "$MELON_URL"
else
    echo "Using cached download: $MELON_ZIP"
fi

# Check if already installed
if [[ -f "$GAME_DIR/version.dll" && -d "$GAME_DIR/MelonLoader" ]]; then
    echo "MelonLoader appears already installed."
    read -p "Reinstall? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Skipping install."
        exit 0
    fi
fi

# Extract to game directory
echo "Extracting to $GAME_DIR..."
unzip -o "$MELON_ZIP" -d "$GAME_DIR"

# Create Mods directory
mkdir -p "$GAME_DIR/Mods"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Set Steam launch options for BDFFHD:"
echo '     WINEDLLOVERRIDES="version=n,b" %command%'
echo ""
echo "  2. Launch the game once. MelonLoader will generate unhollowed assemblies."
echo "     Look for: $GAME_DIR/MelonLoader/Il2CppAssemblies/"
echo ""
echo "  3. Build the mod:"
echo "     cd $(dirname "$0")/.."
echo "     dotnet build BravelyMod/"
echo ""
echo "  4. The mod DLL auto-deploys to $GAME_DIR/Mods/"
echo ""
echo "Hotkeys:"
echo "  F1=1x speed  F2=2x  F3=4x  F4=8x"
echo "  F5=Toggle EXP boost  F6=Toggle damage cap"
