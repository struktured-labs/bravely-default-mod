#!/usr/bin/env bash
# convert_music.sh - Convert MP3/WAV/FLAC/OGG audio to HCA for BDFFHD custom music
#
# Usage:
#   ./scripts/convert_music.sh ~/music/my_song.mp3
#   ./scripts/convert_music.sh ~/music/my_song.mp3 my_custom_name
#
# Output:
#   Converts to HCA, copies to StreamingAssets/CustomBGM/, and prints
#   the relative path ready for use in BravelyMod_Music.yaml.
#
# Requirements:
#   - ffmpeg (for audio format conversion)
#   - PyCriCodecs (pip install PyCriCodecs, or install via uv)
#
# The script:
#   1. Converts input audio to WAV (44100 Hz, stereo, 16-bit PCM)
#   2. Encodes WAV to HCA via PyCriCodecs
#   3. Copies HCA to the game's CustomBGM directory
#   4. Prints the relative path for YAML config

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default Steam path for BDFFHD StreamingAssets
STEAM_STREAMING_ASSETS="${BDFFHD_STREAMING_ASSETS:-$HOME/.steam/debian-installation/steamapps/common/BDFFHD/BDFFHD_Data/StreamingAssets}"
CUSTOM_BGM_DIR="$STEAM_STREAMING_ASSETS/CustomBGM"

# Python venv with PyCriCodecs
VENV_DIR="$PROJECT_DIR/.venv"
PYTHON="$VENV_DIR/bin/python3"

# Temp directory (gitignored)
TMP_DIR="$PROJECT_DIR/tmp"

usage() {
    echo "Usage: $0 <audio-file> [output-name]"
    echo ""
    echo "  audio-file   Path to MP3, WAV, FLAC, OGG, or other ffmpeg-supported audio"
    echo "  output-name  Optional output filename (without extension)"
    echo "               Defaults to the input filename with .hca extension"
    echo ""
    echo "Environment variables:"
    echo "  BDFFHD_STREAMING_ASSETS  Override the StreamingAssets path"
    echo "                           Default: ~/.steam/debian-installation/steamapps/common/BDFFHD/BDFFHD_Data/StreamingAssets"
    echo ""
    echo "Examples:"
    echo "  $0 ~/music/my_song.mp3"
    echo "  $0 ~/music/my_song.mp3 custom-battle"
    echo ""
    echo "Output: CustomBGM/my_song.hca  (ready for BravelyMod_Music.yaml)"
    exit 1
}

# --- Argument parsing ---

if [[ $# -lt 1 ]]; then
    usage
fi

INPUT_FILE="$1"
if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Error: Input file not found: $INPUT_FILE" >&2
    exit 1
fi

# Determine output name
INPUT_BASENAME="$(basename "$INPUT_FILE")"
INPUT_NAME="${INPUT_BASENAME%.*}"

if [[ $# -ge 2 ]]; then
    OUTPUT_NAME="$2"
else
    OUTPUT_NAME="$INPUT_NAME"
fi

# Sanitize output name: replace spaces/special chars with hyphens
OUTPUT_NAME="$(echo "$OUTPUT_NAME" | sed 's/[^a-zA-Z0-9._-]/-/g' | sed 's/--*/-/g' | sed 's/^-//' | sed 's/-$//')"

HCA_FILENAME="${OUTPUT_NAME}.hca"

# --- Dependency checks ---

if ! command -v ffmpeg &>/dev/null; then
    echo "Error: ffmpeg is not installed. Install it with: sudo apt install ffmpeg" >&2
    exit 1
fi

if [[ ! -x "$PYTHON" ]]; then
    echo "Error: Python venv not found at $VENV_DIR" >&2
    echo "Set up the project venv: cd $PROJECT_DIR && uv venv && uv pip install PyCriCodecs" >&2
    exit 1
fi

if ! "$PYTHON" -c "import PyCriCodecs" &>/dev/null; then
    echo "Error: PyCriCodecs not installed in venv." >&2
    echo "Install it: cd $PROJECT_DIR && uv pip install PyCriCodecs" >&2
    exit 1
fi

# --- Create directories ---

mkdir -p "$TMP_DIR"
mkdir -p "$CUSTOM_BGM_DIR"

# --- Step 1: Convert to WAV (44100 Hz, stereo, 16-bit PCM) ---

WAV_FILE="$TMP_DIR/${OUTPUT_NAME}.wav"

echo "Converting to WAV (44100 Hz, stereo, 16-bit)..."
# -fflags +bitexact
#     -map_metadata -1 -flags:a +bitexact strips metadata chunks (LIST/INFO)
# that PyCriCodecs cannot parse. Without these flags, ffmpeg adds a Lavf
# software tag that breaks the WAV header parser.
ffmpeg -y -i "$INPUT_FILE" \
    -ar 44100 \
    -ac 2 \
    -sample_fmt s16 \
    -acodec pcm_s16le \
    -fflags +bitexact \
    -map_metadata -1 \
    -flags:a +bitexact \
    "$WAV_FILE" 2>/dev/null

if [[ ! -f "$WAV_FILE" ]]; then
    echo "Error: WAV conversion failed." >&2
    exit 1
fi

echo "  WAV: $WAV_FILE ($(du -h "$WAV_FILE" | cut -f1))"

# --- Step 2: Encode WAV to HCA via PyCriCodecs ---

HCA_FILE="$TMP_DIR/${HCA_FILENAME}"

echo "Encoding WAV to HCA..."
"$PYTHON" - "$WAV_FILE" "$HCA_FILE" <<'PYEOF'
import sys
from PyCriCodecs import HCA

wav_path = sys.argv[1]
hca_path = sys.argv[2]

h = HCA(wav_path)
hca_bytes = h.encode(force_not_looping=True)

with open(hca_path, 'wb') as f:
    f.write(hca_bytes)

info = h.info()
channels = info.get('fmtChannelCount', info.get('channels', '?'))
sample_rate = info.get('fmtSamplingRate', info.get('samplingRate', '?'))
print(f"  HCA info: {channels}ch, {sample_rate} Hz, {len(hca_bytes)} bytes")
PYEOF

if [[ ! -f "$HCA_FILE" ]]; then
    echo "Error: HCA encoding failed." >&2
    exit 1
fi

echo "  HCA: $HCA_FILE ($(du -h "$HCA_FILE" | cut -f1))"

# --- Step 3: Copy to CustomBGM directory ---

DEST_FILE="$CUSTOM_BGM_DIR/$HCA_FILENAME"

echo "Copying to CustomBGM/..."
cp "$HCA_FILE" "$DEST_FILE"

if [[ ! -f "$DEST_FILE" ]]; then
    echo "Error: Failed to copy HCA to $DEST_FILE" >&2
    exit 1
fi

echo "  Installed: $DEST_FILE"

# --- Step 4: Print the relative path for YAML config ---

RELATIVE_PATH="CustomBGM/$HCA_FILENAME"

echo ""
echo "Done! Add this to your BravelyMod_Music.yaml overrides:"
echo ""
echo "  bgmbtl_01: $RELATIVE_PATH"
echo ""
echo "Relative path: $RELATIVE_PATH"
