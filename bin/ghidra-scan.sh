#!/usr/bin/env bash
# Headless Ghidra scan for referenced 0x270F literal-pool sites. No patching.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GHIDRA_HOME="${GHIDRA_HOME:-$HOME/ghidra/ghidra_11.2.1_PUBLIC}"
CODE_BIN="${1:?usage: $0 <code.bin> [out_dir]}"
OUT_DIR="${2:-$ROOT/build/scan}"
PROJECT_NAME="${PROJECT_NAME:-bs-scan}"
IMAGE_BASE="${IMAGE_BASE:-0x00000000}"

if [[ ! -x "$GHIDRA_HOME/support/analyzeHeadless" ]]; then
  echo "ERROR: analyzeHeadless not found at $GHIDRA_HOME/support/analyzeHeadless" >&2
  exit 1
fi
if [[ ! -f "$CODE_BIN" ]]; then
  echo "ERROR: code.bin not found: $CODE_BIN" >&2
  exit 1
fi

mkdir -p "$OUT_DIR/ghidra"
OUT_JSON="$(realpath -m "$OUT_DIR/sites_candidates.json")"
OUT_MD="$(realpath -m "$OUT_DIR/sites_candidates.md")"
CODE_ABS="$(realpath "$CODE_BIN")"

echo "Scanning $CODE_ABS with Ghidra at $GHIDRA_HOME"
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$OUT_DIR/ghidra" "$PROJECT_NAME" \
  -import "$CODE_ABS" \
  -loader BinaryLoader \
  -loader-baseAddr "$IMAGE_BASE" \
  -processor ARM:LE:32:v7 \
  -scriptPath "$ROOT/ghidra_scripts" \
  -overwrite \
  -postScript scan_999k_sites.py "$OUT_JSON" "$OUT_MD"

if [[ ! -f "$OUT_JSON" ]]; then
  echo "ERROR: scan script did not produce $OUT_JSON" >&2
  exit 1
fi
echo "Done. Candidates: $OUT_JSON"
python3 - << PY
import json
p=json.load(open("$OUT_JSON"))
print("Referenced sites: %d (raw hits: %d, datetime-suspect: %d)" % (
    p["nsites_referenced"], p["nraw_hits"], p["ndatetime_suspect"]))
PY
echo "STOP -- review sites before any patch/IPS generation."
