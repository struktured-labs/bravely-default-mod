#!/bin/bash
set -ex
GHIDRA_HOME=${GHIDRA_HOME:-"$PWD/ghidra"}
QUALIFIER=${QUALIFIER:-"dev"}

BUILD_DIR=${BUILD_DIR:-"build"}

CODE_BIN=${BUILD_DIR}/${QUALIFIER}/cxi/exefs_dir/code.bin

PROJECT_DIR=${BUILD_DIR}/${QUALIFIER}/ghidra
PROJECT_NAME=${PROJECT_NAME:-"bd-${QUALIFIER}"}

 # -loader-option IMAGE_BASE=0x00100000 \

if [[ ! -x "$GHIDRA_HOME/support/analyzeHeadless" ]]; then
  echo "Ghidra not found in $GHIDRA_HOME; attempting automatic setup..."
  bash bin/setup_ghidra.sh
fi

mkdir -p "$PROJECT_DIR"
echo "Running headless Ghidra patch for $PROJECT_NAME from $CODE_BIN"
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -import "$CODE_BIN" \
  -scriptPath ghidra_scripts \
  -processor ARM:LE:32:v7 \
  -postScript 999k-limit-patch.py