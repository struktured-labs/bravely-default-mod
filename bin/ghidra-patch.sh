#!/bin/bash
set -ex
GHIDRA_HOME=${GHIDRA_HOME:-"$HOME/ghidra/build/dist/ghidra_11.4_DEV"}
QUALIFIER=${QUALIFIER:-"dev"}

BUILD_DIR=${BUILD_DIR:-"build"}

CODE_BIN=${BUILD_DIR}/${QUALIFIER}/cxi/exefs_dir/code.bin

PROJECT_DIR=${BUILD_DIR}/${QUALIFIER}/ghidra
PROJECT_NAME=${PROJECT_NAME:-"bd-${QUALIFIER}"}

 # -loader-option IMAGE_BASE=0x00100000 \

# Look for existing Ghidra program file in project
#if find "$PROJECT_DIR" -name "$PROJECT_NAME.gpr" | grep -q .; then
#  echo "✅ Program already in project — skipping import."
#  ${GHIDRA_HOME}/support/analyzeHeadless \
#    $PROJECT_DIR $PROJECT_NAME \
#    -process "code.bin" \
#    -scriptPath ghidra_scripts \
#    -processor ARM:LE:32:v7 \
#    -postScript 999k-limit-patch.py
#else
  mkdir -p $PROJECT_DIR
  echo "📥 Importing new program...  for $PROJECT_NAME from $CODE_BIN"
  ${GHIDRA_HOME}/support/analyzeHeadless \
    $PROJECT_DIR $PROJECT_NAME \
    -import $CODE_BIN \
    -scriptPath ghidra_scripts \
    -processor ARM:LE:32:v7 \
    -postScript 999k-limit-patch.py
#fi