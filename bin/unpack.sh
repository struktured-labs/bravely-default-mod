#!/bin/bash

set -ex
# pipefail

if [[ $# -ne 2 ]]; then
  echo "Unpacks a bravely default CIA file using both ctrtool and 3dstool into a given output directory."
  echo "Usage: $0 <cia> <input_file.cia> <output_dir>"
  exit 1
fi


CTR_TOOL=${CRT_TOOL:-"../../Project_CTR/ctrtool/bin/ctrtool"}
_3DS_TOOL=${_3DS_TOOL:-"../../3dstool/bin/3dstool"}
CIA=`realpath -q $1`

if [[ ! -f "$CIA" ]]; then
  echo Bravely Default CIA file $CIA not found.
  exit 1
fi

QUALIFIER=$2
OUTDIR=$QUALIFIER
mkdir -p $OUTDIR


pushd $OUTDIR

mkdir -p cxi
echo "[1] Extracting CIA with ctrtool to $QUALIFIER"
$CTR_TOOL --contents="content.0000.cxi" --exefs=cxi/exefs.bin --romfs=cxi/romfs.bin \
  --exefsdir=cxi/exefs_dir --romfsdir=cxi/romfs_dir --exheader=cxi/exheader.bin $CIA

echo "[2] Extracting CXI contents with 3dstool..."
mkdir -p "cxi/exefs_dir"

FILE=`ls content*|sort|head -n1`
echo File is "$FILE" 
$_3DS_TOOL -x \
  -t cxi \
  --file "$FILE" \
  --header "cxi/header.bin" \
  --exefs "cxi/exefs.bin" \
  --exefs-dir "cxi/exefs_dir" \
  --romfs "cxi/romfs.bin" \
  --logo "cxi/logo.bin" \
  --plain "cxi/plain.bin"
#  --accessdesc "/cxi/accessdesc.bin"

echo ""
echo "✅ Extraction complete."
tree -L 3 cxi 
popd

