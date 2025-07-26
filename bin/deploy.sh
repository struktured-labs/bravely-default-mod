#!/bin/bash

set -ex

QUALIFIER=${QUALIFIER:-"dev"}
EXEFS_DIR=${EXEFS_DIR:-"build/crowd-${QUALIFIER}-unpacked/cxi/exefs_dir"}
CITRA_DIR=${CITRA_DIR:=$HOME/.local/share/citra-emu}
BACKUP=`date +%Y%m%d_%H%M%S`
VERSION=${VERSION:-"00040000000FC500"}

BACKUP_DIR=${BACKUP_DIR:-"build/$QUALIFIER/backup"}


FROM=$1
TO=${2:-"${CITRA_DIR}/load/mods/${VERSION}/exefs/code.bin"}


mkdir -p $BACKUP_DIR

if [[ -z "$FROM" ]]; then
  FROM=$EXEFS_DIR/code.bin
  echo Using default from $FROM
else
  echo Using given from $FROM
fi

echo "Backing up original code.bin"
cp -v $TO $BACKUP_DIR/code.bin.$BACKUP.bak

echo "Deploying new code.bin"
cp -v $FROM $TO

