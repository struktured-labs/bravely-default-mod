#!/bin/bash

set -ex

QUALIFIER=${QUALIFIER:-"dev"}
ROMFS_DIR=${ROMFS_DIR:-"build/crowd-${QUALIFIER}-packed/cxi/romfs_dir"}
CITRA_DIR=${CITRA_DIR:=$HOME/.local/share/citra-emu}
BACKUP=`date +%Y%m%d_%H%M%S`
VERSION=${VERSION:-"00040000000FC500"}

BACKUP_DIR=${BACKUP_DIR:-"build/$QUALIFIER/backup"}

FROM=$1
TO=${2:-"${CITRA_DIR}/load/mods/${VERSION}/romfs"}

mkdir -p $BACKUP_DIR

if [[ -z "$FROM" ]]; then
  FROM=$ROMFS_DIR
  echo Using default from $FROM
else
  echo Using given from $FROM
fi
mkdir -p $TO

echo "Backing up original romfs"
cp -r -v $TO $BACKUP_DIR/romfs_dir.$BACKUP.bak


echo "Deploying new romfs"
cp -r -v $FROM/* $TO
