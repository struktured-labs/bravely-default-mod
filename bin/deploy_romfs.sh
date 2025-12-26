#!/bin/bash

set -ex

VERSION=${VERSION:-"00040000000FC500"}
QUALIFIER=${QUALIFIER:-"dev"}
ROMFS_DIR=${ROMFS_DIR:-"build/crowd-${QUALIFIER}-packed/${VERSION}/romfs"}
# Respect provided CITRA_DIR, otherwise default to user's HOME
CITRA_DIR=${CITRA_DIR:-"$HOME/.local/share/citra-emu"}
BACKUP=`date +%Y%m%d_%H%M%S`

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

set +e
mkdir -p $TO
set -e
echo "Backing up original romfs"
if [ -d "$TO" ]; then
  cp -r -v "$TO" "$BACKUP_DIR/romfs_dir.$BACKUP.bak"
else
  echo "No existing romfs to backup at $TO"
fi


echo "Deploying new romfs"
# Pack step outputs directly under .../<TITLEID>/romfs, not cxi/romfs_dir
cp -r -v "$FROM"/* "$TO"
