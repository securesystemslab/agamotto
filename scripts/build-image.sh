#!/usr/bin/env bash

if [ $# -ne 2 ]; then
	echo "Usage: $0 <DIR> <IMG>" >&2
	exit 1
fi

OUT_IMG=$2
DIR=$1

if [ -f $OUT_IMG ]; then
	echo "$OUT_IMG already exists." >&2
	exit 1
fi

if [ ! -d $DIR ]; then
	echo "$DIR does not exist." >&2
	exit 1
fi

set -eux

dd if=/dev/zero of=$OUT_IMG bs=1M seek=2047 count=1
sudo mkfs.ext4 -F $OUT_IMG
sudo mkdir -p /mnt/$DIR
sudo mount -o loop $OUT_IMG /mnt/$DIR
sudo cp -a $DIR/. /mnt/$DIR/.
sudo umount /mnt/$DIR
