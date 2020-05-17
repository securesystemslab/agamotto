#!/usr/bin/env bash

if [ $# -ne 3 ]; then
	echo "Usage: $0 <DEV -> rtl8139> <IMG -> stretch_mod.img> <linux -> ../../linux_o_rtl8139_mod>" >&2
	exit 1
fi


DEV=$1
IMG=$2
KERN=$3
OVRLAY=${IMG%.*}
OVRLAY+="_overlay.qcow2"
rm -r out-$DEV
mkdir out-$DEV
rm $OVRLAY
./create-overlay-image.sh $IMG $OVRLAY
echo ./fuzz.py $DEV -k $KERN -d $OVRLAY -i in/
./fuzz.py $DEV -k $KERN -d $OVRLAY -i in/
