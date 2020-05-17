#!/usr/bin/env bash

if [ $# -ne 3 ]; then
	echo "Usage: $0 <MOD_DIR> <IMG_NAME> <AGENT_SCRIPT>" >&2
	exit 1
fi

MOD_DIR=$1
IMG_NAME=$2
AGENT_SCRIPT=$3

if [ ! -f $IMG_NAME ]; then
	echo "$IMG_NAME does not exist." >&2
	exit 1
fi

if [ ! -d $MOD_DIR ]; then
	echo "$MOD_DIR does not exist." >&2
	exit 1
fi

if [ ! -f $AGENT_SCRIPT ]; then
	echo "$AGENT_SCRIPT does not exist." >&2
	exit 1
fi

set -eux

MNT_DIR=/mnt/${IMG_NAME%.*}
AGENT_SCRIPT_NAME=$(basename $AGENT_SCRIPT)

echo "MOUNT_DIR $MNT_DIR"
echo "AGENT_SCRIPT_NAME $AGENT_SCRIPT_NAME"
sudo mkdir -p $MNT_DIR
sudo mount -o loop $IMG_NAME $MNT_DIR
sudo cp -rd $MOD_DIR/lib/modules/* $MNT_DIR/lib/modules/
sudo cp $AGENT_SCRIPT $MNT_DIR/root/
sudo cp ../guest/linux/agents/generated/agent-* $MNT_DIR/root/
sudo cp ../guest/linux/agents/agent-debug.sh $MNT_DIR/root/debug
sudo chmod +x $MNT_DIR/root/debug
sudo cp ../build/guest/linux/blacklist.conf $MNT_DIR/etc/modprobe.d/
sudo cp ../build/guest/linux/agents/agent-* $MNT_DIR/root/
sudo cp -p ../build/guest/linux/progs/prog* $MNT_DIR/root/
#sudo cp ../build/guest/linux/traces/trace* $MNT_DIR/root/
if [ -d $GOPATH ]; then
	sudo gcc $GOPATH/src/github.com/google/syzkaller/tools/syz-usbgen/keyboard.c -o $MNT_DIR/syz-usbgen-keyboard
	sudo cp -p $GOPATH/src/github.com/google/syzkaller/bin/linux_amd64/syz-* $MNT_DIR/
fi
sudo cp -p ../build/guest/linux/syz/syz-executor $MNT_DIR/syz-executor.debug
sudo chmod +x $MNT_DIR/root/$AGENT_SCRIPT_NAME
sudo find $MNT_DIR/root -name "agent-*.sh" |sudo xargs chmod +x
#sudo cp $RC_LOCAL /mnt/$MNT_DIR/etc/rc.local
echo "#!/bin/sh -e" | sudo tee $MNT_DIR/etc/rc.local
echo "nohup /root/$AGENT_SCRIPT_NAME" | sudo tee -a $MNT_DIR/etc/rc.local
sudo chmod +x $MNT_DIR/etc/rc.local
sudo umount $MNT_DIR
