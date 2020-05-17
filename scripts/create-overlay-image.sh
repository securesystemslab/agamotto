#!/usr/bin/env bash

if [ "$#" -ne 2 ] || ! [ -f "$1" ]; then
	echo "Usage: $0 BASE_IMG_FILE OVERLAY_IMG_FILE" >&2
	exit 1
fi

BASE_IMG_FILE=$1
OVERLAY_IMG_FILE=$2

if [ -f "$OVERLAY_IMG_FILE" ]; then
	echo $OVERLAY_IMG_FILE already exists. >&2
	exit 1
fi

qemu-img create -f qcow2 $OVERLAY_IMG_FILE 2G -b $BASE_IMG_FILE -F raw
