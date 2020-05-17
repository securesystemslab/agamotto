#!/usr/bin/env bash

GUEST_CONFIGS=(
	"aqtion"
	"rtl8139"
	"stmmac"
	"snic"
	"usb"
)

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
	echo "Usage: $0 <CONFIG> <KERNEL_SRC_DIR> [<IMAGE_OUT_DIR>]" >&2
	echo "       CONFIG: all ${GUEST_CONFIGS[*]}" >&2
	exit 1
fi

if [ $1 != "all" ]; then
	GUEST_CONFIGS=($1)
fi

KERNEL_SRC_DIR=$2

if [ ! -d $KERNEL_SRC_DIR ]; then
	echo $KERNEL_SRC_DIR does not exist.
	exit 1
fi

if [ $# -eq 3 ]; then
	IMAGE_OUT_DIR=$3
else
	BUILD_DIR=$(dirname $0)/../build
	if [ ! -d $BUILD_DIR ]; then
		echo $BUILD_DIR does not exist.
		exit 1
	fi

	IMAGE_OUT_DIR=$BUILD_DIR/guest/linux/image

	IMAGE_OUT_DIR=$PWD/$IMAGE_OUT_DIR

	if [ ! -d $IMAGE_OUT_DIR ]; then
		echo Creating $IMAGE_OUT_DIR
		mkdir -p $IMAGE_OUT_DIR
	fi
fi

INSTALL_MOD_PATH=$IMAGE_OUT_DIR/modules

pushd $KERNEL_SRC_DIR

set -eux

for config in ${GUEST_CONFIGS[*]}; do
	defconfig=agamotto_${config}_defconfig

	if [ -f arch/x86/configs/$defconfig ]; then
		echo Compiling $defconfig...
		make $defconfig O=$IMAGE_OUT_DIR/$config
		make -j40 O=$IMAGE_OUT_DIR/$config

		if [ $INSTALL_MOD_PATH != "" ]; then
			pushd $IMAGE_OUT_DIR/$config
			make modules_install INSTALL_MOD_PATH=$INSTALL_MOD_PATH
			popd
		fi
	else
		echo $defconfig does not exist. Skipping...
	fi
done

popd
