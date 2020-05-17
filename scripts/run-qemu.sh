#!/usr/bin/env bash

display_help() {
	echo "Usage: $0 [option...] " >&2
	echo
	echo "   -k, --kernel-root-dir      Linux kernel root directory"
	echo "   -w, --windows              Boot Windows"
	echo "   -g, --graphic              Remove -nographic"
	echo "   -d, --drive-img-file       System image file"
	echo "   -l, --load-vm              VM snapshot to load"
	echo "   -s, --monitor-to-socket    Open monitor as a Unix socket"
	echo "   -m, --monitor              Open monitor"
	echo "   -f, --serial-to-file       A file to redirect serial output to"
	echo "   -q, --normal-qemu          Normal QEMU mode w/o fuzzing enabled"
	echo "   -t, --trace                QEMU's --trace; consult QEMU for detail"
	echo "   -c, --coverage             Comma separated list of corpus files/dirs"
	echo "   -n, --nic                  Attach a NIC"
	echo "   -p, --pseudo-device        Pseudo device for direct communication w/ guest kernel"
	echo "   -V, --vendor-id            Vendor ID"
	echo "   -D, --device-id            Device ID"
	echo "   -R, --revision-id          Revision ID"
	echo "   -C, --class-id             Class ID"
	echo "   -SV, --subsystem-vendor-id Subsystem Vendor ID"
	echo "   -SD, --subsystem-id        Subsystem ID"
	echo "   -se, --seed                AFL Seed"
	echo "   -ro, --root-only           Create only root checkpoint"
	echo "   -IO                        I/O mapping descriptions"
	echo "   -IOMMU                     Enable I/OMMU"
	echo "   -I, --fuzzer-in-dir        A path to fuzzer input seed directory"
	echo "   -F, --fuzzer-out-file      A path to fuzzer out file"
	echo "   -O, --fuzzer-out-dir       A path to fuzzer out directory"
	echo "   -M, --master-id            ID for master fuzzer instance"
	echo "   -S, --secondary-id         ID for secondary fuzzer instance"
	echo "   -x, --exec-input-file      Path to an input file to execute"
	echo "   -X, --fuzzer-dict-dir      Path the afl dictionary"
	echo "   -GDB, --gdb                GDB debug"
	echo "   -- ...                     Additional QEMU options"
	echo "   -h, --help                 Display help message"
	echo
}

while true; do
	if [ $# -eq 0 ];then
		echo $#
		break
	fi
	case "$1" in
		-h | --help)
			display_help
			exit 0
			;;
		-k | --kernel-root-dir)
			KERNEL_ROOT_DIR=$2
			shift 2
			;;
		-w | --windows)
			WINDOWS=1
			shift 1
			;;
		-g | --graphic)
			GRAPHIC=1
			shift 1
			;;
		-d | --drive-img-file)
			DRIVE_IMG_FILE=$2
			shift 2
			;;
		-l | --load-vm)
			LOADVM=$2
			shift 2
			;;
		-s | --monitor-to-socket)
			MONITOR_TO_SOCKET=$2
			shift 2
			;;
		-m | --monitor)
			MONITOR=$2
			shift 2
			;;
		-f | --serial-to-file)
			SERIAL_TO_FILE=$2
			shift 2
			;;
		-q | --normal-qemu)
			NORMAL_QEMU=1
			shift 1
			;;
		-t | --trace)
			TRACE=$2
			shift 2
			;;
		-c | --coverage)
			CORPUS_FILES=$2
			shift 2
			;;
		-n | --nic)
			NIC=1
			shift 1
			;;
		-p | --pseudo-device)
			PSEUDO_DEVICE=kcov_vdev
			shift 1
			;;
		-V | --vendor-id)
			VENDOR_ID=$2
			shift 2
			;;
		-D | --device-id)
			DEVICE_ID=$2
			shift 2
			;;
		-R | --revision-id)
			REVISION_ID=$2
			shift 2
			;;
		-C | --class-id)
			CLASS_ID=$2
			shift 2
			;;
		-SV | --subsystem-vendor-id)
			SUBSYSTEM_VENDOR_ID=$2
			shift 2
			;;
		-SD | --subsystem-id)
			SUBSYSTEM_ID=$2
			shift 2
			;;
		-se | --seed)
			AFL_SEED=$2
			shift 2
			;;
		-nr | --no-restore)
			NO_RESTORE=1
			shift 1
			;;
		-ro | --root-only)
			ROOT_ONLY_CHKPT=1
			shift 1
			;;
		-IO)
			IO_MEMORY_DESC=$2
			shift 2
			;;
		-IOMMU)
			IOMMU=true
			shift 1
			;;
		-I | --fuzzer-in-dir)
			FUZZER_IN_DIR=$2
			shift 2
			;;
		-X | --fuzzer-dict-dir)
			FUZZER_DICT_DIR=$2
			shift 2
			;;
		-F | --fuzzer-out-file)
			FUZZER_OUT_FILE=$2
			shift 2
			;;
		-O | --fuzzer-out-dir)
			FUZZER_OUT_DIR=$2
			shift 2
			;;
		-G | --guest-agent-id)
			GUEST_AGENT_ID=$2
			shift 2
			;;
		-M | --master-id)
			MASTER_ID=$2
			shift 2
			;;
		-S | --secondary-id)
			SECONDARY_ID=$2
			shift 2
			;;
		-x | --exec-input-file)
			EXEC_FILE=$2
			shift 2
			;;
		-T | --test-print-only)
			PRINT_ONLY=1
			shift 1
			;;
		-GDB | --gdb)
			GDB=1
			shift 1
			;;
		--)
			ADDITIONAL_ARGS=${@:2}
			break
			;;
		-*)
			echo "Error: Unknown option: $1" >&2
			exit 1
			;;
		*)  # No more options
			break
			;;
	esac
done


if [ ! -z $WINDOWS ]; then
	echo "Booting Windows..."
	GRAPHIC=1
elif [ ! -d $KERNEL_ROOT_DIR ]; then
	echo "--kernel-root-dir invalid." >&2
else
	KERNEL_IMG_FILE=$KERNEL_ROOT_DIR/arch/x86/boot/bzImage
fi

BASE_DIR=$(dirname "$0")/..

LIBAGAMOTTO=$BASE_DIR/build/libagamotto/libagamotto.so

if [ ! -f $DRIVE_IMG_FILE ]; then
	DRIVE_IMG_FILE=$BASE_DIR/scripts/stretch.img
	echo "--drive-img-file invalid." >&2
	exit 1
fi

QEMU=`which qemu-system-x86_64`

if [ ! -f $QEMU ]; then
	echo qemu not found.
	exit 1
fi

if [ ! -z $FUZZER_IN_DIR ]; then
	if [ ! -d $FUZZER_IN_DIR ]; then
		echo $FUZZER_IN_DIR not found.
		exit 1
	fi
	export __PERISCOPE_IN_DIR=$FUZZER_IN_DIR
fi

if [ ! -z $FUZZER_DICT_DIR ]; then
	if [ ! -d $FUZZER_DICT_DIR ]; then
		echo $FUZZER_DICT_DIR not found.
		exit 1
	fi
	export __PERISCOPE_DICT_DIR=$FUZZER_DICT_DIR
fi

if [ ! -z $FUZZER_OUT_FILE ]; then
	if [ -f $FUZZER_OUT_FILE ]; then
		echo $FUZZER_OUT_FILE will be overwritten.
	fi
	export __PERISCOPE_OUT_FILE=$FUZZER_OUT_FILE
fi

if [ ! -z $FUZZER_OUT_DIR ]; then
	if [ -d $FUZZER_OUT_DIR ]; then
		echo $FUZZER_OUT_DIR will be reused.
	fi
	export __PERISCOPE_OUT_DIR=$FUZZER_OUT_DIR
fi

if [ ! -z $MASTER_ID ]; then
	export __PERISCOPE_MASTER_ID=$MASTER_ID
fi

if [ ! -z $SECONDARY_ID ]; then
	export __PERISCOPE_SECONDARY_ID=$SECONDARY_ID
fi

if [ ! -z $AFL_SEED ]; then
	export __PERISCOPE_AFL_SEED=$AFL_SEED
fi
if [ ! -z $ROOT_ONLY_CHKPT ]; then
	export __PERISCOPE_ROOT_ONLY_CHKPT="root_only"
fi
if [ ! -z $NO_RESTORE ]; then
	export __PERISCOPE_NO_RESTORE="no_restore"
fi

echo
echo Using $QEMU...
echo

sleep 0.5

QEMU_CMD=""
QEMU_CMD+=" -smp 1"
QEMU_CMD+=" -net none"

if [ ! -z $IOMMU ]; then
	QEMU_CMD+=" -machine q35,accel=kvm"
else
	QEMU_CMD+=" -cpu host"
fi
QEMU_CMD+=" -nodefaults"

if [ ! -z $WINDOWS ]; then
	QEMU_CMD+=" -m 4G"
else
	QEMU_CMD+=" -m 512M"
fi

if [ ! -z $KERNEL_IMG_FILE ]; then
	QEMU_CMD+=" -kernel $KERNEL_IMG_FILE"
fi

if [ ! -z $WINDOWS ]; then
	QEMU_CMD+=" -drive driver=qcow2,file=$DRIVE_IMG_FILE,if=virtio"
	QEMU_CMD+=" -drive file=virtio-win.iso,index=3,media=cdrom"
else
	QEMU_CMD+=" -hda $DRIVE_IMG_FILE"
fi

if [ -z $GRAPHIC ]; then
	QEMU_CMD+=" -nographic"
fi

QEMU_CMD+=" -enable-kvm"

if [ ! -z $NIC ]; then
	QEMU_CMD+=" -net nic -net user,hostfwd=tcp:127.0.0.1:11023-:23456,hostfwd=tcp:127.0.0.1:11022-:22"
	#QEMU_CMD+=" -net nic"
fi

if [ ! -z $CORPUS_FILES ]; then
	QEMU_CMD+=" -device $PSEUDO_DEVICE,trace-pc=on"
else
	if [ ! -z $PSEUDO_DEVICE ]; then
		QEMU_CMD+=" -device $PSEUDO_DEVICE"
	fi
fi

## SD Card or SDIO?
#QEMU_CMD+=" -device sdhci-pci,id=sdhci0"
#QEMU_CMD+=" -device generic-sdhci,id=sdhci0" # gives an error

#QEMU_CMD+=" -usb"
#QEMU_CMD+=" -device usb-periscope"

## I2C or SMBus
#QEMU_CMD+=" -device periscope-pci-i2c"
#QEMU_CMD+=" -device periscope-i2c,address=0x30"

DEVICE_NAME="periscope" # our exploratory device

if [ ! -z $DEVICE_ID && [ "$DEVICE_ID" != "0x"* ] ]; then
	DEVICE_FOUND=$($QEMU -device ? | grep name | awk -F", " "{print \$1}" | awk "{print \$2}" | grep \"$DEVICE_ID\")
	if [ ! -z $DEVICE_FOUND ]; then
		LIBAGAMOTTO=
		DEVICE_NAME=$DEVICE_ID # existing emulated device
	else
		echo No emulated device \"$DEVICE_ID\" found.
		echo
		exit 1
	fi
fi

if [ ! -z $IOMMU ]; then
	QEMU_CMD+=" -device ioh3420,id=pcie.0,chassis=1"
	QEMU_CMD+=" -device $DEVICE_NAME,bus=pcie.0"
elif [ ! -z $DEVICE_NAME ]; then
	QEMU_CMD+=" -device $DEVICE_NAME"
fi

# XXX uncomment for kvm api test
#QEMU_CMD+=" -device kvm_api_test"

# QCA6174
if [ -z $VENDOR_ID ]; then
	VENDOR_ID=0x168c
fi
if [ -z $DEVICE_ID ]; then
	DEVICE_ID=0x3e
fi
if [ -z $REVISION_ID ]; then
	REVISION_ID=0x20
fi
if [ -z $CLASS_ID ]; then
	CLASS_ID=0x0280
fi
if [ -z $SUBSYSTEM_VENDOR_ID ]; then
	SUBSYSTEM_VENDOR_ID=0x0
fi
if [ -z $SUBSYSTEM_ID ]; then
	SUBSYSTEM_ID=0x0
fi

if [ -z $GUEST_AGENT_ID ]; then
	GUEST_AGENT_ID="3735928559" # 0xDEADBEEF
fi

QEMU_CMD+=" -periscope"
QEMU_CMD+=" vendor=$VENDOR_ID,device=$DEVICE_ID,revision=$REVISION_ID,class=$CLASS_ID"
QEMU_CMD+=",subsystem_vendor_id=$SUBSYSTEM_VENDOR_ID,subsystem_id=$SUBSYSTEM_ID"

if [ ! -z $IO_MEMORY_DESC ]; then
	QEMU_CMD+=",$IO_MEMORY_DESC"
fi

if [ ! -z $CORPUS_FILES ]; then
	LIBAGAMOTTO=
	QEMU_CMD+=" -fuzzer kcov:$GUEST_AGENT_ID,$CORPUS_FILES"
elif [ ! -z $EXEC_FILE ]; then
	LIBAGAMOTTO=
	QEMU_CMD+=" -fuzzer exec:$GUEST_AGENT_ID,$EXEC_FILE"
elif [ ! -z $NORMAL_QEMU ]; then
	LIBAGAMOTTO=
	QEMU_CMD+=" -fuzzer none:$GUEST_AGENT_ID"
else
	export __PERISCOPE_GUEST_AGENT_ID=$GUEST_AGENT_ID
fi

export __PERISCOPE_CHKPT_POOL_SIZE=12288

QEMU_CMD_KERNEL_APPEND="console=ttyS0 root=/dev/sda debug earlyprintk=serial slub_debug=QUZ net.ifnames=0 nokaslr"
if [ ! -z $IOMMU ]; then
	QEMU_CMD_KERNEL_APPEND+=" intel_iommu=strict"
fi
QEMU_CMD_KERNEL_DYNDBG_APPEND="file kernel/module.c +p;"
QEMU_CMD_KERNEL_DYNDBG_APPEND+=" module 8139too +p;"
QEMU_CMD_KERNEL_DYNDBG_APPEND+=" module 8139cp +p;"
QEMU_CMD_KERNEL_DYNDBG_APPEND+=" module vmxnet3 +p;"
QEMU_CMD_KERNEL_DYNDBG_APPEND+=" module ne2k-pci +p;"
QEMU_CMD_KERNEL_APPEND+=" dyndbg=\"$QEMU_CMD_KERNEL_DYNDBG_APPEND\""

if [ ! -z $IOMMU ]; then
	QEMU_CMD+=" -device intel-iommu,caching-mode=true"
fi

if [ ! -f $MONITOR_TO_SOCKET ]; then
	QEMU_CMD+=" -monitor unix:$MONITOR_TO_SOCKET,server,nowait"
else
	if [ -z $MONITOR ]; then
		QEMU_CMD+=" -monitor null"
	else
		QEMU_CMD+=" -monitor $MONITOR"
	fi
fi

if [ ! -z $SERIAL_TO_FILE ]; then
	QEMU_CMD+=" -serial file:$SERIAL_TO_FILE"
fi

if [ ! -z $TRACE ]; then
	QEMU_CMD+=" --trace $TRACE"
fi

QEMU_CMD+=" "$ADDITIONAL_ARGS

if [ ! -z $LOADVM ]; then
	echo Restoring $LOADVM...
	QEMU_CMD+=" -loadvm $LOADVM"
fi

QEMU_CMD+=" -snapshot"

if [ -z $PID_FILE ]; then
	PID_FILE=vm.pid

	if [ ! -z $MASTER_ID ]; then
		PID_FILE=vm-$MASTER_ID.pid
	fi

	if [ ! -z $SECONDARY_ID ]; then
		PID_FILE=vm-$SECONDARY_ID.pid
	fi
fi

echo $QEMU $QEMU_CMD

if [ ! -z $PRINT_ONLY ]; then
	echo LD_PRELOAD=$LIBAGAMOTTO ${QEMU} ${QEMU_CMD} -append "$QEMU_CMD_KERNEL_APPEND"
	exit 0
fi

if [ ! -z $WINDOWS ]; then
	set -eux

	LD_PRELOAD=$LIBAGAMOTTO ${QEMU} ${QEMU_CMD} \
		-usb -device usb-tablet
else
	if [ ! -z $GDB ]; then
		echo set startup-with-shell off | tee /tmp/gdb.cmd
		echo set exec-wrapper env LD_PRELOAD=${LIBAGAMOTTO} | tee -a /tmp/gdb.cmd
		# echo b blockdev.c:933 | tee -a /tmp/gdb.cmd
		echo run ${QEMU_CMD} -append "$QEMU_CMD_KERNEL_APPEND" | tee -a /tmp/gdb.cmd

		gdb ${QEMU} -x /tmp/gdb.cmd
		exit 0
	fi

	set -eux
	LD_PRELOAD=$LIBAGAMOTTO ${QEMU} ${QEMU_CMD} \
		-append "$QEMU_CMD_KERNEL_APPEND"
fi
