#!/bin/bash
#
# This file is a modified version of create-image.sh found in the syzkaller repository.
#

set -eux

# Create a minimal Debian distribution in a directory.
DIR=chroot

# Variables affected by options
RELEASE=stretch
FEATURE=minimal

display_help() {
	echo "Usage: $0 [option...] " >&2
	echo
	echo "   -d, --distribution         Set on which debian distribution to create"
	echo "   -m, --modules              Directory of linux kernel modules (make modules_install INSTALL_MOD_PATH=<..>"
	echo "   -f, --feature              Check what packages to install in the image, options are minimal, full"
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
		-d | --distribution)
			RELEASE=$2
			shift 2
			;;
		-f | --feature)
			FEATURE=$2
			shift 2
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

ADD_PACKAGE=",firmware-brcm80211,firmware-iwlwifi,firmware-atheros,firmware-qlogic,firmware-realtek,firmware-ralink,firmware-libertas,firmware-adi,firmware-misc-nonfree,firmware-linux,pciutils,net-tools,wireless-tools,wireless-regdb"

IMAGE_NAME="$RELEASE"

if [ $FEATURE = "full" ]; then
	ADD_PACKAGE=$ADD_PACKAGE",make,sysbench,git,vim,tmux,usbutils"
fi

ADD_PACKAGE=$ADD_PACKAGE",gdb"
ADD_PACKAGE=$ADD_PACKAGE",lsof"
ADD_PACKAGE=$ADD_PACKAGE",ethtool"
ADD_PACKAGE=$ADD_PACKAGE",i2c-tools"
ADD_PACKAGE=$ADD_PACKAGE",neard-tools"
ADD_PACKAGE=$ADD_PACKAGE",usbutils"

if [ -d $DIR ]; then
	echo $DIR already exists.
	exit
fi

mkdir -p $DIR
sudo debootstrap --components=main,contrib,non-free --include=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc"$ADD_PACKAGE" $RELEASE $DIR

# Set some defaults and enable promtless ssh to the machine for root.
sudo sed -i '/^root/ { s/:x:/::/ }' $DIR/etc/passwd
echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a $DIR/etc/inittab
printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a $DIR/etc/network/interfaces
echo '/dev/root / ext4 defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'securityfs /sys/kernel/security securityfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
#echo 'configfs /sys/kernel/config/ configfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo "kernel.printk = 7 4 1 3" | sudo tee -a $DIR/etc/sysctl.conf
echo 'debug.exception-trace = 0' | sudo tee -a $DIR/etc/sysctl.conf
echo "net.core.bpf_jit_enable = 1" | sudo tee -a $DIR/etc/sysctl.conf
echo "net.core.bpf_jit_kallsyms = 1" | sudo tee -a $DIR/etc/sysctl.conf
echo "net.core.bpf_jit_harden = 0" | sudo tee -a $DIR/etc/sysctl.conf
echo "kernel.softlockup_all_cpu_backtrace = 1" | sudo tee -a $DIR/etc/sysctl.conf
echo "kernel.kptr_restrict = 0" | sudo tee -a $DIR/etc/sysctl.conf
echo "kernel.watchdog_thresh = 60" | sudo tee -a $DIR/etc/sysctl.conf
echo "net.ipv4.ping_group_range = 0 65535" | sudo tee -a $DIR/etc/sysctl.conf
echo -en "127.0.0.1\tlocalhost\n" | sudo tee $DIR/etc/hosts
echo "nameserver 8.8.8.8" | sudo tee -a $DIR/etc/resolve.conf
echo "agamotto" | sudo tee $DIR/etc/hostname
ssh-keygen -f $IMAGE_NAME.id_rsa -t rsa -N ''
sudo mkdir -p $DIR/root/.ssh/
sudo mkdir -p $DIR/lib/modules/
cat $IMAGE_NAME.id_rsa.pub | sudo tee $DIR/root/.ssh/authorized_keys

# Build a disk image
./build-image.sh $DIR $IMAGE_NAME.img
