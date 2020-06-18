# Agamotto: Accelerating Kernel Driver Fuzzing with Lightweight Virtual Machine Checkpoints

## Prerequisite

- CMake 3.7.2 or higher (`cmake -version`)
- Go 1.12.3 or higher (`go version`)
- Python 3


## Setup

### Download source code

```bash
git clone --recursive https://github.com/securesystemslab/agamotto.git
cd agamotto
export AGPATH=$PWD # assumed by commands that follow
./setup.sh
```


### Change the host Linux kernel for custom hypercall support

Build the host Linux kernel with [our patch](host/linux/kernel.patch) applied, and with `CONFIG_KVM_AGAMOTTO=y`, and install & reboot it.

#### Tested environment:
- [Ubuntu-hwe-4.18.0-18.19_18.04.1](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/bionic) on AMD EPYC 7601


### Download and build Syzkaller

```bash
# Get Syzkaller source code
go get -u -d github.com/google/syzkaller
cd $GOPATH/src/github.com/google/syzkaller
git checkout ddc3e85997efdad885e208db6a98bca86e5dd52f

# Apply patch and build
cd $GOPATH/src/github.com/google/syzkaller
patch -p0 <$AGPATH/syzkaller.patch
make
```


### Build project and generate necessary files

```bash
# Build project
cd $AGPATH/build
cmake ..
make
```


### Setup QEMU

```bash
# Apply patch
cd $AGPATH/qemu
patch -p0 <$AGPATH/qemu.patch

# Build
mkdir $AGPATH/build/qemu
cd $AGPATH/build/qemu
$AGPATH/qemu/configure --prefix=$AGPATH/build/qemu/install --target-list=x86_64-softmmu --with-agamotto=$AGPATH/build/libagamotto --enable-debug
make -j4 install
```


### Setup VM

- Patch and build Linux kernel
  ```bash
  cd $AGPATH/guest/linux/kernel
  patch -p0 <../kernel.patch
  ```

  ```bash
  cd $AGPATH/scripts
  ./build-linux-guest.sh all ../guest/linux/kernel/
  ```

- Create a Debian image
  ```bash
  cd $AGPATH/scripts
  ./create-debian-image.sh             # Create an image
  ./copy-modules.py all -d stretch.img # Copy necessary files into the image
  ```


### Start fuzzing

```bash
# Generate Syzkaller config files
cd $AGPATH
make -C configs/syzkaller VMCNT=<number of fuzzing instances> -B

# Run Syzkaller USB fuzzing
cd $GOPATH/src/github.com/google/syzkaller
export PATH=$AGPATH/build/qemu/install/bin:$PATH
export LD_LIBRARY_PATH=$AGPATH/build/libagamotto:$LD_LIBRARY_PATH
./bin/syz-manager -config $AGPATH/configs/syzkaller/generated/<CFG_FILE>.cfg
```

```bash
# Run AFL PCI fuzzing
cd $AGPATH/scripts
./create-overlay-image.py rtl8139 -d stretch.img
export PATH=$AGPATH/build/qemu/install/bin:$PATH
export LD_LIBRARY_PATH=$AGPATH/build/libagamotto:$LD_LIBRARY_PATH
./fuzz.py rtl8139 -g linux-prog05 -i seed/ -N <number of fuzzing instances>
```

## Citing our work

```
@inproceedings{song2020agamotto,
  title =        {{Agamotto}: Accelerating Kernel Driver Fuzzing with
                  Lightweight Virtual Machine Checkpoints},
  author =       {Song, Dokyung and Hetzelt, Felicitas and Kim, Jonghwan and
                  Kang, Brent Byunghoon and Seifert, Jean-Pierre and Franz,
                  Michael},
  booktitle =    {{USENIX} Security Symposium},
  year =         {2020}
}
```
