#!/usr/bin/env bash

AFLVER="${AFLVER:-2.52b}"

wget lcamtuf.coredump.cx/afl/releases/afl-$AFLVER.tgz;
tar -xf afl-$AFLVER.tgz;

pushd afl-$AFLVER
# TODO replace it with patch
git init
git add .
git apply ../libafl.patch
popd
