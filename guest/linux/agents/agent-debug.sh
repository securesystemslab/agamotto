#!/bin/bash

echo $1

cat /proc/modules

for mod in $(cat /proc/modules | awk '{print $1}')
do
    for sect_file in /sys/module/$mod/sections/.*
    do
        addr=$(cat $sect_file)
        sect=$(basename $sect_file)
        (echo $mod $sect $addr) | xargs
    done
done

if [ ! -z $NO_SHUTDOWN ]; then # for debugging
    exit 0
fi

echo shutting down...

# Signal VMM to exit
/root/agent-exit 0xdead0000
