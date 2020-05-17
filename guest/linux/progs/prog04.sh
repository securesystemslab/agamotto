#!/bin/bash

echo $1

cat /proc/net/wireless

ifconfig

exit_code=$?
if [ $exit_code -ne 0 ]; then
    /root/agent-exit
fi

iwlist scan

exit_code=$?
if [ $exit_code -ne 0 ]; then
    /root/agent-exit
fi

iw dev

exit_code=$?
if [ $exit_code -ne 0 ]; then
    /root/agent-exit
fi
