#!/bin/bash

# note that modprobe has been executed by top-level agent script (i.e., agent-dev-prog.sh)

echo $1

ifconfig eth0

exit_code=$?
if [ $exit_code -ne 0 ]; then
    /root/agent-exit
fi

ethtool eth0

exit_code=$?
if [ $exit_code -ne 0 ]; then
    /root/agent-exit
fi

ethtool -t eth0

exit_code=$?
if [ $exit_code -ne 0 ]; then
    /root/agent-exit
fi
