#!/bin/bash

# note that modprobe has been executed by top-level agent script (i.e., agent-dev-prog.sh)

echo "$1"

while :
do
   modprobe $1
   ifconfig eth0
   rmmod -f $1
   /root/agent-next
done
