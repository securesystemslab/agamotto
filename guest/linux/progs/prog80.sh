#!/bin/bash

# note that modprobe has been executed by top-level agent script (i.e., agent-dev-prog.sh)

echo "$1"

/root/agent-next

while :
do
   echo "modprobe $1"
   timeout 5 modprobe -v $1
   #echo "ifconfig"
   #timeout 5 ifconfig
   echo "modprobe -r -f $1"
   timeout 5 modprobe -r -v -f $1
   echo "next input"
   /root/agent-next
done
