#!/bin/bash

if ! false ; then
    /root/agent-chkpt
fi

if ! false ; then
    modprobe atlantic
    # insmod /lib/modules/4.19.0aqtion+/kernel/drivers/net/ethernet/aquantia/atlantic/atlantic.ko
fi

/root/prog02 atlantic
