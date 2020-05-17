#!/bin/bash

if ! false ; then
    /root/agent-chkpt
fi

if ! false ; then
    modprobe 8139cp
    # insmod /lib/modules/4.19.0rtl8139+/kernel/drivers/net/ethernet/realtek/8139cp.ko
fi

/root/prog97 8139cp
