#!/bin/bash

if ! false ; then
    /root/agent-chkpt
fi

if ! false ; then
    modprobe stmmac-pci
    # insmod /lib/modules/4.19.0stmmac+/kernel/drivers/net/ethernet/stmicro/stmmac/stmmac-pci.ko
fi

/root/prog96 stmmac-pci
