#!/bin/bash

if ! false ; then
    /root/agent-chkpt
fi

if ! false ; then
    modprobe snic
    # insmod /lib/modules/4.19.0snic+/kernel/drivers/scsi/snic/snic.ko
fi

/root/prog97 snic
