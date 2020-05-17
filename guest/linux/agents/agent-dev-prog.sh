#!/bin/bash

if ! ${skip_root_chkpt} ; then
    /root/agent-chkpt
fi

if ! ${skip_modprobe} ; then
    modprobe ${module}
    # insmod /lib/modules/4.19.0${image}+/kernel/${module_relpath}
fi

/root/${prog} ${module}
