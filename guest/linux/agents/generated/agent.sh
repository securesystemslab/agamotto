#!/bin/bash

id=$(/root/agent-get-prog)

progs=(
    "agent-aqc100-debug.sh" # 0
    "agent-aqc100-prog01.sh" # 1
    "agent-aqc100-prog02.sh" # 2
    "agent-aqc100-prog03.sh" # 3
    "agent-aqc100-prog04.sh" # 4
    "agent-aqc100-prog05.sh" # 5
    "agent-aqc100-prog80.sh" # 6
    "agent-aqc100-prog81.sh" # 7
    "agent-aqc100-prog96.sh" # 8
    "agent-aqc100-prog97.sh" # 9
    "agent-aqc100-prog98.sh" # 10
    "agent-aqc100-prog99.sh" # 11
    "agent-quark-debug.sh" # 12
    "agent-quark-prog01.sh" # 13
    "agent-quark-prog02.sh" # 14
    "agent-quark-prog03.sh" # 15
    "agent-quark-prog04.sh" # 16
    "agent-quark-prog05.sh" # 17
    "agent-quark-prog80.sh" # 18
    "agent-quark-prog81.sh" # 19
    "agent-quark-prog96.sh" # 20
    "agent-quark-prog97.sh" # 21
    "agent-quark-prog98.sh" # 22
    "agent-quark-prog99.sh" # 23
    "agent-rtl8139-debug.sh" # 24
    "agent-rtl8139-prog01.sh" # 25
    "agent-rtl8139-prog02.sh" # 26
    "agent-rtl8139-prog03.sh" # 27
    "agent-rtl8139-prog04.sh" # 28
    "agent-rtl8139-prog05.sh" # 29
    "agent-rtl8139-prog80.sh" # 30
    "agent-rtl8139-prog81.sh" # 31
    "agent-rtl8139-prog96.sh" # 32
    "agent-rtl8139-prog97.sh" # 33
    "agent-rtl8139-prog98.sh" # 34
    "agent-rtl8139-prog99.sh" # 35
    "agent-snic-debug.sh" # 36
    "agent-snic-prog01.sh" # 37
    "agent-snic-prog02.sh" # 38
    "agent-snic-prog03.sh" # 39
    "agent-snic-prog04.sh" # 40
    "agent-snic-prog05.sh" # 41
    "agent-snic-prog80.sh" # 42
    "agent-snic-prog81.sh" # 43
    "agent-snic-prog96.sh" # 44
    "agent-snic-prog97.sh" # 45
    "agent-snic-prog98.sh" # 46
    "agent-snic-prog99.sh" # 47
    "agent-usb-debug.sh" # 48
    "agent-usb-prog01.sh" # 49
    "agent-usb-prog02.sh" # 50
    "agent-usb-prog03.sh" # 51
    "agent-usb-prog04.sh" # 52
    "agent-usb-prog05.sh" # 53
    "agent-usb-prog80.sh" # 54
    "agent-usb-prog81.sh" # 55
    "agent-usb-prog96.sh" # 56
    "agent-usb-prog97.sh" # 57
    "agent-usb-prog98.sh" # 58
    "agent-usb-prog99.sh" # 59
)

sleep 5

if [ $id -lt ${#progs[@]} ]; then
    /root/${progs[$id]}
else
    echo "Failed to find guest agent $id"
    /root/agent-exit AGENT_START_FAILURE
    exit 1
fi

/root/agent-exit
