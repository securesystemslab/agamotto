#!/bin/bash

id=$$(/root/agent-get-prog)

progs=(
    ${AGENTS}
)

sleep 5

if [ $$id -lt $${#progs[@]} ]; then
    /root/$${progs[$$id]}
else
    echo "Failed to find guest agent $$id"
    /root/agent-exit AGENT_START_FAILURE
    exit 1
fi

/root/agent-exit
