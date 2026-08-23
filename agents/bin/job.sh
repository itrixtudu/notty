#!/usr/bin/env bash

set -x

CONTAINER=nosh-$(basename $PWD)
USER=$(whoami)
CONTEXT=" -u ${USER} ${CONTAINER} "

docker exec -it $CONTAINER tmux new-session -u -d -c $PWD -s $1 -- $PWD/agents/bin/job-simple.sh $1



