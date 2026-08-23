#!/usr/bin/env bash

CONTAINER="nosh-$(basename $PWD)"
SCRIPT_PATH="$0"
#SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER=$(whoami)
DSTHOME="${CONTAINER}:/home/$USER/"
CONTEXT=" -u ${USER} ${CONTAINER} "

dcp() {
  docker cp $1 ${DSTHOME}
}

dxp() {
  docker exec -w $PWD -i ${CONTEXT} bash 
}

cp agents/README.md agents/jobs/$1.job.running
cat agents/jobs/$1.job >> $1.job.running

echo "tmux -u new-session -d -c $PWD -s $1 'cat agents/jobs/$1.job.running | ~/node_modules/.bin/codex exec --full-auto'" 


echo "tmux -u new-session -d -c $PWD -s $1 'cat agents/jobs/$1.job | ~/node_modules/.bin/codex -a never -s danger-full-access'" | dxp
#echo "tmux new-session -d -c /workspace -s gemini '~/node_modules/.bin/gemini -y'" | dxp
#sleep 3
#echo "rm /home/$USER/.codex/auth.json /home/$USER/.gemini/oauth_creds.json  /home/$USER/.gemini/google_accounts.json" | dxp




