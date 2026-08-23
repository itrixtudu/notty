#!/usr/bin/env bash

set -x
MYID=codex-$(date +%s)
JOBID=$1-$MYID
JOBFILE=$PWD/agents/jobs/$JOBID.job.running

echo "MYID:$MYID"
echo "JOBID:$JOBID"
echo "JOBFILE:$JOBFILE"


cp $PWD/AGENTS.md $JOBFILE
echo "Your MYID is $MYID" >> $JOBFILE
cat $PWD/agents/jobs/$1.job >> $JOBFILE
cat $JOBFILE | $HOME/node_modules/.bin/codex exec --output-last-message $PWD/agents/logs/$JOBID.final -C $PWD --json --full-auto | tee -a $PWD/agents/logs/$JOBID.log 

