#!/usr/bin/env bash

set -x

JOBID="gemini-$1"


cp $PWD/agents/README.md $PWD/agents/jobs/$JOBID.job.running
echo "Your MYID is $JOBID" >> $PWD/agents/jobs/$JOBID.job.running 
cat $PWD/agents/jobs/$JOBID.job >> $PWD/agents/jobs/$JOBID.job.running 
cat $PWD/agents/jobs/$JOBID.job.running | $PWD/node_modules/.bin/gemini -y --json | tee -a $PWD/agents/logs/$JOBID.log

