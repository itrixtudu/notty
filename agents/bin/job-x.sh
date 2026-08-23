#!/usr/bin/env bash

set -x

cp $PWD/agents/README.md $PWD/agents/jobs/$1.job.running
echo "Your MYID is $1" >> $PWD/agents/jobs/$1.job.running 
cat $PWD/agents/jobs/$1.job >> $PWD/agents/jobs/$1.job.running 
#cat $PWD/agents/jobs/$1.job.running | $PWD/node_modules/.bin/codex exec -o $PWD/agents/logs/$1.final -C $PWD --json --dangerously-bypass-approvals-and-sandbox | tee -a $PWD/agents/logs/$1.log
cat $PWD/agents/jobs/$1.job.running 

