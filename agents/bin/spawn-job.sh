#!/usr/bin/env bash


tmux -u new-session -d -c $PWD -s "$1" "cat agents/jobs/$1.job ~/node_modules/.bin/codex -a never -s danger-full-access"
