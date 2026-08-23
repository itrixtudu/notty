#!/usr/bin/env bash



docker build -f Dockerfile.prod -t ntty .
#docker run --rm -it -p 3000:3000 ntty
docker run --rm -it -p 3000:3000 \
  -e NOTTY_MCP_SPAWN_OTP=otptest \
  ntty 
#  -e NOTTY_MCP_TOOLSET=durdraw \

