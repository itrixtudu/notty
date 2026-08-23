#!/usr/bin/env bash
set -u

# The application applies its current lockdown view and route policy. This
# process is only its read-only display; it is not an authentication prompt.
trap 'exit 0' HUP TERM
trap '' INT QUIT TSTP

printf '\033[2J\033[H'
printf '%s\n' \
  'NOTTY LOCKDOWN VIEW ACTIVE' \
  '' \
  'The browser is showing the restricted lockdown view.' \
  'This view does not disable MCP or terminal WebSocket control.' \
  'This screen does not accept a password or change service policy.'

# Consume input without echoing it. The controlling Notty process terminates
# this display when the lockdown view ends or the service shuts down.
while IFS= read -r -s -n 1 _input; do
  :
done
