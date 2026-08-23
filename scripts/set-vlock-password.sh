#!/bin/sh
set -eu

PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
umask 077

# The host launcher clears loader and shell startup variables before this
# interpreter starts. Clear them again before executing any child process.
unset BASH_ENV ENV GCONV_PATH LD_AUDIT LD_DEBUG LD_DEBUG_OUTPUT \
  LD_LIBRARY_PATH LD_PRELOAD LOCPATH NLSPATH

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
  printf '%s\n' 'set-vlock-password: must run as container root' >&2
  exit 1
fi

identityFile='/etc/notty/container-user'
if [ ! -f "$identityFile" ] || [ -L "$identityFile" ]; then
  printf '%s\n' 'set-vlock-password: trusted container identity is unavailable' >&2
  exit 1
fi

if [ "$(/usr/bin/stat -c '%u:%g:%a' "$identityFile")" != '0:0:444' ]; then
  printf '%s\n' 'set-vlock-password: trusted container identity has unsafe ownership or mode' >&2
  exit 1
fi

if [ "$(/usr/bin/wc -l < "$identityFile")" != '1' ]; then
  printf '%s\n' 'set-vlock-password: trusted container identity is invalid' >&2
  exit 1
fi
IFS= read -r target < "$identityFile"
case "$target" in
  ''|*[!a-zA-Z0-9_.-]*)
    printf '%s\n' 'set-vlock-password: trusted container identity is invalid' >&2
    exit 1
    ;;
esac

if ! entry=$(/usr/bin/getent passwd "$target"); then
  printf 'set-vlock-password: container user does not exist: %s\n' "$target" >&2
  exit 1
fi

account=${entry%%:*}
entry=${entry#*:}
entry=${entry#*:}
uid=${entry%%:*}
case "$uid" in
  ''|0|*[!0-9]*)
    printf '%s\n' 'set-vlock-password: refusing to set the root password' >&2
    exit 1
    ;;
esac
if [ "$account" != "$target" ]; then
  printf '%s\n' 'set-vlock-password: refusing to set the root password' >&2
  exit 1
fi

exec /usr/bin/env -i \
  PATH='/usr/sbin:/usr/bin:/sbin:/bin' \
  LANG='C.UTF-8' \
  LC_ALL='C.UTF-8' \
  /usr/bin/passwd "$account"
