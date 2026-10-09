#!/usr/bin/env bash
set -euo pipefail

resolve_script_dir() {
  local source="${BASH_SOURCE[0]}"
  local dir

  while [[ -L "$source" ]]; do
    dir="$(cd -P "$(dirname "$source")" && pwd)"
    source="$(readlink "$source")"
    if [[ "$source" != /* ]]; then
      source="$dir/$source"
    fi
  done

  cd -P "$(dirname "$source")" && pwd
}

SCRIPT_DIR="$(resolve_script_dir)"
url="$1"

# Example:
# nosh://container-name?cmd=restart

proto_removed="${url#nosh://}"
container="${proto_removed%%\?*}"
query="${proto_removed#*\?}"

# Parse query params (simple version)
#cmd="$(printf '%s\n' "$query" | sed -n 's/^cmd=//p')"

#logger "[nosh-handler] container=$container cmd=$cmd"

tilix -- bash "$SCRIPT_DIR/nosh-xdg-container.sh" "$url"

# Your action
#case "$cmd" in
#  restart)
#    nosh exec "$container" restart
#    ;;
#  shell)
#    tilix -- docker exec -it "$container" /bin/bash
#    ;;
#  *)
#    notify-send "nosh" "Unknown command"
#    ;;
#esac
#
