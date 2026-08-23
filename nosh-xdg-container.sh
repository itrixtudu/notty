#!/usr/bin/env bash
set -euo pipefail

url="$1"

# Strip scheme
rest="${url#nosh://}"

# Take only the first path segment (ignore / ? # entirely)
container="${rest%%/*}"
container="${container%%\?*}"
container="${container%%#*}"

#logger "[nosh-handler] container=$container"

# Do the one thing you care about
docker_exec_args=(exec -it)
for key in TILIX_ID VTE_VERSION; do
  if [[ -n "${!key-}" ]]; then
    docker_exec_args+=(-e "$key=${!key}")
  fi
done

exec docker "${docker_exec_args[@]}" "$container" /bin/bash
