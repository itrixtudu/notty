#!/bin/sh
set -eu

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
codex_root=${CODEX_HOME:-"$HOME/.codex"}
pet_root="$codex_root/pets"
destination="$pet_root/bubble-bai"

if [ ! -f "$package_dir/pet.json" ] || [ ! -f "$package_dir/spritesheet.png" ]; then
    printf 'Missing pet.json or spritesheet.png in the package.\n' >&2
    exit 1
fi

if [ -d "$destination" ]; then
    if cmp -s "$package_dir/pet.json" "$destination/pet.json" && \
       cmp -s "$package_dir/spritesheet.png" "$destination/spritesheet.png"; then
        printf 'Bubble Bai is already installed at %s\n' "$destination"
        exit 0
    fi
    printf 'Existing pet directory differs: %s\nMove it aside before installing this package.\n' "$destination" >&2
    exit 1
fi

mkdir -p "$pet_root"
staging=$(mktemp -d "$pet_root/.bubble-bai-install.XXXXXXXX")
trap 'if [ -n "${staging:-}" ] && [ -d "$staging" ]; then rmdir "$staging" 2>/dev/null || :; fi' EXIT HUP INT TERM
cp "$package_dir/spritesheet.png" "$staging/spritesheet.png"
cp "$package_dir/pet.json" "$staging/pet.json"
mv "$staging" "$destination"
staging=

printf 'Installed Bubble Bai at %s\n' "$destination"
printf 'In Codex, open /pets and choose Bubble Bai. Restart Codex if it was already open.\n'
