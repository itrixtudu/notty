Confirmed: Parrot’s Buildx 0.13.1 does not contain history; the experimental flag cannot expose it. Nosh needs Buildx ≥0.24.0. I recommend v0.34.1 because it matches Nosh’s pinned BuildKit
  v0.30.0.

  First leave the root shell. Install this as kross, not root:

  exit   # until the prompt shows kross

  (
    set -euo pipefail
    [[ "$(id -un)" == "kross" ]] || {
      echo "run this as kross, not root" >&2
      exit 1
    }

    buildx_version="v0.34.1"
    buildx_asset="buildx-${buildx_version}.linux-amd64"
    docker_config="${DOCKER_CONFIG:-$HOME/.docker}"
    plugin_dir="$docker_config/cli-plugins"
    plugin="$plugin_dir/docker-buildx"

    [[ ! -e "$plugin" ]] || {
      echo "refusing to overwrite $plugin" >&2
      exit 1
    }

    download_file="$(mktemp)"
    trap 'rm -f -- "$download_file"' EXIT

    curl --fail --location --proto '=https' --tlsv1.2 \
      "https://github.com/docker/buildx/releases/download/$buildx_version/$buildx_asset" \
      --output "$download_file"

    printf '%s  %s\n' \
      'f1332ddb9010bd0b72628266c3a906d9a6979848033df4c8d9bd2cd113bae12b' \
      "$download_file" |
      sha256sum --check --strict -

    install -d -m 0700 "$docker_config"
    install -d -m 0755 "$plugin_dir"
    install -m 0755 "$download_file" "$plugin"
  )

  Verify the user plugin is selected:

  docker buildx version
  docker buildx history inspect --help >/dev/null
  docker buildx history export --help | grep -F -- '--finalize'

  The first command should report v0.34.1. This retains Parrot’s packaged Buildx as the system fallback and avoids mixing Docker CE packages. The manual plugin will not receive automatic
  package updates. See the official Buildx installation guidance (https://github.com/docker/buildx/blob/v0.34.1/README.md#installing) and v0.24.0 history-finalization addition
  (https://github.com/docker/buildx/releases/tag/v0.24.0).

  Then profile a project, still as kross:

  cd /path/to/project

  nosh build profile --dry-run --tag myproject:profile .
  sudo -v
  nosh build profile --tag myproject:profile .
  nosh build status .

  Do not run nosh build through sudo; Nosh elevates only its narrow sensor operations. The default profile performs both cold and warm builds.

  And no—the dedicated build-profiling process is currently missing from EXAMPLES.md. It is documented in docs/nosh-build-profiling.md:18, with a shorter version in README.md:297. The Guard
  section in EXAMPLES.md describes runtime/network profiling, which is a separate workflow.

─ Worked for 5m 37s ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


