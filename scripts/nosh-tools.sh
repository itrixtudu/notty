#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
command=${1:-help}
[[ $# == 0 ]] || shift
if [[ $command == help || $command == --help ]]; then
  cat <<'HELP'
Usage: nosh tools init|review|check|apply|status|rollback|doctor [options]
  --scope repo|directory|all  History scope for init (all recorded dates)
  --codex-home PATH      History location for init
  --output-dir PATH     New private audit directory for init
  --no-prompt           Disable init prompts; requires --scope
  --request-details original|none  Original unique inputs (init default: original)
  --build-ui            Allow review to build a missing/outdated UI image in Docker
  --no-browser          Print the review URL without opening a browser
  --review REPORT       Saved audit directory (review prompts when omitted)
  --workdir WORKSPACE    Workspace (default: cwd)
  --policy-digest HASH   Exact saved environment-policy digest, required for apply
  --guard-prefix PATH   Installed Guard prefix (default /opt/notty)
  --revision HASH        Previously applied revision for rollback
Apply and rollback use the installed root-owned /opt/notty/bin/nosh-guard authority.
Saved policies apply to future containers. Existing containers require explicit recreate.
HELP
  exit 0
fi
if [[ $command == doctor ]]; then
  exec python3 -B "$SCRIPT_DIR/nosh-command-doctor.py"
fi
guard_prefix=/opt/notty
args=()
while (($#)); do
  case $1 in
    --guard-prefix) guard_prefix=${2:?--guard-prefix requires a value}; shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
set -- "${args[@]}"
has_workdir=false
for arg in "$@"; do [[ $arg != --workdir && $arg != --workdir=* ]] || has_workdir=true; done
[[ $has_workdir == true ]] || args+=(--workdir "$PWD")
if [[ $command == init ]]; then
  exec python3 -B "$SCRIPT_DIR/audit-codex-tools.py" --init "${args[@]}"
fi
if [[ $command == review ]]; then
  report=''
  review_args=()
  while (($#)); do
    case $1 in
      --review) report=$2; shift 2 ;;
      --build-ui|--no-browser) review_args+=("$1"); shift ;;
      --workdir|--workload) shift 2 ;;
      *) printf 'nosh tools review: unknown option %s\n' "$1" >&2; exit 2 ;;
    esac
  done
  if [[ -z $report ]]; then
    printf 'Saved audit directory: ' >&2
    IFS= read -r report
  fi
  exec python3 -B "$SCRIPT_DIR/review-codex-tools.py" "$report" "${review_args[@]}"
fi
if [[ $command == apply || $command == rollback ]]; then
  # Never elevate the mutable workspace checkout. Guard and its payload are
  # installed by the existing root-owned host-bundle installer.
  authority="$guard_prefix/bin/nosh-guard"
  authority=$(python3 -I -S - "$authority" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]).resolve(strict=True)
for node in (p, *p.parents):
    s = node.stat()
    if s.st_uid != 0 or s.st_mode & 0o022:
        sys.exit('Install the root-owned Nosh Guard host bundle before applying policies')
print(p)
PY
)
  exec sudo -- "$authority" tools "$command" "${args[@]}"
fi
exec python3 -I -S "$SCRIPT_DIR/nosh-tool-policy.py" "$command" "${args[@]}"
