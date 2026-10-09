#!/usr/bin/env bash
set -euo pipefail

umask 077

resolve_script_dir() {
  local source=${BASH_SOURCE[0]} dir
  while [[ -L $source ]]; do
    dir=$(cd -P "$(dirname "$source")" && pwd)
    source=$(readlink "$source")
    [[ $source == /* ]] || source=$dir/$source
  done
  cd -P "$(dirname "$source")" && pwd
}

SCRIPT_DIR=$(resolve_script_dir)
REPO_ROOT=$(cd -P "$SCRIPT_DIR/.." && pwd)
USER_ONLY=false
REMOVE_GUARD=false
PACKAGE_REMOVAL=false
PURGE_CONFIG=false
PURGE_STATE=false
DRY_RUN=false
YES=false

usage() {
  cat <<'EOF'
Usage: nosh uninstall [options]

Remove the current user's Nosh setup, then optionally remove Nosh Guard.
Policy, evidence, project configuration, Docker images, and containers are
preserved unless an explicit purge option says otherwise.

Options:
  --user-only       remove only managed user launchers/configuration and TUI venv
  --guard           also remove the privileged Guard installation
  --purge-config    with --guard, remove Guard configuration
  --purge-state     with --guard, permanently remove Guard evidence and state
  --dry-run         print the verified removal plan without changing anything
  --yes             confirm non-destructive phases noninteractively
  -h, --help        show this help
EOF
}

die() { printf 'nosh uninstall: %s\n' "$*" >&2; exit 1; }

while (($#)); do
  case $1 in
    --user-only) USER_ONLY=true ;;
    --guard) REMOVE_GUARD=true ;;
    --purge-config) PURGE_CONFIG=true; REMOVE_GUARD=true ;;
    --purge-state) PURGE_STATE=true; REMOVE_GUARD=true ;;
    --dry-run) DRY_RUN=true ;;
    --yes) YES=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
  shift
done

[[ $USER_ONLY == false || $REMOVE_GUARD == false ]] \
  || die '--user-only conflicts with Guard and purge options'
[[ -z ${SUDO_UID:-}${SUDO_GID:-}${SUDO_USER:-} ]] \
  || die 'run this command as the configured user, not through sudo'

CONFIG_HOME=${XDG_CONFIG_HOME:-${HOME:?HOME is required}/.config}
DATA_HOME=${XDG_DATA_HOME:-$HOME/.local/share}
[[ $CONFIG_HOME == /* && $CONFIG_HOME != / && $DATA_HOME == /* && $DATA_HOME != / ]] \
  || die 'XDG configuration and data homes must be absolute paths other than /'
CONFIG=$CONFIG_HOME/nosh/paths.conf
IMAGE_CONFIG=$CONFIG_HOME/nosh/policy-review-images.conf
TUI_ROOT=$DATA_HOME/nosh/tui
BIN_DIR=''
NOSH_BIN=''
GUARD_BIN=''
GUARD_PREFIX=''
PRIVILEGED_BIN=''
declare -A FIELDS=()

read_paths_config() {
  local metadata line key value
  [[ -e $CONFIG || -L $CONFIG ]] || return 0
  [[ -f $CONFIG && ! -L $CONFIG ]] || die "unsafe path configuration: $CONFIG"
  metadata=$(stat -Lc '%u %a %h' -- "$CONFIG")
  [[ $metadata == "$(id -u) 600 1" ]] || die "unsafe path configuration ownership/mode: $CONFIG"
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -n $line && $line == *=* && $line != *$'\r'* ]] || die "malformed path configuration: $CONFIG"
    key=${line%%=*}; value=${line#*=}
    case $key in
      SCHEMA_VERSION|BIN_DIR|NOSH_BIN|NOSH_GUARD_BIN|NOSH_GUARD_PREFIX|NOSH_GUARD_PRIVILEGED_BIN) ;;
      *) die "unknown path configuration key: $key" ;;
    esac
    [[ ! -v FIELDS[$key] ]] || die "duplicate path configuration key: $key"
    FIELDS[$key]=$value
  done <"$CONFIG"
  [[ ${FIELDS[SCHEMA_VERSION]:-} == 1 ]] || die 'unsupported path configuration schema'
  for key in BIN_DIR NOSH_BIN NOSH_GUARD_BIN NOSH_GUARD_PREFIX NOSH_GUARD_PRIVILEGED_BIN; do
    [[ -v FIELDS[$key] && ${FIELDS[$key]} == /* ]] || die "invalid path configuration field: $key"
  done
  BIN_DIR=${FIELDS[BIN_DIR]}; NOSH_BIN=${FIELDS[NOSH_BIN]}; GUARD_BIN=${FIELDS[NOSH_GUARD_BIN]}
  GUARD_PREFIX=${FIELDS[NOSH_GUARD_PREFIX]}; PRIVILEGED_BIN=${FIELDS[NOSH_GUARD_PRIVILEGED_BIN]}
  [[ $PRIVILEGED_BIN == "$GUARD_PREFIX/bin/nosh-guard" ]] || die 'inconsistent Guard paths in configuration'
}

validate_managed_link() {
  local target=$1 expected=$2
  [[ -e $target || -L $target ]] || return 0
  [[ -L $target && $(readlink "$target") == "$expected" ]] \
    || die "refusing to remove foreign launcher: $target"
}

validate_optional_user_file() {
  local target=$1 metadata
  [[ -e $target || -L $target ]] || return 0
  [[ -f $target && ! -L $target ]] || die "refusing unsafe user configuration removal: $target"
  metadata=$(stat -Lc '%u %a %h' -- "$target")
  [[ $metadata == "$(id -u) 600 1" ]] || die "refusing user configuration with unsafe ownership/mode: $target"
}

validate_image_config() {
  local line key value count=0
  declare -A seen=()
  [[ -f $IMAGE_CONFIG && ! -L $IMAGE_CONFIG ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -n $line && $line == *=* && $line != *$'\r'* ]] \
      || die "malformed Policy Review image configuration: $IMAGE_CONFIG"
    key=${line%%=*}; value=${line#*=}; ((count += 1))
    case $key in
      SCHEMA_VERSION) [[ $value == 1 ]] || die 'unsupported Policy Review image configuration schema' ;;
      NOSH_POLICY_TOOLING_IMAGE|NOSH_POLICY_REVIEW_UI_IMAGE)
        [[ $value =~ ^sha256:[a-f0-9]{64}$ ]] || die "invalid image digest in $IMAGE_CONFIG"
        ;;
      *) die "unknown Policy Review image configuration key: $key" ;;
    esac
    [[ ! -v seen[$key] ]] || die "duplicate Policy Review image configuration key: $key"
    seen[$key]=1
  done <"$IMAGE_CONFIG"
  [[ $count == 3 && -v seen[SCHEMA_VERSION] && -v seen[NOSH_POLICY_TOOLING_IMAGE] \
      && -v seen[NOSH_POLICY_REVIEW_UI_IMAGE] ]] \
    || die "incomplete Policy Review image configuration: $IMAGE_CONFIG"
}

read_paths_config
if [[ -n $BIN_DIR ]]; then
  validate_managed_link "$BIN_DIR/nosh" "$NOSH_BIN"
  validate_managed_link "$BIN_DIR/nosh-guard" "$GUARD_BIN"
fi
validate_optional_user_file "$IMAGE_CONFIG"
validate_image_config
if [[ -e $TUI_ROOT || -L $TUI_ROOT ]]; then
  [[ -d $TUI_ROOT && ! -L $TUI_ROOT ]] || die "refusing unsafe TUI environment removal: $TUI_ROOT"
  [[ $(stat -Lc '%u' -- "$TUI_ROOT") == "$(id -u)" ]] || die "TUI environment is not owned by the current user: $TUI_ROOT"
fi

printf '%s\n' 'User removal plan:'
[[ -z $BIN_DIR ]] || printf '  launcher: %s\n  launcher: %s\n' "$BIN_DIR/nosh" "$BIN_DIR/nosh-guard"
printf '  config:   %s\n  config:   %s\n  TUI venv: %s\n' "$CONFIG" "$IMAGE_CONFIG" "$TUI_ROOT"
printf '%s\n' '  preserved: policies, evidence, signing state, Docker data, and repository .nosh files'

confirm() {
  local prompt=$1 answer
  [[ $YES == true ]] && return 0
  [[ -t 0 ]] || return 1
  read -r -p "$prompt [y/N]: " answer
  [[ $answer == y || $answer == Y ]]
}

if [[ $DRY_RUN == false ]]; then
  confirm 'Remove the verified user setup?' || { printf '%s\n' 'User uninstall cancelled.'; exit 0; }
  if [[ -n $BIN_DIR ]]; then
    [[ ! -L $BIN_DIR/nosh ]] || unlink "$BIN_DIR/nosh"
    [[ ! -L $BIN_DIR/nosh-guard ]] || unlink "$BIN_DIR/nosh-guard"
  fi
  [[ ! -f $CONFIG ]] || unlink "$CONFIG"
  [[ ! -f $IMAGE_CONFIG ]] || unlink "$IMAGE_CONFIG"
  if [[ -d $TUI_ROOT && ! -L $TUI_ROOT ]]; then
    rm -rf -- "$TUI_ROOT"
  fi
  printf '%s\n' 'Removed the verified user setup.'
fi

[[ $USER_ONLY == false ]] || exit 0
if [[ $REMOVE_GUARD == false && -t 0 ]]; then
  confirm 'Continue with privileged Nosh Guard removal?' && REMOVE_GUARD=true
fi
[[ $REMOVE_GUARD == true ]] || { printf '%s\n' 'Nosh Guard was preserved.'; exit 0; }

if [[ $PURGE_CONFIG == true || $PURGE_STATE == true ]]; then
  printf '%s\n' 'PURGE REQUESTED: Guard configuration and/or evidence will be permanently deleted.' >&2
  if [[ $YES == false ]]; then
    read -r -p 'Type PURGE to continue: ' purge_answer
    [[ $purge_answer == PURGE ]] || { printf '%s\n' 'Guard purge cancelled.'; exit 0; }
  fi
fi

if command -v dpkg-query >/dev/null 2>&1 \
    && dpkg-query -W -f='${Status}' notty-nosh 2>/dev/null | grep -q 'install ok installed' \
    && dpkg-query -S /opt/notty/bin/nosh-guard 2>/dev/null | grep -q '^notty-nosh:'; then
  PACKAGE_REMOVAL=true
  package_action=remove
  [[ $PURGE_CONFIG == false ]] || package_action=purge
  command=(sudo apt-get "$package_action" notty-nosh)
else
  receipt=/etc/nosh-guard-install-layout.conf
  [[ -f $receipt && ! -L $receipt ]] || die 'Guard installation receipt is unavailable; privileged files were not changed'
  [[ $(stat -Lc '%u %a %h' -- "$receipt") == '0 644 1' ]] \
    || die 'Guard installation receipt has unsafe ownership or mode'
  [[ $(sed -n '/^\(SCHEMA_VERSION\|NOSH_GUARD_PREFIX\|MANIFEST_SHA256\)=/!p' "$receipt" | wc -l) == 0 ]] \
    || die 'Guard installation receipt has unknown fields'
  [[ $(sed -n '$=' "$receipt") == 3 && $(sed -n 's/^SCHEMA_VERSION=//p' "$receipt") == 1 \
      && $(sed -n 's/^MANIFEST_SHA256=//p' "$receipt") =~ ^[a-f0-9]{64}$ ]] \
    || die 'Guard installation receipt is malformed'
  receipt_prefix=$(sed -n 's/^NOSH_GUARD_PREFIX=//p' "$receipt")
  [[ $receipt_prefix =~ ^/[A-Za-z0-9][A-Za-z0-9._+-]*(/[A-Za-z0-9][A-Za-z0-9._+-]*)*$ \
      && $receipt_prefix != / ]] || die 'Guard installation receipt has an unsafe prefix'
  installer=$receipt_prefix/lib/notty/nosh-guard/current/install.sh
  [[ -x $installer && ! -L $installer ]] || die "verified Guard uninstaller is unavailable: $installer"
  installer_metadata=$(stat -Lc '%u %a %h' -- "$installer")
  installer_mode=${installer_metadata#* }; installer_mode=${installer_mode%% *}
  [[ ${installer_metadata%% *} == 0 && ${installer_metadata##* } == 1 ]] \
    && (( (8#$installer_mode & 8#22) == 0 )) \
    || die 'verified Guard uninstaller has unsafe ownership or mode'
  command=(sudo "$installer" uninstall --prefix "$receipt_prefix")
  [[ $PURGE_CONFIG == false ]] || command+=(--purge-config)
  [[ $PURGE_STATE == false ]] || command+=(--purge-state)
fi

printf 'Guard removal command:'; printf ' %q' "${command[@]}"; printf '\n'
if [[ $PACKAGE_REMOVAL == true && $PURGE_STATE == true ]]; then
  printf '%s\n' 'After package removal: permanently remove /var/lib/nosh-guard'
fi
[[ $DRY_RUN == false ]] || exit 0
confirm 'Run the privileged Guard removal command?' || { printf '%s\n' 'Nosh Guard was preserved.'; exit 0; }
if [[ $PACKAGE_REMOVAL == true ]]; then
  "${command[@]}"
  if [[ $PURGE_STATE == true ]]; then
    sudo rm -rf -- /var/lib/nosh-guard
    printf '%s\n' 'Permanently removed /var/lib/nosh-guard evidence and state.'
  fi
  exit 0
fi
exec "${command[@]}"
