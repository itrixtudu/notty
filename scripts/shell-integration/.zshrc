# Notty command lifecycle integration for interactive Zsh terminals.
# Capture the private marker nonce before loading user configuration, and never export it
# to commands launched from this shell.

typeset -g _notty_marker_nonce="${NOTTY_SHELL_MARKER_NONCE:-}"
typeset +x _notty_marker_nonce
unset NOTTY_SHELL_MARKER_NONCE

typeset -g _notty_original_zdotdir="${NOTTY_ORIGINAL_ZDOTDIR-}"
typeset -g _notty_original_zdotdir_set="${NOTTY_ORIGINAL_ZDOTDIR_SET:-0}"
typeset -g _notty_original_startup_dir="${NOTTY_ORIGINAL_ZDOTDIR_PATH-$HOME}"
typeset +x _notty_original_zdotdir _notty_original_zdotdir_set _notty_original_startup_dir

# Restore the user's startup environment before replaying files skipped by Notty's temporary
# ZDOTDIR. .zshenv is sourced first and may itself select a new ZDOTDIR for .zshrc.
if [[ "$_notty_original_zdotdir_set" == "1" ]]; then
  export ZDOTDIR="$_notty_original_zdotdir"
else
  unset ZDOTDIR
fi
unset NOTTY_ORIGINAL_ZDOTDIR NOTTY_ORIGINAL_ZDOTDIR_PATH NOTTY_ORIGINAL_ZDOTDIR_SET

if [[ -r "$_notty_original_startup_dir/.zshenv" ]]; then
  source "$_notty_original_startup_dir/.zshenv"
fi
if (( ${+ZDOTDIR} )); then
  typeset -g _notty_effective_zdotdir="$ZDOTDIR"
else
  typeset -g _notty_effective_zdotdir="$HOME"
fi
typeset +x _notty_effective_zdotdir
if [[ -o rcs && -r "$_notty_effective_zdotdir/.zshrc" ]]; then
  source "$_notty_effective_zdotdir/.zshrc"
fi
unset _notty_original_zdotdir _notty_original_zdotdir_set
unset _notty_original_startup_dir _notty_effective_zdotdir

if [[ ! -o interactive || -n "${NOTTY_SHELL_INTEGRATION_ACTIVE:-}" ]]; then
  return
fi

export NOTTY_SHELL_INTEGRATION_ACTIVE=1
autoload -Uz add-zsh-hook

_notty_hex() {
  printf '%s' "${1-}" | command od -An -v -tx1 | command tr -d ' \n'
}

_notty_emit_marker() {
  local type="$1"
  local command_id="$2"
  local exit_code="$3"
  local cwd_value="$4"
  local command_value="$5"
  printf '\033]6973;notty-command;2;%s;%s;%s;%s;%s;%s\007' \
    "$_notty_marker_nonce" \
    "$type" \
    "$command_id" \
    "$exit_code" \
    "$(_notty_hex "$cwd_value")" \
    "$(_notty_hex "$command_value")"
}

typeset -g _notty_command_id=""
typeset -g _notty_command_value=""
typeset -gi _notty_command_sequence=0

_notty_preexec() {
  _notty_command_sequence=$((_notty_command_sequence + 1))
  _notty_command_id="zsh-$$-${_notty_command_sequence}"
  _notty_command_value="$1"
  _notty_emit_marker start "$_notty_command_id" "" "$PWD" "$_notty_command_value"
}

_notty_precmd() {
  local command_status=$?
  if [[ -n "$_notty_command_id" ]]; then
    _notty_emit_marker \
      complete \
      "$_notty_command_id" \
      "$command_status" \
      "$PWD" \
      "$_notty_command_value"
    _notty_command_id=""
    _notty_command_value=""
  else
    _notty_emit_marker prompt "" "" "$PWD" ""
  fi
  return "$command_status"
}

add-zsh-hook preexec _notty_preexec
add-zsh-hook precmd _notty_precmd
