#!/bin/zsh
# vim: set ft=sh:
# shellcheck shell=bash

set -euo pipefail

# environment variables for great justice
export XDG_CONFIG_HOME="$HOME/.config"
export GNUPGHOME="$XDG_CONFIG_HOME/gnupg"
export TRUSTED_GPGKEY_FINGREPRINT="77D8616541A323FF03E6639947BEA857F03AFE90"
export PINENTRY_PROGRAM="/opt/homebrew/bin/pinentry-mac"
export GIT_HIGHLANDER="https://raw.githubusercontent.com/dinklebop/dotfiles/init/scripts/bootstrap/highlander.asc"
export TOUCH_ID_TEMPLATE_FILE="/etc/pam.d/sudo_local.template"
export TOUCH_ID_AUTH_FILE="/etc/pam.d/sudo_local"

# OS Name
OS_NAME="$(uname)"
ARCH="$(uname -m)"
BREW="/opt/homebrew/bin/brew"

RED="\033[1;31m"
GREEN="\033[1;32m"
NOCOLOR="\033[0m"

HIGHLANDER_WORKSPACE=""
TEMP_HIGHLANDER=""
WORKING_HIGHLANDER=""
PAYLOAD_RUNNING=0

print_with_color() {
  local color="$1"
  local message="$2"
  echo -e "${color}$message${NOCOLOR}"
  echo -e "\n"
  sleep 3
}

print_error() {
  local message="$1"
  print_with_color "$RED" "$message"
}

print_message() {
  local message="$1"
  print_with_color "$GREEN" "$message"
}

cleanup_highlander() {
  if [[ -n "$HIGHLANDER_WORKSPACE" && -d "$HIGHLANDER_WORKSPACE" ]]; then
    /bin/rm -rf -- "$HIGHLANDER_WORKSPACE"
  fi
}

bootstrap_failure() {
  local status=$?
  if (( PAYLOAD_RUNNING == 0 )); then
    print_error "Bootstrap failed before repository initialization. Rerun: /bin/zsh <(curl -fsSL https://dinklebop.com)"
  fi
  return $status
}

trap cleanup_highlander EXIT
trap bootstrap_failure ZERR

install_homebrew() {
  if [[ ! -f "$BREW" ]]; then
    print_message "Installing homebrew ... follow the prompts"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  fi
}

bootstrap_brew_env() {
  # shellcheck disable=SC2046,SC1091
  eval $($BREW shellenv zsh)
  $BREW install --force chezmoi rcmdnk/file/brew-file
  # shellcheck disable=SC1091
  if [[ -f "$HOMEBREW_PREFIX/etc/brew-wrap" ]]; then
    export HOMEBREW_BREWFILE_ON_REQUEST=1
    source "$HOMEBREW_PREFIX/etc/brew-wrap"
  fi
}

setup_gnupg() {
  # shellcheck disable=2154
  $BREW install --force gnupg pinentry-mac git-crypt
  mkdir -p "$GNUPGHOME"
  chmod 700 "$GNUPGHOME"
  cat > "$GNUPGHOME/gpg-agent.conf" <<EOF

enable-ssh-support
pinentry-program $PINENTRY_PROGRAM
EOF
  echo "standard-resolver" > "$GNUPGHOME/dirmngr.conf"
  pkill dirmngr || true
  sleep 3
  gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys "$TRUSTED_GPGKEY_FINGREPRINT"
  echo "$TRUSTED_GPGKEY_FINGREPRINT:6:" | gpg --import-ownertrust
  gpg --card-status
  gpg --list-secret-keys
}

link-ssh-auth-sock() {
  if [[ -S "$GNUPGHOME/S.gpg-agent.ssh" ]]; then
    print_message "gpg-agent present, linking ssh listener."
    /bin/ln -sf "$GNUPGHOME/S.gpg-agent.ssh" "$SSH_AUTH_SOCK"
    print_message "restarting gpg agent to reflect changes"
    gpg-connect-agent updatestartuptty /bye
  else
    print_error "Error: missing gpg-agent"
    return 1
  fi
}

kill_TALLogoutSavesState() {
  print_message "Disabling macOS reopen windows on login."
  /usr/bin/defaults write com.apple.loginwindow -bool false
}

touch_id_sudo() {
  if [[ ! -f "$TOUCH_ID_AUTH_FILE" ]]; then
    echo "Setting up Touch ID for sudo, you might need to authenticate"
    sudo /bin/cp "$TOUCH_ID_TEMPLATE_FILE" "$TOUCH_ID_AUTH_FILE"
    sudo sed -i '' -e 's,#auth       sufficient     pam_tid.so,auth       sufficient     pam_tid.so,g' "$TOUCH_ID_AUTH_FILE"
    sudo /usr/sbin/chown root:wheel "$TOUCH_ID_AUTH_FILE"
    sudo /bin/chmod 555 "$TOUCH_ID_AUTH_FILE"
  else
    echo "$TOUCH_ID_AUTH_FILE already exists."
  fi
}

create_highlander_workspace() {
  local temp_root="${TMPDIR:-/tmp}"
  HIGHLANDER_WORKSPACE="$(umask 077 && mktemp -d "$temp_root/highlander.XXXXXX")"
  chmod 700 "$HIGHLANDER_WORKSPACE"
  TEMP_HIGHLANDER="$HIGHLANDER_WORKSPACE/highlander.asc"
  WORKING_HIGHLANDER="$HIGHLANDER_WORKSPACE/highlander.sh"
}

curl_highlander() {
  echo "Obtaining highlander file."
  /usr/bin/curl -fsSL --output "$TEMP_HIGHLANDER" "$GIT_HIGHLANDER"
}

there_can_be_only_one() {
  print_with_color "$RED" "THERE CAN BE ONLY ONE!!!"
  print_with_color "$GREEN" "DON'T FORGET TO TOUCH YUBIKEY!"
  gpg --output "$WORKING_HIGHLANDER" --decrypt "$TEMP_HIGHLANDER"
  chmod 700 "$WORKING_HIGHLANDER"
  echo "Running highlander script."
  PAYLOAD_RUNNING=1
  if /bin/zsh "$WORKING_HIGHLANDER"; then
    return 0
  else
    return $?
  fi
}

install_homebrew
bootstrap_brew_env
kill_TALLogoutSavesState
touch_id_sudo
setup_gnupg
link-ssh-auth-sock
create_highlander_workspace
curl_highlander
there_can_be_only_one
