#!/usr/bin/env bash
# Module: coolify_remote — Coolify slave/remote deploy user (no local Coolify/Docker required)
# Enabled by harden-ubuntu.sh --coolify-remote (or --module coolify_remote).
# Reuses helpers from docker_deploy_user.sh (sourced with all modules).

module_coolify_remote() {
  if [[ "${COOLIFY_REMOTE}" -ne 1 ]]; then
    log_info "coolify_remote skipped (pass --coolify-remote on harden-ubuntu.sh for Coolify slave prep)"
    state_set coolify_remote skipped
    return 0
  fi

  if ! run_module_guard coolify_remote "Coolify remote (slave) deploy user"; then
    return 0
  fi

  load_config_env
  require_cmd id adduser usermod getent install

  echo
  log_info "Coolify slave prep: create a deploy user the Coolify *master* will SSH into."
  log_info "You will paste the public key from the Coolify master (Keys / Add Server)."
  log_info "Docker is optional here — Coolify can install it later via passwordless sudo."
  echo

  if ! confirm_test "Add a Coolify-only deploy user on this host now?" "y"; then
    state_set coolify_remote skipped
    log_info "Operator declined Coolify remote user"
    return 0
  fi

  local duser
  duser="$(config_get DEPLOY_USER "")"
  duser="$(prompt_value "Coolify deploy username" "${duser:-coolify}")"
  config_set DEPLOY_USER "${duser}"
  config_set COOLIFY_ROLE remote

  if [[ "${duser}" == "root" ]]; then
    die "Refusing to use root as Coolify deploy user"
  fi
  if [[ -n "${ADMIN_USER:-}" && "${duser}" == "${ADMIN_USER}" ]]; then
    log_warn "Coolify user equals ADMIN_USER (${duser}) — shared admin/deploy identity"
    if ! confirm "Continue with the same account?" "n"; then
      state_set coolify_remote skipped
      return 0
    fi
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN: would create ${duser}, paste master pubkey, passwordless sudo, AllowUsers"
    state_set coolify_remote skipped
    return 0
  fi

  if id "${duser}" &>/dev/null; then
    log_ok "User ${duser} already exists"
  else
    log_info "Creating Coolify deploy user ${duser}"
    run_or_die "adduser ${duser}" adduser --disabled-password --gecos "Coolify" "${duser}"
    id "${duser}" >/dev/null || module_fail coolify_remote "User ${duser} missing after adduser"
  fi

  if getent group docker >/dev/null; then
    if id -nG "${duser}" | tr ' ' '\n' | grep -qx docker; then
      log_ok "${duser} already in docker group"
    else
      run_or_die "add ${duser} to docker" usermod -aG docker "${duser}"
      log_ok "Added ${duser} to docker group"
    fi
  else
    log_info "docker group not present yet — OK for slaves; Coolify can install Docker later"
  fi

  if ! _coolify_ensure_nopasswd_sudo "${duser}"; then
    module_fail coolify_remote "Coolify requires passwordless sudo for ${duser}"
  fi

  local home sshdir ak
  home="$(getent passwd "${duser}" | cut -d: -f6)"
  [[ -n "${home}" ]] || module_fail coolify_remote "Could not resolve home for ${duser}"
  sshdir="${home}/.ssh"
  ak="${sshdir}/authorized_keys"
  run_or_die "ensure .ssh" install -d -o "${duser}" -g "${duser}" -m 700 "${sshdir}"
  run_or_die "chown home" chown "${duser}:${duser}" "${home}"
  run_or_die "chmod home" chmod 750 "${home}"

  echo
  log_info "Paste the Coolify *master* public key (.pub line), then Enter:"
  local pubkey=""
  read -r pubkey || true
  pubkey="${pubkey//$'\r'/}"
  pubkey="$(sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//' <<<"${pubkey}")"
  if [[ -z "${pubkey}" ]] || ! _is_ssh_pubkey_line "${pubkey}"; then
    module_fail coolify_remote "Invalid or empty public key — copy the pubkey from Coolify master UI"
  fi
  if [[ -f "${ak}" ]] && grep -Fqx "${pubkey}" "${ak}"; then
    log_ok "Public key already in authorized_keys"
  else
    printf '%s\n' "${pubkey}" >>"${ak}"
    log_ok "Installed Coolify master public key for ${duser}"
  fi
  run_or_die "chown authorized_keys" chown "${duser}:${duser}" "${ak}"
  run_or_die "chmod authorized_keys" chmod 600 "${ak}"

  [[ -s "${ak}" ]] || module_fail coolify_remote "authorized_keys empty"
  if command -v ssh-keygen >/dev/null; then
    ssh-keygen -lf "${ak}" || module_fail coolify_remote "ssh-keygen -lf failed"
  fi

  if ! _ensure_allowusers_includes "${duser}"; then
    module_fail coolify_remote "AllowUsers does not include ${duser} — Coolify SSH would fail"
  fi

  local port
  port="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"
  port="${port:-${SSH_PORT:-22}}"

  echo
  log_ok "Coolify remote user ready: ${duser}"
  echo "On Coolify master → Add Server:"
  echo "  Host:  this server IP/hostname"
  echo "  Port:  ${port}"
  echo "  User:  ${duser}"
  echo "  Key:   the private key matching the pubkey you just pasted"
  echo "Test from master (or any admin machine):"
  echo "  ssh -i <coolify-master-private-key> -p ${port} ${duser}@SERVER_IP"

  if confirm_test "Confirm Coolify master can SSH as ${duser}?" "n"; then
    state_set coolify_remote verified
  else
    state_set coolify_remote applied
    log_warn "Marked applied — validate from Coolify master before relying on this host"
  fi
}
