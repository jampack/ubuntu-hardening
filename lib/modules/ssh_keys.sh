#!/usr/bin/env bash
# Module: ssh_keys — install authorized_keys (paste) before disabling passwords

_is_ssh_pubkey_line() {
  local line="$1"
  [[ "${line}" =~ ^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+[A-Za-z0-9+/=]+ ]]
}

_fix_key_perms() {
  local home="/home/${ADMIN_USER}"
  local sshdir="${home}/.ssh"
  local ak="${sshdir}/authorized_keys"
  id "${ADMIN_USER}" &>/dev/null || die "ADMIN_USER ${ADMIN_USER} does not exist"
  run_or_die "chown home" chown "${ADMIN_USER}:${ADMIN_USER}" "${home}"
  run_or_die "chmod home" chmod 750 "${home}"
  run_or_die "ensure .ssh" install -d -o "${ADMIN_USER}" -g "${ADMIN_USER}" -m 700 "${sshdir}"
  if [[ -f "${ak}" ]]; then
    run_or_die "chown authorized_keys" chown "${ADMIN_USER}:${ADMIN_USER}" "${ak}"
    run_or_die "chmod authorized_keys" chmod 600 "${ak}"
  fi
}

_install_authorized_key() {
  local pubkey="$1"
  local sshdir="/home/${ADMIN_USER}/.ssh"
  local ak="${sshdir}/authorized_keys"

  _fix_key_perms
  if [[ -f "${ak}" ]] && grep -Fqx "${pubkey}" "${ak}" 2>/dev/null; then
    log_ok "Public key already present in ${ak}"
  else
    printf '%s\n' "${pubkey}" >>"${ak}"
    log_ok "Installed public key into ${ak}"
  fi
  run_or_die "chown authorized_keys" chown "${ADMIN_USER}:${ADMIN_USER}" "${ak}"
  run_or_die "chmod authorized_keys" chmod 600 "${ak}"
  [[ -s "${ak}" ]] || die "authorized_keys empty after install"
  if command -v ssh-keygen >/dev/null; then
    echo "Installed key fingerprint(s):"
    ssh-keygen -lf "${ak}" || die "ssh-keygen -lf failed — key file may be corrupt"
  fi
}

_current_ssh_listen_port() {
  # Prefer what is actually listening; fall back to sshd -T / config.
  local p
  if ss -tln 2>/dev/null | grep -qE ':2121\s'; then
    echo "2121"
    return 0
  fi
  if ss -tln 2>/dev/null | grep -qE ':22\s'; then
    echo "22"
    return 0
  fi
  p="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"
  echo "${p:-${SSH_PORT:-22}}"
}

_print_client_test_help() {
  local port user
  port="$(_current_ssh_listen_port)"
  user="${ADMIN_USER}"
  echo
  log_info "Password prompt usually means KEY AUTH FAILED (wrong key/path), then SSH fell back to password."
  echo
  echo "Test as user \"${user}\" on port ${port} (current listener — still often 22 before ssh_port):"
  echo "  type \$HOME\\.ssh\\id_ed25519.pub"
  echo "  ssh -i \$HOME\\.ssh\\id_ed25519 -o IdentitiesOnly=yes -p ${port} ${user}@SERVER_IP"
  echo
  echo "Notes:"
  echo "  - Paste the .pub line (public), never the private key."
  echo "  - -i must match the .pub you pasted."
  echo "  - IdentitiesOnly=yes avoids unrelated agent keys."
  echo
}

module_ssh_keys() {
  if ! run_module_guard ssh_keys "SSH authorized keys gate"; then
    return 0
  fi

  load_config_env
  require_critical_gate admin_user "Admin account required before key install."

  local ak="/home/${ADMIN_USER}/.ssh/authorized_keys"
  local test_port
  test_port="$(_current_ssh_listen_port)"

  log_info "Generate a key on your admin client if needed (runbook §5):"
  echo "  ssh-keygen -t ed25519 -a 100"
  echo "  Then paste the contents of the .pub file here (one line)."
  echo

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    if [[ -s "${ak}" ]]; then
      log_ok "DRY-RUN: ${ak} present"
      state_set ssh_keys verified
    else
      log_warn "DRY-RUN: ${ak} missing or empty"
      state_set ssh_keys skipped
    fi
    return 0
  fi

  while true; do
    if [[ -s "${ak}" ]]; then
      _fix_key_perms
      test_port="$(_current_ssh_listen_port)"
      log_ok "authorized_keys present ($(wc -l <"${ak}") line(s))"
      echo "Preview (first 120 chars of first line):"
      head -n1 "${ak}" | cut -c1-120
      command -v ssh-keygen >/dev/null && ssh-keygen -lf "${ak}" || true
      _print_client_test_help
      if confirm "Add / replace with another public key?" "n"; then
        :
      elif confirm "Did key login work for user \"${ADMIN_USER}\" on port ${test_port} WITHOUT a password prompt?" "n"; then
        state_set ssh_keys verified
        return 0
      else
        log_warn "Do not continue until: ssh -p ${test_port} ${ADMIN_USER}@SERVER_IP works with key only."
        if ! confirm "Retry / re-check?" "y"; then
          state_set ssh_keys failed
          die "SSH keys not verified — re-run: sudo ./harden-ubuntu.sh --module ssh_keys"
        fi
        continue
      fi
    else
      log_info "No authorized_keys yet — paste a public key to install."
    fi

    local pubkey=""
    echo
    echo "Paste the public key line (.pub), then press Enter:"
    read -r pubkey || true
    pubkey="${pubkey//$'\r'/}"
    pubkey="$(sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//' <<<"${pubkey}")"

    if [[ -z "${pubkey}" ]]; then
      log_warn "Empty input."
      if [[ -s "${ak}" ]]; then
        continue
      fi
      if ! confirm "Retry paste?" "y"; then
        state_set ssh_keys failed
        die "SSH keys not installed."
      fi
      continue
    fi

    if ! _is_ssh_pubkey_line "${pubkey}"; then
      log_error "That does not look like an OpenSSH public key line."
      echo "Expected: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... comment"
      if ! confirm "Try again?" "y"; then
        state_set ssh_keys failed
        die "SSH keys not installed."
      fi
      continue
    fi

    _install_authorized_key "${pubkey}"
  done
}
