#!/usr/bin/env bash
# Module: allow_users — runbook §22

module_allow_users() {
  if ! run_module_guard allow_users "SSH AllowUsers restriction"; then
    return 0
  fi

  load_config_env
  require_critical_gate ssh_hardening "SSH drop-in should exist before AllowUsers."
  require_critical_gate ssh_keys "Key auth must work for allowed users."
  require_cmd sshd systemctl

  local dropin="/etc/ssh/sshd_config.d/00-ssh-hardening.conf"
  require_path "${dropin}"

  echo "Existing AllowUsers/AllowGroups/Deny*:"
  grep -RniE '^\s*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true

  local users
  users="$(prompt_value "AllowUsers list (space-separated)" "${ADMIN_USER}")"
  [[ -n "${users}" ]] || module_fail allow_users "AllowUsers list cannot be empty"

  log_warn "HARD GATE: accounts omitted from AllowUsers cannot SSH."
  log_warn "Keep this session open; test a new session after reload."
  if ! confirm_token "write AllowUsers ${users} into the SSH hardening drop-in"; then
    state_set allow_users skipped
    return 0
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN: would set AllowUsers ${users}"
    state_set allow_users skipped
    return 0
  fi

  backup_path "${dropin}" >/dev/null

  local tmp
  tmp="$(mktemp)"
  chmod 600 "${tmp}"
  grep -vE '^\s*AllowUsers\b' "${dropin}" >"${tmp}" || true
  printf '\nAllowUsers %s\n' "${users}" >>"${tmp}"
  mv "${tmp}" "${dropin}"
  run_or_die "chown drop-in" chown root:root "${dropin}"
  run_or_die "chmod drop-in" chmod 600 "${dropin}"

  if ! sshd_test_or_restore "${HARDEN_BACKUP_DIR}/00-ssh-hardening.conf"; then
    module_fail allow_users "sshd -t failed after AllowUsers"
  fi

  sshd -T | grep -i '^allowusers' || true
  if [[ -n "${ADMIN_CLIENT_IP}" && -n "${SERVER_HOST}" ]]; then
    sshd -T -C "user=${ADMIN_USER},host=${SERVER_HOST},addr=${ADMIN_CLIENT_IP},lport=${SSH_PORT}" \
      | grep -iE '^(allowusers|permitrootlogin|passwordauthentication)' || true
  fi

  local au
  au="$(sshd_allowusers_effective)"
  if ! sshd_allowusers_includes "${ADMIN_USER}"; then
    module_fail allow_users "Effective allowusers does not include ${ADMIN_USER}: ${au:-<missing>} (competing directive?)"
  fi
  log_ok "Effective allowusers includes ${ADMIN_USER} (${au})"

  if ! confirm_token "reload SSH to apply AllowUsers"; then
    state_set allow_users applied
    log_warn "AllowUsers written and verified via sshd -T, but SSH not reloaded yet."
    return 0
  fi
  run_or_die "reload SSH" systemctl reload ssh

  au="$(sshd_allowusers_effective)"
  if ! sshd_allowusers_includes "${ADMIN_USER}"; then
    module_fail allow_users "After reload, allowusers still wrong: ${au:-<missing>}"
  fi

  if confirm_test "Confirm ${ADMIN_USER} can still open a new SSH session?" "n"; then
    state_set allow_users verified
  else
    log_warn "If locked out, restore drop-in from ${HARDEN_BACKUP_DIR} via console"
    state_set allow_users applied
  fi
}
