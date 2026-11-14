#!/usr/bin/env bash
# Module: ssh_hardening — runbook §6–§8

module_ssh_hardening() {
  if ! run_module_guard ssh_hardening "SSH hardening drop-in"; then
    return 0
  fi

  load_config_env
  require_critical_gate ssh_keys "Public-key auth must work before disabling passwords."
  require_critical_gate backup_ssh "SSH backup recommended before config changes."
  require_cmd sshd systemctl

  local dropin="/etc/ssh/sshd_config.d/00-ssh-hardening.conf"
  local keywords='Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|MaxSessions|LogLevel|TCPKeepAlive'

  log_info "Inspecting existing SSH directives (first-value-wins):"
  grep -nE "^\s*Include|^\s*(${keywords})\b" /etc/ssh/sshd_config 2>/dev/null || true
  find /etc/ssh/sshd_config.d -maxdepth 1 -type f -name '*.conf' -print 2>/dev/null | sort || true
  grep -RniE "^\s*(${keywords})\b" /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true

  # Detect competing drop-ins (excluding our target)
  local conflicts
  conflicts="$(grep -RniE "^\s*(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|MaxSessions|LogLevel|TCPKeepAlive)\b" /etc/ssh/sshd_config.d 2>/dev/null | grep -v '00-ssh-hardening.conf' || true)"
  if [[ -n "${conflicts}" ]]; then
    log_warn "Other sshd drop-ins already set Port/PasswordAuthentication/etc.:"
    echo "${conflicts}"
    echo
    echo "Why this matters: OpenSSH uses first-value-wins. If an earlier file already"
    echo "sets PasswordAuthentication yes (or Port, PermitRootLogin, …), our"
    echo "00-ssh-hardening.conf may NOT take effect for those keywords until you"
    echo "edit/remove the competing lines. This script will not delete them blindly."
    echo
    if ! confirm_proceed "Write 00-ssh-hardening.conf anyway, then verify sshd -T (mismatch = STOP)?" "n"; then
      state_set ssh_hardening skipped
      return 0
    fi
  fi

  # Idempotent check
  if [[ -f "${dropin}" ]] && sshd -t 2>/dev/null; then
    if verify_sshd_effective \
      "permitrootlogin=no" \
      "passwordauthentication=no" \
      "pubkeyauthentication=yes" \
      "kbdinteractiveauthentication=no" \
      "maxsessions=2" \
      "loglevel=VERBOSE" \
      "tcpkeepalive=no"
    then
      log_ok "Effective SSH hardening already matches targets"
      if confirm "Reload SSH anyway?" "n"; then
        run_or_die "reload SSH" systemctl reload ssh
      fi
      state_set ssh_hardening verified
      return 0
    fi
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN: would write ${dropin}"
    state_set ssh_hardening skipped
    return 0
  fi

  run_or_die "create sshd_config.d" mkdir -p /etc/ssh/sshd_config.d
  if [[ -f "${dropin}" ]]; then
    backup_path "${dropin}" >/dev/null
  fi

  render_template "${HARDEN_TEMPLATES}/00-ssh-hardening.conf" "${dropin}"
  run_or_die "chown drop-in" chown root:root "${dropin}"
  run_or_die "chmod drop-in" chmod 600 "${dropin}"

  local restore="${HARDEN_BACKUP_DIR}/$(basename "${dropin}")"
  if [[ ! -e "${restore}" ]]; then
    restore=""
  fi

  if ! sshd_test_or_restore "${restore}"; then
    module_fail ssh_hardening "SSH config validation failed (sshd -t)"
  fi

  echo "Effective settings (before reload):"
  sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|maxsessions|maxauthtries|maxstartups|loglevel|tcpkeepalive|allowtcpforwarding|allowagentforwarding|x11forwarding)'

  if ! verify_sshd_effective \
    "permitrootlogin=no" \
    "passwordauthentication=no" \
    "pubkeyauthentication=yes" \
    "kbdinteractiveauthentication=no" \
    "x11forwarding=no" \
    "allowtcpforwarding=no" \
    "allowagentforwarding=no" \
    "maxsessions=2" \
    "loglevel=VERBOSE" \
    "tcpkeepalive=no"
  then
    module_fail ssh_hardening "Effective sshd settings do NOT match hardening file (competing drop-in?). Fix conflicts, then retry."
  fi

  log_warn "Keep this session open. Test a new connection after reload."
  if ! confirm_token "reload SSH daemon so hardening takes effect"; then
    state_set ssh_hardening applied
    log_warn "Config written and verified via sshd -T, but SSH not reloaded yet."
    return 0
  fi

  run_or_die "reload SSH" systemctl reload ssh
  log_ok "SSH reloaded"

  if ! verify_sshd_effective \
    "permitrootlogin=no" \
    "passwordauthentication=no" \
    "pubkeyauthentication=yes" \
    "kbdinteractiveauthentication=no" \
    "maxsessions=2" \
    "loglevel=VERBOSE" \
    "tcpkeepalive=no"
  then
    module_fail ssh_hardening "After reload, effective sshd values still mismatch — reconcile competing drop-ins."
  fi

  state_set ssh_hardening verified
}
