#!/usr/bin/env bash
# Module: auditd — runbook §15.1

module_auditd() {
  if ! run_module_guard auditd "Auditd rules"; then
    return 0
  fi

  load_config_env
  export SUDO_PATH
  SUDO_PATH="$(readlink -f /usr/bin/sudo 2>/dev/null || echo /usr/bin/sudo)"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN: would install auditd and write 99-hardening.rules (SUDO_PATH=${SUDO_PATH})"
    auditctl -s 2>/dev/null || true
    state_set auditd skipped
    return 0
  fi

  install_packages auditd
  require_cmd auditctl augenrules systemctl
  run_or_die "enable auditd" systemctl enable --now auditd
  require_service_enabled auditd
  require_service_active auditd

  local enabled
  enabled="$(auditctl -s 2>/dev/null | awk '/^enabled/{print $2}')"
  log_info "auditctl enabled=${enabled:-unknown}"
  [[ -n "${enabled}" ]] || module_fail auditd "Could not read auditctl -s enabled state"

  if [[ "${enabled}" == "2" ]]; then
    log_warn "Audit rules are IMMUTABLE. Will update persistent files only; apply via controlled reboot."
  fi

  backup_path /etc/audit/rules.d >/dev/null
  [[ -f /etc/audit/audit.rules ]] && backup_path /etc/audit/audit.rules >/dev/null

  local rules="/etc/audit/rules.d/99-hardening.rules"
  render_template "${HARDEN_TEMPLATES}/99-hardening.rules" "${rules}"

  # Drop watches for paths that do not exist (explicit log per omission)
  local tmp omitted=0
  tmp="$(mktemp)"
  chmod 600 "${tmp}"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ "${line}" =~ ^-w[[:space:]]+([^[:space:]]+) ]]; then
      local path="${BASH_REMATCH[1]}"
      if [[ ! -e "${path}" ]]; then
        log_warn "Omitting missing path watch: ${path}"
        omitted=$((omitted + 1))
        continue
      fi
    fi
    printf '%s\n' "${line}" >>"${tmp}"
  done <"${rules}"
  mv "${tmp}" "${rules}"
  run_or_die "chown audit rules" chown root:root "${rules}"
  run_or_die "chmod audit rules" chmod 640 "${rules}"
  if [[ "${omitted}" -gt 0 ]]; then
    log_warn "Omitted ${omitted} watch(es) for missing paths — continuing with remaining rules"
  fi

  if confirm "Apply recommended auditd.conf retention settings (8MB x 5)?" "n"; then
    require_path /etc/audit/auditd.conf
    backup_path /etc/audit/auditd.conf >/dev/null
    local kv
    for kv in \
      'write_logs = yes' \
      'log_format = ENRICHED' \
      'max_log_file = 8' \
      'num_logs = 5' \
      'max_log_file_action = ROTATE' \
      'space_left_action = SYSLOG' \
      'admin_space_left_action = SUSPEND' \
      'disk_full_action = SUSPEND' \
      'disk_error_action = SUSPEND'
    do
      local key="${kv%% =*}"
      if grep -qE "^${key}\s*=" /etc/audit/auditd.conf; then
        sed -i -E "s|^${key}\s*=.*|${kv}|" /etc/audit/auditd.conf
      else
        echo "${kv}" >>/etc/audit/auditd.conf
      fi
    done
    log_ok "auditd.conf retention settings applied"
  fi

  run_or_die "augenrules" augenrules
  if ! augenrules --check; then
    module_fail auditd "augenrules --check reported issues"
  fi
  grep -nE 'ssh_authorized_keys|-e 2|^-f |^-b ' /etc/audit/audit.rules || true

  if [[ "${enabled}" == "2" ]]; then
    log_warn "Immutable: reboot required to load new rules. Do not augenrules --load."
    state_set auditd applied
    return 0
  fi

  if ! confirm "Load audit rules now (mutable)?" "y"; then
    state_set auditd applied
    log_warn "Rules written but not loaded yet (operator declined load)."
    return 0
  fi

  run_or_die "augenrules --load" augenrules --load
  auditctl -l | head -n 40
  auditctl -s

  log_info "Functional smoke test: touch temporary file under watched /etc/ssh/sshd_config.d"
  local probe="/etc/ssh/sshd_config.d/.harden-audit-probe.$$"
  run_or_die "create audit probe file" touch "${probe}"
  sleep 1
  if ! ausearch -k sshd_config -ts recent 2>/dev/null | tail -n 5 | tee -a "${HARDEN_LOG_FILE}"; then
    rm -f "${probe}"
    module_fail auditd "ausearch did not show expected sshd_config events after probe"
  fi
  log_ok "Audit events searchable for sshd_config"
  rm -f "${probe}"

  if confirm "Enable immutable audit lock (-e 2)? Requires typed confirm." "n"; then
    if ! confirm_token "enable immutable audit lock (-e 2) — rule changes need reboot afterward"; then
      state_set auditd verified
      return 0
    fi
    sed -i 's/^# -e 2$/-e 2/' "${rules}"
    run_or_die "augenrules after -e 2" augenrules
    if ! augenrules --check; then
      module_fail auditd "augenrules --check failed after enabling -e 2"
    fi
    tail -n 5 /etc/audit/audit.rules
    if ! grep -qE '^-e 2$' /etc/audit/audit.rules; then
      module_fail auditd "Generated rules do not end with -e 2"
    fi
    run_or_die "augenrules --load immutable" augenrules --load
    auditctl -s
    log_ok "Audit immutable mode requested"
  fi

  state_set auditd verified
}
