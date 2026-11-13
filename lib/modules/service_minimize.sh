#!/usr/bin/env bash
# Module: service_minimize — runbook §21 (interactive only)

module_service_minimize() {
  if ! run_module_guard service_minimize "Service minimization"; then
    return 0
  fi

  section "Listening sockets inventory"
  ss -tulpen || true
  echo
  echo "Enabled services (subset):"
  systemctl list-unit-files --type=service --state=enabled --no-pager | head -n 80 || true

  log_warn "This module never auto-disables services. You choose units explicitly."
  log_warn "Do not disable ssh, ssh.socket, networking, chrony, auditd, fail2ban, or provider agents without review."

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    state_set service_minimize skipped
    return 0
  fi

  # Never auto-enter interactive disable under --yes (would hang on unit prompts).
  if [[ "${ASSUME_YES}" -eq 1 ]]; then
    log_warn "ASSUME_YES set — skipping interactive service disable (inventory only)"
    state_set service_minimize skipped
    return 0
  fi

  if ! confirm "Interactively disable any services now?" "n"; then
    state_set service_minimize skipped
    return 0
  fi

  local unit
  while true; do
    read -r -p "Unit to disable (empty to finish): " unit || true
    [[ -z "${unit}" ]] && break
    if [[ ! "${unit}" =~ \.service$ ]]; then
      unit="${unit}.service"
    fi
    case "${unit}" in
      ssh.service|ssh.socket|systemd-networkd.service|NetworkManager.service|chrony.service|auditd.service|fail2ban.service)
        log_error "Refusing to disable critical unit ${unit}"
        continue
        ;;
    esac
    systemctl status "${unit}" --no-pager -l || true
    if confirm_token "disable and stop ${unit}"; then
      run_or_die "disable ${unit}" systemctl disable --now "${unit}"
      if systemctl is-enabled --quiet "${unit}" 2>/dev/null; then
        module_fail service_minimize "${unit} still enabled after disable"
      fi
      log_ok "Disabled ${unit}"
    fi
  done

  echo "Post-change listeners:"
  ss -tulpen || true
  state_set service_minimize verified
}
