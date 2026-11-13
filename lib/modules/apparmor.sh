#!/usr/bin/env bash
# Module: apparmor — runbook §20

module_apparmor() {
  if ! run_module_guard apparmor "AppArmor enforcement"; then
    return 0
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    aa-status 2>/dev/null | head -n 40 || true
    state_set apparmor skipped
    return 0
  fi

  install_packages apparmor apparmor-utils
  require_cmd aa-enabled aa-status systemctl
  run_or_die "enable apparmor" systemctl enable --now apparmor
  require_service_enabled apparmor
  require_service_active apparmor

  echo "AppArmor status:"
  if ! aa-enabled; then
    module_fail apparmor "AppArmor not enabled — check GRUB/cmdline (do not disable to workaround denials)"
  fi
  aa-status | head -n 60

  echo "Recent denials (journal, last matching lines):"
  journalctl -b -g apparmor -n 100 --no-pager 2>/dev/null | tail -n 40 || true
  dmesg 2>/dev/null | grep -i apparmor | tail -n 20 || true

  log_info "Correct profiles for service denials; do not disable AppArmor."
  state_set apparmor verified
}
