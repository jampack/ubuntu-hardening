#!/usr/bin/env bash
# Module: unattended — runbook §16

module_unattended() {
  if ! run_module_guard unattended "Unattended security updates"; then
    return 0
  fi

  load_config_env

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN: would enable unattended-upgrades + mail report"
    apt-config dump 2>/dev/null | grep -E 'APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)|Unattended-Upgrade::(Mail|MailReport|Automatic-Reboot)' || true
    state_set unattended skipped
    return 0
  fi

  install_packages unattended-upgrades apt-listchanges
  require_cmd apt-config systemctl

  local auto="/etc/apt/apt.conf.d/20auto-upgrades"
  if [[ -f "${auto}" ]]; then
    backup_path "${auto}" >/dev/null
  fi
  cat >"${auto}" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  log_ok "Wrote ${auto}"

  local drop="/etc/apt/apt.conf.d/60-hardening-unattended-upgrades"
  if [[ -f "${drop}" ]]; then
    backup_path "${drop}" >/dev/null
  fi
  render_template "${HARDEN_TEMPLATES}/60-hardening-unattended-upgrades" "${drop}"
  run_or_die "chmod unattended drop-in" chmod 644 "${drop}"

  # systemctl can hang on dbus; use timeout -k. Failure/timeout = STOP.
  if ! timeout -k 5 20 systemctl enable --now apt-daily.timer apt-daily-upgrade.timer; then
    module_fail unattended "Failed/timed out enabling apt-daily timers"
  fi
  if ! timeout -k 3 10 systemctl is-enabled --quiet apt-daily.timer; then
    module_fail unattended "apt-daily.timer is not enabled"
  fi
  if ! timeout -k 3 10 systemctl is-enabled --quiet apt-daily-upgrade.timer; then
    module_fail unattended "apt-daily-upgrade.timer is not enabled"
  fi
  log_ok "apt-daily.timer and apt-daily-upgrade.timer enabled"

  echo "Effective APT hardening keys:"
  local dump
  dump="$(apt-config dump)"
  echo "${dump}" | grep -E 'APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)|Unattended-Upgrade::(Mail|MailReport|Automatic-Reboot)' \
    || module_fail unattended "Expected APT Periodic / Unattended-Upgrade keys not found in apt-config dump"

  echo "${dump}" | grep -q 'APT::Periodic::Update-Package-Lists "1"' \
    || module_fail unattended "APT::Periodic::Update-Package-Lists is not 1"
  echo "${dump}" | grep -q 'APT::Periodic::Unattended-Upgrade "1"' \
    || module_fail unattended "APT::Periodic::Unattended-Upgrade is not 1"
  echo "${dump}" | grep -q 'Unattended-Upgrade::Automatic-Reboot "false"' \
    || module_fail unattended "Unattended-Upgrade::Automatic-Reboot must be false"

  if [[ "${ASSUME_YES}" -eq 1 ]]; then
    log_warn "ASSUME_YES set — skipping unattended-upgrade --dry-run (explicit)"
  elif confirm "Run unattended-upgrade --dry-run --debug?" "y"; then
    if ! timeout 300 unattended-upgrade --dry-run --debug; then
      module_fail unattended "unattended-upgrade --dry-run failed or timed out"
    fi
    log_ok "unattended-upgrade --dry-run completed"
  fi

  if [[ -f /var/run/reboot-required ]]; then
    log_warn "REBOOT REQUIRED flag present — plan a manual reboot"
    [[ -f /var/run/reboot-required.pkgs ]] && cat /var/run/reboot-required.pkgs || true
  else
    log_ok "No reboot-required flag"
  fi

  state_set unattended verified
}
