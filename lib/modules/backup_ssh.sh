#!/usr/bin/env bash
# Module: backup_ssh — runbook §3

module_backup_ssh() {
  if ! run_module_guard backup_ssh "Backup SSH configuration"; then
    return 0
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN: would back up sshd_config and drop-ins"
    state_set backup_ssh skipped
    return 0
  fi

  require_cmd sshd
  require_path /etc/ssh/sshd_config
  ls -la /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true

  backup_path /etc/ssh/sshd_config >/dev/null \
    || module_fail backup_ssh "Failed to back up /etc/ssh/sshd_config"
  if [[ ! -d /etc/ssh/sshd_config.d ]]; then
    module_fail backup_ssh "/etc/ssh/sshd_config.d missing"
  fi
  backup_path /etc/ssh/sshd_config.d >/dev/null \
    || module_fail backup_ssh "Failed to back up /etc/ssh/sshd_config.d"

  if ! sshd -T >"${HARDEN_BACKUP_DIR}/sshd-effective-config.bkp"; then
    module_fail backup_ssh "sshd -T failed while capturing effective config"
  fi
  run_or_die "chmod effective config backup" chmod 600 "${HARDEN_BACKUP_DIR}/sshd-effective-config.bkp"

  log_ok "SSH backups under ${HARDEN_BACKUP_DIR}"
  state_set backup_ssh verified
}
