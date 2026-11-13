#!/usr/bin/env bash
# Module: ssh_perms — runbook §10

module_ssh_perms() {
  if ! run_module_guard ssh_perms "SSH filesystem permissions"; then
    return 0
  fi

  load_config_env
  require_cmd stat
  local dropin="/etc/ssh/sshd_config.d/00-ssh-hardening.conf"
  local home="/home/${ADMIN_USER}"
  local sshdir="${home}/.ssh"
  local ak="${sshdir}/authorized_keys"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN permission check:"
    stat -c '%a %U:%G %n' /etc/ssh /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true
    [[ -f "${dropin}" ]] && stat -c '%a %U:%G %n' "${dropin}" || true
    [[ -d "${home}" ]] && stat -c '%a %U:%G %n' "${home}" "${sshdir}" "${ak}" 2>/dev/null || true
    state_set ssh_perms skipped
    return 0
  fi

  require_path /etc/ssh/sshd_config /etc/ssh/sshd_config.d
  run_or_die "chown sshd_config" chown root:root /etc/ssh/sshd_config
  run_or_die "chmod sshd_config" chmod 644 /etc/ssh/sshd_config
  run_or_die "chown sshd_config.d" chown root:root /etc/ssh/sshd_config.d
  run_or_die "chmod sshd_config.d" chmod 755 /etc/ssh/sshd_config.d
  if [[ -f "${dropin}" ]]; then
    run_or_die "chown drop-in" chown root:root "${dropin}"
    run_or_die "chmod drop-in" chmod 600 "${dropin}"
  fi
  shopt -s nullglob
  local hk
  for hk in /etc/ssh/ssh_host_*_key; do
    run_or_die "chown ${hk}" chown root:root "${hk}"
    run_or_die "chmod ${hk}" chmod 600 "${hk}"
  done
  shopt -u nullglob

  if ! id "${ADMIN_USER}" &>/dev/null; then
    module_fail ssh_perms "Admin user ${ADMIN_USER} missing — complete admin_user first"
  fi
  require_path "${home}"
  run_or_die "chown home" chown "${ADMIN_USER}:${ADMIN_USER}" "${home}"
  run_or_die "chmod home" chmod 750 "${home}"
  run_or_die "ensure .ssh dir" install -d -o "${ADMIN_USER}" -g "${ADMIN_USER}" -m 700 "${sshdir}"
  if [[ -f "${ak}" ]]; then
    run_or_die "chown authorized_keys" chown "${ADMIN_USER}:${ADMIN_USER}" "${ak}"
    run_or_die "chmod authorized_keys" chmod 600 "${ak}"
  else
    module_fail ssh_perms "authorized_keys missing at ${ak} — complete ssh_keys first"
  fi

  echo "Validation:"
  local mode bad=0
  mode="$(stat -c '%a' /etc/ssh/sshd_config)"
  assert_eq "sshd_config mode" "${mode}" "644" || bad=1
  if [[ -f "${dropin}" ]]; then
    mode="$(stat -c '%a' "${dropin}")"
    assert_eq "drop-in mode" "${mode}" "600" || bad=1
  fi
  mode="$(stat -c '%a' "${ak}")"
  assert_eq "authorized_keys mode" "${mode}" "600" || bad=1
  mode="$(stat -c '%a' "${sshdir}")"
  assert_eq ".ssh mode" "${mode}" "700" || bad=1
  if [[ "${bad}" -ne 0 ]]; then
    module_fail ssh_perms "Permission validation failed after apply"
  fi

  stat -c '%a %U:%G %n' /etc/ssh /etc/ssh/sshd_config /etc/ssh/sshd_config.d "${home}" "${sshdir}" "${ak}"
  [[ -f "${dropin}" ]] && stat -c '%a %U:%G %n' "${dropin}"

  state_set ssh_perms verified
}
