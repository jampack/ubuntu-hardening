#!/usr/bin/env bash
# Module: admin_user — runbook §4

module_admin_user() {
  if ! run_module_guard admin_user "Administrative account"; then
    return 0
  fi

  load_config_env
  [[ -n "${ADMIN_USER}" ]] || die "ADMIN_USER not set in config"
  require_cmd id adduser usermod

  if id "${ADMIN_USER}" &>/dev/null; then
    log_ok "User ${ADMIN_USER} already exists"
  else
    if [[ "${DRY_RUN}" -eq 1 ]]; then
      log_info "DRY-RUN: would create user ${ADMIN_USER}"
      state_set admin_user skipped
      return 0
    fi
    log_info "Creating user ${ADMIN_USER} (interactive adduser)"
    if ! adduser "${ADMIN_USER}"; then
      module_fail admin_user "adduser ${ADMIN_USER} failed"
    fi
    id "${ADMIN_USER}" >/dev/null || module_fail admin_user "User ${ADMIN_USER} missing after adduser"
  fi

  if id -nG "${ADMIN_USER}" | tr ' ' '\n' | grep -qx sudo; then
    log_ok "${ADMIN_USER} already in sudo group"
  else
    if [[ "${DRY_RUN}" -eq 1 ]]; then
      log_info "DRY-RUN: would add ${ADMIN_USER} to sudo"
    else
      run_or_die "add ${ADMIN_USER} to sudo" usermod -aG sudo "${ADMIN_USER}"
      id -nG "${ADMIN_USER}" | tr ' ' '\n' | grep -qx sudo \
        || module_fail admin_user "${ADMIN_USER} not in sudo group after usermod"
    fi
  fi

  id "${ADMIN_USER}"
  sudo -l -U "${ADMIN_USER}" 2>/dev/null || true
  readlink -f /usr/bin/sudo || true
  dpkg-query -W sudo sudo-rs 2>/dev/null || true

  state_set admin_user verified
}
