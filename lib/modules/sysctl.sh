#!/usr/bin/env bash
# Module: sysctl — runbook §12.2

module_sysctl() {
  if ! run_module_guard sysctl "Kernel and network sysctl"; then
    return 0
  fi

  load_config_env
  require_cmd sysctl
  local ifaces="${INTERFACES:-${INTERFACE:-}}"
  if [[ -z "${ifaces}" ]]; then
    die "INTERFACES not set in config — re-run config or set INTERFACES in ${CONFIG_FILE}"
  fi
  if ! validate_interfaces "${ifaces}"; then
    die "Fix INTERFACES in ${CONFIG_FILE}"
  fi

  local conf="/etc/sysctl.d/99-hardening.conf"
  log_info "Applying sysctl for interfaces: ${ifaces}"
  log_info "Competing sysctl settings:"
  grep -RniE '^(fs\.protected_fifos|fs\.suid_dumpable|kernel\.kptr_restrict|kernel\.unprivileged_bpf_disabled|net\.core\.bpf_jit_harden|net\.ipv4\.conf|net\.ipv6\.conf)' /etc/sysctl.conf /etc/sysctl.d 2>/dev/null || true

  _sysctl_matches() {
    local k iface key want have
    for k in \
      fs.protected_fifos=2 \
      fs.suid_dumpable=0 \
      kernel.kptr_restrict=2 \
      kernel.unprivileged_bpf_disabled=1 \
      net.core.bpf_jit_harden=2 \
      net.ipv4.conf.all.accept_redirects=0 \
      net.ipv4.conf.all.rp_filter=2
    do
      key="${k%%=*}"
      want="${k#*=}"
      have="$(sysctl -n "${key}" 2>/dev/null || echo missing)"
      [[ "${have}" == "${want}" ]] || return 1
    done
    for iface in ${ifaces}; do
      for k in \
        "net.ipv4.conf.${iface}.accept_redirects=0" \
        "net.ipv4.conf.${iface}.send_redirects=0" \
        "net.ipv4.conf.${iface}.log_martians=1" \
        "net.ipv6.conf.${iface}.accept_redirects=0"
      do
        key="${k%%=*}"
        want="${k#*=}"
        have="$(sysctl -n "${key}" 2>/dev/null || echo missing)"
        [[ "${have}" == "${want}" ]] || return 1
      done
    done
    return 0
  }

  _sysctl_verify_all() {
    local k iface key want have bad=0
    for k in \
      fs.protected_fifos=2 \
      fs.suid_dumpable=0 \
      kernel.kptr_restrict=2 \
      kernel.unprivileged_bpf_disabled=1 \
      net.core.bpf_jit_harden=2 \
      net.ipv4.conf.all.accept_redirects=0 \
      net.ipv4.conf.all.rp_filter=2
    do
      key="${k%%=*}"
      want="${k#*=}"
      have="$(sysctl -n "${key}" 2>/dev/null || echo missing)"
      assert_eq "sysctl ${key}" "${have}" "${want}" || bad=1
    done
    for iface in ${ifaces}; do
      for k in \
        "net.ipv4.conf.${iface}.accept_redirects=0" \
        "net.ipv4.conf.${iface}.send_redirects=0" \
        "net.ipv4.conf.${iface}.log_martians=1" \
        "net.ipv6.conf.${iface}.accept_redirects=0"
      do
        key="${k%%=*}"
        want="${k#*=}"
        have="$(sysctl -n "${key}" 2>/dev/null || echo missing)"
        assert_eq "sysctl ${key}" "${have}" "${want}" || bad=1
      done
    done
    return "${bad}"
  }

  if [[ -f "${conf}" ]] && _sysctl_matches; then
    log_ok "Sysctl hardening already effective for: ${ifaces}"
    state_set sysctl verified
    return 0
  fi
  if [[ -f "${conf}" ]]; then
    log_info "Sysctl not fully matching yet — will (re)apply ${conf}"
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN: would write ${conf} for INTERFACES=${ifaces}"
    state_set sysctl skipped
    return 0
  fi

  if [[ -f "${conf}" ]]; then
    backup_path "${conf}" >/dev/null
  fi

  render_template "${HARDEN_TEMPLATES}/99-hardening.conf" "${conf}"
  {
    echo
    echo "# Per-interface hardening ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    for iface in ${ifaces}; do
      cat <<EOF
net.ipv4.conf.${iface}.accept_redirects = 0
net.ipv4.conf.${iface}.send_redirects = 0
net.ipv4.conf.${iface}.log_martians = 1
net.ipv6.conf.${iface}.accept_redirects = 0
EOF
    done
  } >>"${conf}"

  run_or_die "chown sysctl conf" chown root:root "${conf}"
  run_or_die "chmod sysctl conf" chmod 644 "${conf}"

  if ! sysctl --system; then
    module_fail sysctl "sysctl --system reported errors — review and restore backup if needed"
  fi

  echo "Runtime values (global + per interface) — verifying:"
  if ! _sysctl_verify_all; then
    module_fail sysctl "Runtime sysctl values do not match intent after apply"
  fi
  state_set sysctl verified
}
