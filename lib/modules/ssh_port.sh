#!/usr/bin/env bash
# Module: ssh_port — runbook §11

module_ssh_port() {
  if ! run_module_guard ssh_port "SSH listen port migration"; then
    return 0
  fi

  load_config_env
  require_critical_gate ssh_hardening "SSH hardening drop-in should be in place before port migration."
  require_cmd ss sshd systemctl

  echo "SSH listen model discovery:"
  systemctl is-enabled ssh.socket ssh.service 2>/dev/null || true
  systemctl is-active ssh.socket ssh.service 2>/dev/null || true
  systemctl show ssh.socket -p Listen -p FragmentPath -p DropInPaths 2>/dev/null || true
  ss -tlnp | grep -E '(:22|:'"${SSH_PORT}"')\s' || true
  sshd -T | grep '^port ' || true

  local socket_active=0
  if systemctl is-active --quiet ssh.socket 2>/dev/null && systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
    socket_active=1
    log_info "Detected socket-activated SSH (typical Ubuntu 26.04)"
  else
    log_info "Detected traditional ssh.service-managed listener (or atypical layout)"
  fi

  # Already on target?
  if ss -tlnp | grep -qE ':'"${SSH_PORT}"'\s' && ! ss -tlnp | grep -qE ':22\s'; then
    local eff
    eff="$(sshd -T | awk '/^port /{print $2}')"
    if [[ "${eff}" == "${SSH_PORT}" || "${socket_active}" -eq 1 ]]; then
      log_ok "Already listening only on ${SSH_PORT}"
      state_set ssh_port verified
      return 0
    fi
  fi

  log_warn "HARD GATE: Confirm provider firewall ALREADY allows TCP ${SSH_PORT} before continuing."
  log_warn "Keep this session open. Do not remove TCP 22 at the provider until a new session on ${SSH_PORT} works."
  if ! confirm_token "confirm TCP ${SSH_PORT} is reachable (provider/lab firewall) before moving SSH off 22"; then
    state_set ssh_port skipped
    return 0
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN: would migrate SSH listen port to ${SSH_PORT}"
    state_set ssh_port skipped
    return 0
  fi

  if [[ "${socket_active}" -eq 1 ]]; then
    if [[ -d /etc/systemd/system/ssh.socket.d ]]; then
      backup_path /etc/systemd/system/ssh.socket.d >/dev/null
    fi
    run_or_die "mkdir ssh.socket.d" mkdir -p /etc/systemd/system/ssh.socket.d
    local listen_conf="/etc/systemd/system/ssh.socket.d/listen.conf"
    if ip -6 addr show scope global 2>/dev/null | grep -q .; then
      render_template "${HARDEN_TEMPLATES}/ssh.socket.listen.conf" "${listen_conf}"
    else
      cat >"${listen_conf}" <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:${SSH_PORT}
EOF
      log_info "No global IPv6 — wrote IPv4-only ListenStream"
    fi
    run_or_die "chmod listen.conf" chmod 644 "${listen_conf}"
    sshd -t || module_fail ssh_port "sshd -t failed before socket restart"
    run_or_die "daemon-reload" systemctl daemon-reload
    if ! confirm_token "restart ssh.socket so SSH listens on ${SSH_PORT}"; then
      state_set ssh_port applied
      log_warn "Socket drop-in written but ssh.socket not restarted yet."
      return 0
    fi
    run_or_die "restart ssh.socket" systemctl restart ssh.socket
  else
    sshd -t || module_fail ssh_port "sshd -t failed"
    if ! confirm_token "reload ssh.service so SSH listens on ${SSH_PORT}"; then
      state_set ssh_port applied
      return 0
    fi
    if ! systemctl reload ssh 2>/dev/null; then
      run_or_die "restart ssh" systemctl restart ssh
    fi
  fi

  echo "Listeners after change:"
  ss -tlnp | grep -E '(:22|:'"${SSH_PORT}"')\s' || true
  systemctl show ssh.socket -p Listen 2>/dev/null || true

  if ss -tlnp | grep -qE ':22\s' && ss -tlnp | grep -qE ':'"${SSH_PORT}"'\s'; then
    module_fail ssh_port "Both :22 and :${SSH_PORT} listening — empty ListenStream= reset likely missing. Fix before closing session."
  fi

  if ! ss -tlnp | grep -qE ':'"${SSH_PORT}"'\s'; then
    module_fail ssh_port "Port ${SSH_PORT} not listening after migration"
  fi
  log_ok "Listener present on ${SSH_PORT}"

  if ss -tlnp | grep -qE ':22\s'; then
    module_fail ssh_port "Port 22 still listening — migration incomplete"
  fi

  echo
  echo "From your client, open a NEW session BEFORE closing this one:"
  echo "  ssh -p ${SSH_PORT} -i ~/.ssh/id_ed25519 ${ADMIN_USER}@SERVER_IP"

  if confirm "Confirm new session as ${ADMIN_USER} on port ${SSH_PORT} succeeded?" "n"; then
    state_set ssh_port verified
  else
    log_warn "Marked applied — verify manually; rollback: restore ssh.socket.d backup and daemon-reload/restart"
    state_set ssh_port applied
  fi
}
