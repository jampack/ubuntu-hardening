#!/usr/bin/env bash
# Module: docker_fail2ban — §25.7 Fail2ban vs Docker firewall compatibility

module_docker_fail2ban() {
  if ! run_module_guard docker_fail2ban "Fail2ban + Docker compatibility"; then
    return 0
  fi

  require_critical_gate docker_check "Docker must be installed/running first."
  require_cmd docker

  if ! command -v fail2ban-client >/dev/null; then
    module_fail docker_fail2ban "fail2ban-client not installed — run host harden-ubuntu.sh (fail2ban module) first"
  fi

  echo "--- fail2ban sshd ---"
  if ! fail2ban-client status sshd 2>/dev/null && ! fail2ban-client status ssh 2>/dev/null; then
    module_fail docker_fail2ban "sshd/ssh jail status unavailable"
  fi
  fail2ban-client get sshd actions 2>/dev/null || fail2ban-client get ssh actions 2>/dev/null || true
  require_service_active fail2ban
  require_service_enabled fail2ban

  echo "--- docker / firewall snapshot ---"
  docker ps --format 'table {{.Names}}\t{{.Ports}}' || module_fail docker_fail2ban "docker ps failed"
  docker network ls || module_fail docker_fail2ban "docker network ls failed"
  timeout -k 3 15 iptables -S 2>/dev/null | head -n 30 || log_warn "iptables -S unavailable"
  timeout -k 3 15 iptables -t nat -S 2>/dev/null | head -n 30 || true

  log_warn "Optional controlled ban of documentation IP 198.51.100.25 only — never ban your admin IP."
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    state_set docker_fail2ban skipped
    return 0
  fi
  if confirm "Run a controlled ban/unban of 198.51.100.25 to observe nftables interaction?" "n"; then
    local myip
    myip="$(current_ssh_client_ip)"
    if [[ "${myip}" == "198.51.100.25" ]]; then
      module_fail docker_fail2ban "Refusing — documentation IP matches your client IP"
    fi
    if ! fail2ban-client set sshd banip 198.51.100.25 2>/dev/null \
      && ! fail2ban-client set ssh banip 198.51.100.25 2>/dev/null; then
      module_fail docker_fail2ban "banip 198.51.100.25 failed"
    fi
    sleep 1
    fail2ban-client status sshd 2>/dev/null || fail2ban-client status ssh 2>/dev/null || true
    if ! fail2ban-client set sshd unbanip 198.51.100.25 2>/dev/null \
      && ! fail2ban-client set ssh unbanip 198.51.100.25 2>/dev/null; then
      module_fail docker_fail2ban "unbanip 198.51.100.25 failed — clear manually"
    fi
    log_ok "Ban/unban succeeded — confirm app/container traffic still works"
  fi

  state_set docker_fail2ban verified
}
