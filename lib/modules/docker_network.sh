#!/usr/bin/env bash
# Module: docker_network — §25.5 inspect only (never flush Docker firewall rules)

module_docker_network() {
  if ! run_module_guard docker_network "Docker networking / firewall inspection"; then
    return 0
  fi

  require_critical_gate docker_check "Docker must be installed/running first."
  require_cmd docker ss

  log_warn "INSPECT ONLY — do not flush or replace Docker-managed nftables/iptables rules."
  echo "--- networks ---"
  if ! docker network ls; then
    module_fail docker_network "docker network ls failed"
  fi
  docker network inspect bridge 2>/dev/null | head -n 80 || log_warn "bridge network inspect unavailable"

  echo "--- iptables (head) ---"
  if ! timeout -k 3 15 iptables -S 2>/dev/null | head -n 40; then
    log_warn "iptables -S unavailable/timeout (continuing inspect)"
  fi
  timeout -k 3 15 iptables -t nat -S 2>/dev/null | head -n 40 || true

  echo "--- nft (head) ---"
  if command -v nft >/dev/null; then
    if ! timeout -k 3 15 nft list ruleset 2>/dev/null | head -n 60; then
      log_warn "nft list timed out/unavailable"
    fi
  else
    log_warn "nft not installed — nftables ruleset not inspected"
  fi

  echo "--- host listeners (common web/SSH) ---"
  ss -tulpen | grep -E ':(80|443|8000|6001|6002|2121|22)\s' || log_warn "No common web/SSH listeners matched (may be OK)"

  state_set docker_network verified
}
