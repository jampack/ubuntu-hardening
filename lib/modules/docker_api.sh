#!/usr/bin/env bash
# Module: docker_api — §25.1 Docker API TCP exposure check

module_docker_api() {
  if ! run_module_guard docker_api "Docker API exposure check"; then
    return 0
  fi

  require_critical_gate docker_check "Docker must be installed/running first."
  require_cmd ss docker

  echo "--- listeners 2375/2376 ---"
  local exposed=0
  if ss -tulpen | grep -E '(:2375|:2376)\s'; then
    log_error "Docker API TCP listener detected on 2375/2376"
    exposed=1
  else
    log_ok "No Docker API TCP listener on 2375/2376"
  fi

  echo "--- docker info (swarm/listening) ---"
  docker info 2>/dev/null | grep -iE 'swarm|listening' || true

  echo "--- daemon.json / systemd overrides ---"
  grep -RniE 'tcp://|2375|2376|hosts?' /etc/docker/daemon.json /etc/systemd/system/docker.service.d 2>/dev/null || echo "(no matches)"

  local bad=0
  if ss -tulpen | grep -qE '0\.0\.0\.0:2375\s|\[::\]:2375\s'; then
    bad=1
    log_error "Unauthenticated Docker API appears bound on all interfaces (:2375) — critical risk"
  fi
  if [[ "${exposed}" -eq 1 ]]; then
    bad=1
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    if [[ "${bad}" -eq 1 ]]; then
      module_fail docker_api "DRY-RUN: Docker API TCP exposure detected — would fail apply"
    fi
    state_set docker_api skipped
    return 0
  fi

  if [[ "${bad}" -eq 1 ]]; then
    log_error "Remediation is manual: remove tcp:// hosts from daemon.json / systemd drop-ins, then restart docker during a maintenance window."
    log_error "Do not flush firewall rules. Retest Docker apps after any change."
    module_fail docker_api "Docker API TCP exposure on 2375/2376 — fix before continuing"
  fi

  state_set docker_api verified
}
