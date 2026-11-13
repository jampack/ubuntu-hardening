#!/usr/bin/env bash
# Module: docker_check — §25.1 verify Docker/containerd

module_docker_check() {
  if ! run_module_guard docker_check "Docker / containerd presence"; then
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    module_fail docker_check "docker CLI not found — install Docker first (this script does not install it)"
  fi

  if ! command -v containerd >/dev/null 2>&1 && ! systemctl list-unit-files containerd.service &>/dev/null; then
    log_warn "containerd binary/unit not obviously present (may still be fine if docker manages it)"
  fi

  echo "--- docker / containerd ---"
  systemctl is-active docker 2>/dev/null || true
  systemctl is-enabled docker 2>/dev/null || true
  systemctl is-active containerd 2>/dev/null || true
  systemctl is-enabled containerd 2>/dev/null || true
  docker version | head -n 30
  docker info | head -n 40

  require_service_active docker
  require_service_enabled docker

  if ! systemctl is-active --quiet containerd 2>/dev/null; then
    module_fail docker_check "containerd.service is not active"
  fi
  log_ok "containerd is active"

  if [[ -d /data/coolify ]]; then
    log_info "Detected /data/coolify (panel data dir present)"
  fi

  if command -v snap >/dev/null && snap list docker &>/dev/null; then
    module_fail docker_check "snap docker is installed — use Docker Engine (non-snap); many installers reject snap Docker"
  fi

  log_ok "Docker appears installed and running"
  state_set docker_check verified
}
