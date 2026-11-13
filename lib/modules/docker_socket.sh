#!/usr/bin/env bash
# Module: docker_socket — §25.3 socket permissions / docker group (inspect only by default)

module_docker_socket() {
  if ! run_module_guard docker_socket "Docker socket and group"; then
    return 0
  fi

  require_critical_gate docker_check "Docker must be installed/running first."
  require_cmd stat getent

  echo "--- socket ---"
  if [[ ! -S /var/run/docker.sock ]]; then
    module_fail docker_socket "/var/run/docker.sock missing"
  fi
  stat -c '%a %U:%G %n' /var/run/docker.sock

  echo "--- docker group ---"
  if ! getent group docker; then
    module_fail docker_socket "docker group missing"
  fi
  echo "Members of docker group have root-equivalent host control."
  echo "Do not add ordinary app users. Deploy tools may rely on current docker-group access."

  local mode
  mode="$(stat -c '%a' /var/run/docker.sock)"
  if [[ "${mode}" == "666" || "${mode}" == "777" ]]; then
    module_fail docker_socket "docker.sock mode ${mode} is overly permissive"
  fi
  log_ok "docker.sock mode ${mode} is acceptable"

  state_set docker_socket verified
}
