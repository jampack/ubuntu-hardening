#!/usr/bin/env bash
# Module: docker_inventory — §25.4 container ports / privilege review

module_docker_inventory() {
  if ! run_module_guard docker_inventory "Container inventory and security review"; then
    return 0
  fi

  require_critical_gate docker_check "Docker must be installed/running first."
  require_cmd docker

  echo "--- running containers ---"
  if ! docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"; then
    module_fail docker_inventory "docker ps failed"
  fi
  echo
  docker ps --format '{{.Names}} {{.Ports}}'

  local ids
  ids="$(docker ps -q)"
  if [[ -n "${ids}" ]]; then
    echo "--- privilege / user ---"
    # shellcheck disable=SC2086
    docker inspect ${ids} --format '{{.Name}} Privileged={{.HostConfig.Privileged}} ReadOnlyRootfs={{.HostConfig.ReadonlyRootfs}} User={{.Config.User}}' \
      || module_fail docker_inventory "docker inspect (privilege) failed"
    echo "--- capabilities ---"
    # shellcheck disable=SC2086
    docker inspect ${ids} --format '{{.Name}} CapAdd={{.HostConfig.CapAdd}} CapDrop={{.HostConfig.CapDrop}}' \
      || module_fail docker_inventory "docker inspect (capabilities) failed"
    echo "--- mounts (docker.sock?) ---"
    # shellcheck disable=SC2086
    docker inspect ${ids} --format '{{.Name}} {{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}' \
      | grep -E 'docker\.sock|/var/run/docker.sock' || echo "(no docker.sock mounts found in summary)"
  else
    log_error "No running containers — unexpected if you already validated Docker with a workload"
    if ! confirm "Continue inventory with zero containers?" "n"; then
      module_fail docker_inventory "No running containers"
    fi
  fi

  log_info "Review privileged containers, published ports, and socket mounts manually. Do not blind-change infra containers."
  state_set docker_inventory verified
}
