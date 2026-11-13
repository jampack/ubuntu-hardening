#!/usr/bin/env bash
# Module: docker_storage — §25.6 storage and logging review (no prune)

module_docker_storage() {
  if ! run_module_guard docker_storage "Docker storage and logs"; then
    return 0
  fi

  require_critical_gate docker_check "Docker must be installed/running first."
  require_cmd docker

  echo "--- system df ---"
  if ! docker system df; then
    module_fail docker_storage "docker system df failed"
  fi
  echo "--- data root ---"
  if ! docker info 2>/dev/null | grep -E 'Docker Root Dir|Storage Driver|Logging Driver'; then
    module_fail docker_storage "Could not read Docker Root Dir / Storage / Logging from docker info"
  fi
  du -sh /var/lib/docker 2>/dev/null || log_warn "du /var/lib/docker unavailable"
  findmnt /var/lib/docker 2>/dev/null || true
  df -h /var/lib/docker 2>/dev/null || df -h / || module_fail docker_storage "df failed"

  echo "--- largest container json logs (top 15) ---"
  find /var/lib/docker/containers -name '*-json.log' -type f -printf '%s %p\n' 2>/dev/null \
    | sort -nr | head -n 15 \
    | awk '{printf "%.1fMiB %s\n", $1/1024/1024, $2}' || true

  log_info "Do not prune volumes or move Docker root as a hardening shortcut."
  state_set docker_storage verified
}
