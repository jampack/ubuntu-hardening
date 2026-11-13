#!/usr/bin/env bash
# Module: docker_daemon — §25.2 optional log rotation (merge, never blind overwrite)

module_docker_daemon() {
  if ! run_module_guard docker_daemon "Docker daemon.json log rotation"; then
    return 0
  fi

  require_critical_gate docker_check "Docker must be installed/running first."
  require_cmd docker systemctl python3

  local conf="/etc/docker/daemon.json"
  echo "--- current daemon config ---"
  if [[ -f "${conf}" ]]; then
    cat "${conf}"
  else
    echo "(no ${conf})"
    systemctl cat docker 2>/dev/null | head -n 40 || true
  fi
  docker info 2>/dev/null | grep -iE 'Logging Driver|Docker Root Dir' || true

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN: would optionally merge json-file log rotation into ${conf}"
    state_set docker_daemon skipped
    return 0
  fi

  log_warn "Changing daemon.json requires restarting Docker and may interrupt ALL containers."
  if ! confirm "Merge json-file log rotation (max-size 10m, max-file 3) into daemon.json?" "n"; then
    state_set docker_daemon skipped
    return 0
  fi
  if ! confirm_token "write daemon.json and restart Docker (interrupts all containers)"; then
    state_set docker_daemon skipped
    return 0
  fi

  run_or_die "mkdir /etc/docker" mkdir -p /etc/docker
  if [[ -f "${conf}" ]]; then
    backup_path "${conf}" >/dev/null || module_fail docker_daemon "Failed to back up ${conf}"
  fi

  if ! python3 - <<'PY'
import json, os
path = "/etc/docker/daemon.json"
data = {}
if os.path.exists(path):
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().strip()
        if raw:
            data = json.loads(raw)
if not isinstance(data, dict):
    raise SystemExit("daemon.json root must be an object")
hosts = data.get("hosts")
if hosts:
    raise SystemExit("daemon.json already defines hosts=...; refuse automatic edit (API exposure risk)")
data["log-driver"] = data.get("log-driver") or "json-file"
opts = data.get("log-opts") if isinstance(data.get("log-opts"), dict) else {}
opts.setdefault("max-size", "10m")
opts.setdefault("max-file", "3")
data["log-opts"] = opts
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
print("wrote", path)
PY
  then
    module_fail docker_daemon "Failed to merge log rotation into daemon.json"
  fi

  run_or_die "validate daemon.json JSON" python3 -m json.tool "${conf}"
  run_or_die "restart docker" systemctl restart docker
  require_service_active docker

  local driver
  driver="$(docker info 2>/dev/null | awk -F': ' '/Logging Driver/{print $2; exit}')"
  if [[ -z "${driver}" ]]; then
    module_fail docker_daemon "Could not read Logging Driver after restart"
  fi
  log_ok "Logging Driver: ${driver}"
  log_warn "Retest your apps/proxy/deployments before closing the window."
  state_set docker_daemon verified
}
