#!/usr/bin/env bash
# Optional Docker hardening / verification (runbook §25).
# Run after Docker is already installed and working — does not install Docker.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "${SCRIPT_DIR}/lib/common.sh"

# Separate state from host hardening
STATE_FILE="${STATE_DIR}/docker-state.env"
touch "${STATE_FILE}"
chmod 600 "${STATE_FILE}" 2>/dev/null || true

# Override module list for this orchestrator
MODULE_ORDER=(
  "docker_check|Docker / containerd presence"
  "docker_deploy_user|Deploy user + SSH key (optional)"
  "docker_api|Docker API exposure (2375/2376)"
  "docker_daemon|Daemon log rotation (optional)"
  "docker_socket|Socket permissions / docker group"
  "docker_inventory|Container inventory review"
  "docker_network|Networking / firewall inspection"
  "docker_storage|Storage and logging review"
  "docker_fail2ban|Fail2ban + Docker compatibility"
  "docker_verify|Final Docker verification"
)

source_modules

usage() {
  cat <<'EOF'
Usage: harden-docker.sh [options]

Optional Docker hardening (runbook §25). Verifies Docker/containerd, checks
API exposure (2375/2376), reviews socket/containers/networks/storage,
optionally creates a dedicated deploy user + SSH key, optionally merges
log rotation into daemon.json, and checks Fail2ban compatibility.

  (no args)       Wizard or menu depending on existing docker-state
  --wizard        Linear wizard
  --menu          Module menu
  --resume        Pending modules
  --module NAME   Single module (e.g. docker_check)
  --status        Print state
  --dry-run       Inspect-only where possible
  --yes           Auto-confirm (still warns on Docker restart)
  -h, --help      Help

Prerequisite: Docker already installed and running.
Do NOT use this script to install Docker.
EOF
}

MODE=""
MODULE_NAME=""

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --wizard) MODE="wizard"; shift ;;
      --menu) MODE="menu"; shift ;;
      --resume) MODE="resume"; shift ;;
      --module)
        MODE="module"
        MODULE_NAME="${2:-}"
        [[ -n "${MODULE_NAME}" ]] || die "--module requires a name"
        shift 2
        ;;
      --status) MODE="status"; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --yes) ASSUME_YES=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1" ;;
    esac
  done
}

run_wizard() {
  section "Docker hardening wizard"
  log_warn "Restarting Docker interrupts containers. Prefer a maintenance window."
  local entry name
  for entry in "${MODULE_ORDER[@]}"; do
    name="${entry%%|*}"
    run_one_module "${name}"
  done
  print_status
}

run_resume() {
  local entry name st
  for entry in "${MODULE_ORDER[@]}"; do
    name="${entry%%|*}"
    st="$(state_get "${name}")"
    case "${st}" in
      verified|skipped) continue ;;
      *) run_one_module "${name}" ;;
    esac
  done
  print_status
}

run_menu() {
  while true; do
    print_status
    echo "Commands: <module-name> | all | resume | status | quit"
    local choice
    read -r -p "docker-menu> " choice || true
    case "${choice}" in
      "" ) continue ;;
      quit|q|exit) break ;;
      status) print_status ;;
      all|wizard) run_wizard; break ;;
      resume) run_resume; break ;;
      *)
        if declare -F "module_${choice}" >/dev/null; then
          run_one_module "${choice}"
        else
          echo "Unknown module: ${choice}"
        fi
        ;;
    esac
  done
}

main() {
  parse_args "$@"
  require_root
  detect_os
  init_runtime
  # Re-point state after init_runtime (which may touch host state file)
  STATE_FILE="${STATE_DIR}/docker-state.env"
  touch "${STATE_FILE}"
  chmod 600 "${STATE_FILE}"

  case "${MODE}" in
    status) print_status; exit 0 ;;
    module) run_one_module "${MODULE_NAME}"; exit 0 ;;
  esac

  section "Docker hardening"
  echo "Host hardening (harden-ubuntu.sh) should already be done."
  echo "Docker must already be installed and running (this script does not install it)."
  if ! confirm "Docker is installed and a container/app works on this host?" "y"; then
    die "Install and validate Docker first, then re-run harden-docker.sh."
  fi

  if [[ -z "${MODE}" ]]; then
    if grep -qE '^docker_[a-z_]+=(verified|skipped|failed|applied)' "${STATE_FILE}" 2>/dev/null; then
      MODE="menu"
    else
      MODE="wizard"
    fi
  fi

  case "${MODE}" in
    wizard) run_wizard ;;
    menu) run_menu ;;
    resume) run_resume ;;
    *) die "Unknown mode ${MODE}" ;;
  esac
}

main "$@"
