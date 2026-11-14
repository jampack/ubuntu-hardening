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
  --no-confirm    Apply every module without accept/CONFIRM prompts.
                  Still asks for required values and for lockout tests.
  --coolify-master
                  Coolify *master* host: default deploy user coolify,
                  import SSH keys from /data/coolify/ssh/keys (additive),
                  passwordless sudo. Not for slave servers.
  -h, --help      Help

Prerequisite: Docker already installed and running.
Do NOT use this script to install Docker.
Install Coolify before --coolify-master if you want automatic key import.
Slave servers: omit --coolify-master; deploy user comes from
harden-ubuntu.sh --coolify-remote (skip docker_deploy_user).
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
      --no-confirm) NO_CONFIRM=1; shift ;;
      --coolify-master) COOLIFY_MODE=1; shift ;;
      --coolify)
        die "Flag --coolify was renamed to --coolify-master (Coolify host). Slave servers: omit it and skip docker_deploy_user if coolify_remote already ran."
        ;;
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
  section "Resume pending modules"
  local entry name st ran=0
  for entry in "${MODULE_ORDER[@]}"; do
    name="${entry%%|*}"
    st="$(state_get "${name}")"
    case "${st}" in
      verified|skipped)
        log_info "Skip ${name} (${st})"
        continue
        ;;
      *)
        log_info "Resume ${name} (${st:-pending})"
        run_one_module "${name}"
        ran=1
        ;;
    esac
  done
  if [[ "${ran}" -eq 0 ]]; then
    log_ok "Nothing pending — every module is verified or skipped"
  fi
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
  if [[ "${NO_CONFIRM}" -eq 1 ]]; then
    log_warn "--no-confirm: skipping accept/CONFIRM gates. Lockout tests still wait for your answer."
  fi
  if [[ "${COOLIFY_MODE}" -eq 1 ]]; then
    log_info "--coolify-master: deploy user defaults to coolify; prefer importing keys from /data/coolify/ssh/keys"
    if [[ ! -d /data/coolify ]]; then
      log_warn "/data/coolify not found yet — install Coolify first, then re-run with --coolify-master"
    fi
  fi
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
  if [[ "${COOLIFY_MODE}" -eq 0 && -d /data/coolify ]]; then
    # Default n: without --coolify-master, declining continues as generic Docker harden.
    if confirm "Coolify detected under /data/coolify — enable Coolify *master* mode for this run?" "n"; then
      COOLIFY_MODE=1
      log_info "Coolify master mode enabled for this run"
    else
      log_info "Continuing without Coolify master mode (pass --coolify-master to opt in)"
    fi
  fi

  # Slave prep + master flag = wrong combo
  if [[ "${COOLIFY_MODE}" -eq 1 ]]; then
    load_config_env
    local coolify_role remote_st=""
    coolify_role="$(config_get COOLIFY_ROLE "")"
    if [[ -f "${STATE_DIR}/state.env" ]]; then
      remote_st="$(grep -E '^coolify_remote=' "${STATE_DIR}/state.env" 2>/dev/null | tail -n1 | cut -d= -f2- || true)"
    fi
    if [[ "${coolify_role}" == "remote" || "${remote_st}" == "applied" || "${remote_st}" == "verified" ]]; then
      log_warn "This host was prepared as a Coolify *slave* (harden-ubuntu --coolify-remote / COOLIFY_ROLE=remote)."
      log_warn "You also enabled --coolify-master — that is for the Coolify *host*, not a remote node."
      log_warn "On slaves run: sudo ./harden-docker.sh   (without --coolify-master)"
      if ! confirm_proceed "Continue with --coolify-master anyway?" "n"; then
        die "Aborted — drop --coolify-master on Coolify slave servers"
      fi
    fi
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
