#!/usr/bin/env bash
# Interactive, fail-safe, idempotent Ubuntu 26.04 server hardening orchestrator.
# Implements core controls from Ubuntu-26.04-Server-Hardening-Runbook.md
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "${SCRIPT_DIR}/lib/common.sh"
source_modules

usage() {
  cat <<'EOF'
Usage: harden-ubuntu.sh [options]

  (no args)       First run: config + linear wizard.
                  Later runs: resume menu (pending modules).
  --wizard        Force linear wizard from the start
  --menu          Interactive module menu
  --resume        Run next pending modules in order
  --module NAME   Run a single module
  --status        Print module state
  --dry-run       Check / prompt only; skip mutating apply where possible
  --yes           Auto-answer apply/confirm (dangerous; still logs warnings)
  --no-confirm    Apply every module without accept/CONFIRM prompts.
                  Still asks for required values and for lockout tests.
  --coolify-remote
                  Prepare a Coolify slave/remote deploy user (prompt for
                  username + Coolify master public key; passwordless sudo;
                  AllowUsers). No local Coolify/Docker required.
  -h, --help      Show this help

Modules:
  assess backup_ssh admin_user ssh_keys ssh_hardening ssh_perms ssh_port
  sysctl fail2ban auditd unattended apparmor service_minimize allow_users
  coolify_remote tmp_harden verify

Examples:
  sudo ./harden-ubuntu.sh
  sudo ./harden-ubuntu.sh --status
  sudo ./harden-ubuntu.sh --module ssh_hardening
  sudo ./harden-ubuntu.sh --coolify-remote
  sudo ./harden-ubuntu.sh --dry-run --menu
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
      --coolify-remote) COOLIFY_REMOTE=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1 (try --help)" ;;
    esac
  done
  # Explicit single-module run implies Coolify remote prep.
  if [[ "${MODE}" == "module" && "${MODULE_NAME}" == "coolify_remote" ]]; then
    COOLIFY_REMOTE=1
  fi
}

run_wizard() {
  section "Linear hardening wizard"
  log_info "Keep this SSH session open. Keep provider console access available."
  local entry name
  for entry in "${MODULE_ORDER[@]}"; do
    name="${entry%%|*}"
    run_one_module "${name}"
  done
  section "Wizard complete"
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
    read -r -p "menu> " choice || true
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
  if [[ "${COOLIFY_REMOTE}" -eq 1 ]]; then
    log_info "--coolify-remote: will offer Coolify slave deploy user (master pubkey + passwordless sudo)"
  fi
  load_config_env

  case "${MODE}" in
    status)
      print_status
      exit 0
      ;;
    module)
      if [[ ! -f "${CONFIG_FILE}" ]]; then
        ensure_config
      else
        load_config_env
      fi
      run_one_module "${MODULE_NAME}"
      exit 0
      ;;
  esac

  if [[ ! -f "${CONFIG_FILE}" ]] || [[ -z "$(config_get ADMIN_USER)" ]]; then
    ensure_config
  else
    section "Existing configuration"
    echo "  ADMIN_USER=${ADMIN_USER}"
    echo "  SSH_PORT=${SSH_PORT}"
    echo "  SECURITY_EMAIL=${SECURITY_EMAIL}"
    echo "  INTERFACES=${INTERFACES:-$INTERFACE}"
    if confirm "Reconfigure values?" "n"; then
      ensure_config
    else
      load_config_env
    fi
  fi

  if [[ -z "${MODE}" ]]; then
    if grep -qE '^[a-z_]+=(verified|skipped|failed|applied)' "${STATE_FILE}" 2>/dev/null; then
      MODE="menu"
    else
      MODE="wizard"
    fi
  fi

  case "${MODE}" in
    wizard) run_wizard ;;
    menu) run_menu ;;
    resume) run_resume ;;
    *) die "Internal error: unknown mode ${MODE}" ;;
  esac
}

main "$@"
