#!/usr/bin/env bash
# Shared helpers for Ubuntu hardening orchestrator.
# shellcheck disable=SC2034

HARDEN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARDEN_LIB="${HARDEN_ROOT}/lib"
HARDEN_MODULES="${HARDEN_LIB}/modules"
HARDEN_TEMPLATES="${HARDEN_ROOT}/templates"

CONFIG_DIR="/etc/ubuntu-hardening"
CONFIG_FILE="${CONFIG_DIR}/config.env"
STATE_DIR="/var/lib/ubuntu-hardening"
STATE_FILE="${STATE_DIR}/state.env"
LOG_DIR="/var/log/ubuntu-hardening"
BACKUP_ROOT="/root/hardening-backups"

DRY_RUN=0
ASSUME_YES=0
HARDEN_RUN_TS=""
HARDEN_LOG_FILE=""
HARDEN_BACKUP_DIR=""

# Module order for wizard (name|title)
MODULE_ORDER=(
  "assess|Initial assessment"
  "backup_ssh|Backup SSH configuration"
  "admin_user|Administrative account"
  "ssh_keys|SSH authorized keys gate"
  "ssh_hardening|SSH hardening drop-in"
  "ssh_perms|SSH filesystem permissions"
  "ssh_port|SSH listen port migration"
  "sysctl|Kernel and network sysctl"
  "fail2ban|Fail2ban and optional Postfix"
  "auditd|Auditd rules"
  "unattended|Unattended security updates"
  "apparmor|AppArmor enforcement"
  "service_minimize|Service minimization"
  "allow_users|SSH AllowUsers restriction"
  "tmp_harden|/tmp mount hardening"
  "verify|Final verification checklist"
)

# ---------------------------------------------------------------------------
# Logging / UI
# ---------------------------------------------------------------------------

_harden_ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() {
  local msg="$*"
  printf '[%s] %s\n' "$(_harden_ts)" "$msg" | tee -a "${HARDEN_LOG_FILE:-/dev/null}"
}

log_info()  { log "INFO  $*"; }
log_warn()  { log "WARN  $*"; }
log_error() { log "ERROR $*"; }
log_ok()    { log "OK    $*"; }

die() {
  log_error "$*"
  log_error "STOPPED — fix the issue, then resume (e.g. sudo ./harden-ubuntu.sh --resume or --module NAME)."
  exit 1
}

# Mark module failed, then stop the whole script.
module_fail() {
  local mod="$1"
  shift
  state_set "${mod}" failed
  die "$*"
}

# Run a mutating/security command; non-zero exit stops the script.
# usage: run_or_die "human description" cmd [args...]
run_or_die() {
  local desc="$1"
  shift
  if [[ $# -lt 1 ]]; then
    die "run_or_die: missing command for: ${desc}"
  fi
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN would: ${desc} — $*"
    return 0
  fi
  log_info "RUN: ${desc}"
  if "$@"; then
    log_ok "${desc}"
    return 0
  fi
  local rc=$?
  die "Command failed (exit ${rc}): ${desc} — $*"
}

require_service_enabled() {
  local unit="$1"
  if systemctl is-enabled --quiet "${unit}" 2>/dev/null; then
    log_ok "${unit} is enabled at boot"
    return 0
  fi
  die "${unit} is NOT enabled at boot — check: systemctl is-enabled ${unit}"
}

require_service_active() {
  local unit="$1"
  if systemctl is-active --quiet "${unit}" 2>/dev/null; then
    log_ok "${unit} is active"
    return 0
  fi
  die "${unit} is NOT active — check: systemctl status ${unit}"
}

# Assert runtime equality (e.g. sysctl). usage: assert_eq "label" got want
# Returns 1 on mismatch (does not exit). Prefer module_fail after a failed assert in modules.
assert_eq() {
  local label="$1" got="$2" want="$3"
  if [[ "${got}" == "${want}" ]]; then
    log_ok "${label}: ${got}"
    return 0
  fi
  log_error "${label}: got '${got}' — expected '${want}'"
  return 1
}

section() {
  echo
  echo "================================================================"
  log_info "$*"
  echo "================================================================"
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Run as root (sudo -i or sudo ./harden-ubuntu.sh)."
  fi
}

detect_os() {
  if [[ ! -f /etc/os-release ]]; then
    die "Cannot detect OS (/etc/os-release missing)."
  fi
  # shellcheck source=/dev/null
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    die "This script targets Ubuntu only (detected ID=${ID:-unknown})."
  fi
  if [[ "${VERSION_ID:-}" != "26.04" ]]; then
    log_warn "Designed for Ubuntu 26.04 LTS; detected ${PRETTY_NAME:-$VERSION_ID}."
    log_warn "Paths/units (ssh.socket, tmp.mount, package names) may differ — mismatches should warn or fail, not silently succeed."
    if ! confirm "Continue anyway?" "n"; then
      die "Aborted due to OS version mismatch."
    fi
  fi
  # Baseline tools we call often — fail loudly if missing
  require_cmd ip ss systemctl
}

init_runtime() {
  HARDEN_RUN_TS="$(date +%Y%m%d-%H%M%S)"
  mkdir -p "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}" "${BACKUP_ROOT}"
  chmod 700 "${CONFIG_DIR}" "${STATE_DIR}" "${BACKUP_ROOT}"
  chmod 755 "${LOG_DIR}"
  HARDEN_LOG_FILE="${LOG_DIR}/harden-${HARDEN_RUN_TS}.log"
  touch "${HARDEN_LOG_FILE}"
  chmod 600 "${HARDEN_LOG_FILE}"
  HARDEN_BACKUP_DIR="${BACKUP_ROOT}/${HARDEN_RUN_TS}"
  mkdir -p "${HARDEN_BACKUP_DIR}"
  chmod 700 "${HARDEN_BACKUP_DIR}"
  if [[ ! -f "${STATE_FILE}" ]]; then
    touch "${STATE_FILE}"
    chmod 600 "${STATE_FILE}"
  fi
  log_info "Log: ${HARDEN_LOG_FILE}"
  log_info "Backup dir for this run: ${HARDEN_BACKUP_DIR}"
}

# ---------------------------------------------------------------------------
# Config / state
# ---------------------------------------------------------------------------

config_get() {
  local key="$1" default="${2:-}"
  if [[ -f "${CONFIG_FILE}" ]]; then
    local val
    val="$(grep -E "^${key}=" "${CONFIG_FILE}" 2>/dev/null | tail -n1 | cut -d= -f2- | sed 's/^"//;s/"$//')"
    if [[ -n "${val}" ]]; then
      printf '%s' "${val}"
      return 0
    fi
  fi
  printf '%s' "${default}"
}

config_set() {
  local key="$1" value="$2"
  mkdir -p "${CONFIG_DIR}"
  touch "${CONFIG_FILE}"
  chmod 600 "${CONFIG_FILE}"
  if grep -qE "^${key}=" "${CONFIG_FILE}" 2>/dev/null; then
    # Avoid leaking secrets via sed temp files with world-readable umask: rewrite file
    local tmp
    tmp="$(mktemp)"
    chmod 600 "${tmp}"
    grep -vE "^${key}=" "${CONFIG_FILE}" >"${tmp}" || true
    printf '%s=%s\n' "${key}" "${value}" >>"${tmp}"
    mv "${tmp}" "${CONFIG_FILE}"
    chmod 600 "${CONFIG_FILE}"
  else
    printf '%s=%s\n' "${key}" "${value}" >>"${CONFIG_FILE}"
  fi
}

load_config_env() {
  if [[ -f "${CONFIG_FILE}" ]]; then
    set -a
    # shellcheck source=/dev/null
    . "${CONFIG_FILE}"
    set +a
  fi
  ADMIN_USER="${ADMIN_USER:-$(config_get ADMIN_USER)}"
  SSH_PORT="${SSH_PORT:-$(config_get SSH_PORT 2121)}"
  SECURITY_EMAIL="${SECURITY_EMAIL:-$(config_get SECURITY_EMAIL)}"
  FAIL2BAN_SENDER_EMAIL="${FAIL2BAN_SENDER_EMAIL:-$(config_get FAIL2BAN_SENDER_EMAIL)}"
  INTERFACE="${INTERFACE:-$(config_get INTERFACE)}"
  INTERFACES="${INTERFACES:-$(config_get INTERFACES)}"
  # Prefer INTERFACES; keep INTERFACE as first entry for older configs/modules.
  if [[ -z "${INTERFACES}" && -n "${INTERFACE}" ]]; then
    INTERFACES="${INTERFACE}"
  fi
  if [[ -n "${INTERFACES}" ]]; then
    INTERFACE="$(awk '{print $1}' <<<"${INTERFACES}")"
  fi
  SERVER_HOST="${SERVER_HOST:-$(config_get SERVER_HOST)}"
  ADMIN_CLIENT_IP="${ADMIN_CLIENT_IP:-$(config_get ADMIN_CLIENT_IP)}"
  SMTP_RELAY="${SMTP_RELAY:-$(config_get SMTP_RELAY '[smtp.gmail.com]:587')}"
  SMTP_USERNAME="${SMTP_USERNAME:-$(config_get SMTP_USERNAME)}"
}

# Return 0 if iface exists and is not loopback.
interface_exists() {
  local iface="$1"
  [[ -n "${iface}" && "${iface}" != "lo" && -d "/sys/class/net/${iface}" ]]
}

# Validate space-separated interface list; prints errors to stderr.
validate_interfaces() {
  local list="$1"
  local iface bad=0
  if [[ -z "${list}" ]]; then
    echo "At least one interface is required." >&2
    return 1
  fi
  for iface in ${list}; do
    if [[ "${iface}" == "lo" ]]; then
      echo "Refusing loopback interface 'lo'." >&2
      bad=1
      continue
    fi
    if [[ ! -d "/sys/class/net/${iface}" ]]; then
      echo "Unknown interface: ${iface}" >&2
      bad=1
    fi
  done
  if [[ "${bad}" -ne 0 ]]; then
    echo "Available:" >&2
    ip -br link >&2 || true
    return 1
  fi
  return 0
}

# Suggest non-lo interfaces (space-separated).
suggest_interfaces() {
  local out="" iface
  while read -r iface _; do
    [[ -z "${iface}" || "${iface}" == "lo" ]] && continue
    # strip trailing colon from `ip -br link` first column if present
    iface="${iface%:}"
    out+="${iface} "
  done < <(ip -br link 2>/dev/null || true)
  # trim
  sed -E 's/[[:space:]]+$//' <<<"${out}"
}

prompt_interfaces() {
  # IMPORTANT: callers use $(prompt_interfaces ...). Only the chosen names may go
  # to stdout; all UI/help must use stderr or it disappears into the variable.
  local default="${1:-}"
  local suggested raw
  suggested="$(suggest_interfaces)"
  [[ -z "${default}" ]] && default="${suggested}"
  echo "Available interfaces:" >&2
  ip -br link >&2 || true
  echo >&2
  echo "Why this is needed:" >&2
  echo "  Sysctl hardening sets both global and per-NIC network settings" >&2
  echo "  (e.g. disable ICMP redirects / harden rp_filter on each uplink)." >&2
  echo "  Global 'all/default' keys cover every interface; the named NICs get" >&2
  echo "  matching interface-specific lines so those values stick on the real links." >&2
  echo "  Use your public/default-route uplink(s). Do not include lo." >&2
  echo >&2
  echo "Enter one or more uplink interface names, space-separated." >&2
  while true; do
    raw="$(prompt_value "Network INTERFACES" "${default}")"
    raw="$(sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//;s/[[:space:]]+/ /g' <<<"${raw}")"
    if validate_interfaces "${raw}"; then
      printf '%s' "${raw}"
      return 0
    fi
    echo "Try again." >&2
    default="${raw}"
  done
}

state_get() {
  local module="$1"
  if [[ -f "${STATE_FILE}" ]]; then
    grep -E "^${module}=" "${STATE_FILE}" 2>/dev/null | tail -n1 | cut -d= -f2-
  fi
}

state_set() {
  local module="$1" status="$2"
  touch "${STATE_FILE}"
  chmod 600 "${STATE_FILE}"
  local tmp
  tmp="$(mktemp)"
  chmod 600 "${tmp}"
  if [[ -f "${STATE_FILE}" ]]; then
    grep -vE "^${module}=" "${STATE_FILE}" >"${tmp}" || true
  fi
  printf '%s=%s\n' "${module}" "${status}" >>"${tmp}"
  mv "${tmp}" "${STATE_FILE}"
  chmod 600 "${STATE_FILE}"
  log_info "State: ${module}=${status}"
}

print_status() {
  section "Module status"
  local entry name title st
  for entry in "${MODULE_ORDER[@]}"; do
    name="${entry%%|*}"
    title="${entry#*|}"
    st="$(state_get "${name}")"
    st="${st:-pending}"
    printf '  %-20s %-12s %s\n' "${name}" "[${st}]" "${title}"
  done
  echo
}

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

confirm() {
  local prompt="$1" default="${2:-n}"
  local hint yn
  if [[ "${ASSUME_YES}" -eq 1 ]]; then
    log_info "Auto-confirm: ${prompt}"
    return 0
  fi
  if [[ "${default}" == "y" ]]; then
    hint="Y/n"
  else
    hint="y/N"
  fi
  while true; do
    read -r -p "${prompt} [${hint}]: " yn || true
    yn="${yn:-$default}"
    case "${yn}" in
      y|Y|yes|YES) return 0 ;;
      n|N|no|NO) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

# Require typing CONFIRM (lockout-risk gates).
# usage: confirm_token "Short description of the action"
confirm_token() {
  local what="${1:-continue}"
  local token="CONFIRM"
  local answer
  if [[ "${ASSUME_YES}" -eq 1 ]]; then
    log_warn "ASSUME_YES set — skipping typed gate for: ${what}"
    return 0
  fi
  echo "About to: ${what}"
  read -r -p "Type \"${token}\" to continue: " answer || true
  # Accept with or without quotes if user types them
  answer="${answer//\"/}"
  answer="${answer//\'/}"
  if [[ "${answer}" == "${token}" ]]; then
    return 0
  fi
  log_warn "Expected \"${token}\" — aborted."
  return 1
}

prompt_choice() {
  # Prints Apply/Skip/Abort choice to stdout as: apply|skip|abort
  local prompt="${1:-Proceed with this module?}"
  local choice
  # Dry-run still enters modules so they can perform check-only logic.
  if [[ "${DRY_RUN}" -eq 1 || "${ASSUME_YES}" -eq 1 ]]; then
    echo "apply"
    return 0
  fi
  while true; do
    read -r -p "${prompt} [a]pply / [s]kip / [q]uit: " choice || true
    case "${choice}" in
      a|A|apply|APPLY) echo "apply"; return 0 ;;
      s|S|skip|SKIP) echo "skip"; return 0 ;;
      q|Q|quit|abort|ABORT) echo "abort"; return 0 ;;
      *) echo "Enter a, s, or q." >&2 ;;
    esac
  done
}

prompt_value() {
  # usage: prompt_value "Prompt" [default] [allow_empty=0|1]
  local prompt="$1" default="${2:-}" allow_empty="${3:-0}" var
  if [[ -n "${default}" ]]; then
    read -r -p "${prompt} [${default}]: " var || true
    printf '%s' "${var:-$default}"
  elif [[ "${allow_empty}" == "1" ]]; then
    read -r -p "${prompt} [optional, Enter to skip]: " var || true
    printf '%s' "${var}"
  else
    while true; do
      read -r -p "${prompt}: " var || true
      if [[ -n "${var}" ]]; then
        printf '%s' "${var}"
        return 0
      fi
      echo "Value required."
    done
  fi
}

prompt_secret() {
  local prompt="$1" var
  read -r -s -p "${prompt}: " var || true
  echo >&2
  printf '%s' "${var}"
}

ensure_config() {
  section "Configuration"
  load_config_env

  local admin port email sender ifaces host clientip
  admin="$(prompt_value "Administrative username (ADMIN_USER)" "${ADMIN_USER:-}")"
  port="$(prompt_value "SSH port" "${SSH_PORT:-2121}")"
  email="$(prompt_value "Security notification email (SECURITY_EMAIL)" "${SECURITY_EMAIL:-}")"
  sender="$(prompt_value "Fail2ban sender email" "${FAIL2BAN_SENDER_EMAIL:-$email}")"

  ifaces="$(prompt_interfaces "${INTERFACES:-${INTERFACE:-}}")"

  host="$(prompt_value "Server hostname for sshd -C checks (SERVER_HOST)" "${SERVER_HOST:-$(hostname -f 2>/dev/null || hostname)}")"
  clientip="$(prompt_value "Admin client IP for Match checks (ADMIN_CLIENT_IP)" "${ADMIN_CLIENT_IP:-}" 1)"

  config_set ADMIN_USER "${admin}"
  config_set SSH_PORT "${port}"
  config_set SECURITY_EMAIL "${email}"
  config_set FAIL2BAN_SENDER_EMAIL "${sender}"
  config_set INTERFACES "${ifaces}"
  config_set INTERFACE "$(awk '{print $1}' <<<"${ifaces}")"
  config_set SERVER_HOST "${host}"
  config_set ADMIN_CLIENT_IP "${clientip}"

  load_config_env
  log_ok "Config saved to ${CONFIG_FILE}"
  log_info "INTERFACES=${INTERFACES}"
}

# ---------------------------------------------------------------------------
# Backup / files / packages
# ---------------------------------------------------------------------------

backup_path() {
  local src="$1"
  local dest_base="${HARDEN_BACKUP_DIR}"
  mkdir -p "${dest_base}"
  if [[ ! -e "${src}" ]]; then
    log_error "Backup source missing: ${src}"
    return 1
  fi
  local base
  base="$(basename "${src}")"
  local dest="${dest_base}/${base}"
  if [[ -e "${dest}" ]]; then
    dest="${dest_base}/${base}.$(date +%s)"
  fi
  if ! cp -a "${src}" "${dest}"; then
    log_error "Backup copy failed: ${src} -> ${dest}"
    return 1
  fi
  log_ok "Backed up ${src} -> ${dest}"
  printf '%s' "${dest}"
}

render_template() {
  local template="$1" dest="$2"
  local tmp
  tmp="$(mktemp)"
  chmod 600 "${tmp}"
  # Substitute known placeholders; keep others intact
  sed \
    -e "s|ADMIN_USER|${ADMIN_USER}|g" \
    -e "s|SSH_PORT|${SSH_PORT}|g" \
    -e "s|SECURITY_EMAIL|${SECURITY_EMAIL}|g" \
    -e "s|FAIL2BAN_SENDER_EMAIL|${FAIL2BAN_SENDER_EMAIL}|g" \
    -e "s|INTERFACE|${INTERFACE}|g" \
    -e "s|SERVER_HOST|${SERVER_HOST}|g" \
    -e "s|ADMIN_CLIENT_IP|${ADMIN_CLIENT_IP}|g" \
    -e "s|SUDO_PATH|${SUDO_PATH:-/usr/bin/sudo}|g" \
    "${template}" >"${tmp}"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN would write ${dest} from $(basename "${template}")"
    rm -f "${tmp}"
    return 0
  fi
  mkdir -p "$(dirname "${dest}")"
  mv "${tmp}" "${dest}"
  log_ok "Wrote ${dest}"
}

install_packages() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN would apt install: $*"
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  run_or_die "apt-get update" apt-get update -y
  run_or_die "apt-get install $*" apt-get install -y "$@"
}

sshd_test_or_restore() {
  local restore_from="${1:-}"
  if sshd -t 2>/tmp/sshd-t.err; then
    rm -f /tmp/sshd-t.err
    log_ok "sshd -t OK"
    return 0
  fi
  log_error "sshd -t failed:"
  cat /tmp/sshd-t.err | tee -a "${HARDEN_LOG_FILE}" || true
  if [[ -n "${restore_from}" && -e "${restore_from}" ]]; then
    log_warn "Restoring from ${restore_from}"
    if [[ -d "${restore_from}" ]]; then
      rm -rf /etc/ssh/sshd_config.d
      cp -a "${restore_from}" /etc/ssh/sshd_config.d
    else
      cp -a "${restore_from}" /etc/ssh/sshd_config.d/00-ssh-hardening.conf
    fi
    sshd -t && log_ok "Restored config parses" || log_error "Restore still fails — use provider console"
  fi
  return 1
}

# Compare effective sshd -T values to intent. Args: key=want [key=want ...]
# Prints OK/MISMATCH lines; returns 1 if any mismatch. Comparison is case-insensitive.
verify_sshd_effective() {
  local pair key want have bad=0 want_l have_l
  echo "Effective sshd -T verification:"
  for pair in "$@"; do
    key="${pair%%=*}"
    want="${pair#*=}"
    have="$(sshd -T 2>/dev/null | awk -v k="${key}" 'BEGIN{key=tolower(k)} $1==key {print $2; exit}')"
    want_l="$(printf '%s' "${want}" | tr '[:upper:]' '[:lower:]')"
    have_l="$(printf '%s' "${have}" | tr '[:upper:]' '[:lower:]')"
    if [[ -n "${have}" && "${have_l}" == "${want_l}" ]]; then
      log_ok "sshd -T ${key}=${have} (expected ${want})"
    else
      log_error "sshd -T ${key}='${have:-<missing>}' — expected '${want}'"
      log_warn "Another sshd_config/drop-in likely wins (first-value-wins). Inspect with:"
      echo "  grep -RniE '^\\s*${key}\\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/"
      bad=1
    fi
  done
  return "${bad}"
}

require_cmd() {
  local c
  for c in "$@"; do
    if ! command -v "${c}" >/dev/null 2>&1; then
      die "Required command not found: ${c} (wrong OS/image or incomplete package set)"
    fi
  done
}

require_path() {
  local p
  for p in "$@"; do
    if [[ ! -e "${p}" ]]; then
      die "Required path missing: ${p}"
    fi
  done
}

current_ssh_client_ip() {
  # Prefer SSH_CLIENT / SSH_CONNECTION when present
  if [[ -n "${SSH_CLIENT:-}" ]]; then
    awk '{print $1}' <<<"${SSH_CLIENT}"
    return 0
  fi
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    awk '{print $1}' <<<"${SSH_CONNECTION}"
    return 0
  fi
  printf ''
}

module_already_verified() {
  local mod="$1"
  local st
  st="$(state_get "${mod}")"
  [[ "${st}" == "verified" ]]
}

module_blurb() {
  # Short "what this module does" text for prompts
  case "$1" in
    assess)
      echo "Discover OS, SSH, networking, time sync, and packages. Read-only snapshot; no hardening changes."
      ;;
    backup_ssh)
      echo "Timestamped backup of sshd_config, drop-ins, and effective sshd -T under /root/hardening-backups/."
      ;;
    admin_user)
      echo "Create the admin account (ADMIN_USER) if missing and add it to the sudo group. Does not reset existing passwords."
      ;;
    ssh_keys)
      echo "Install your SSH public key for ADMIN_USER (paste .pub), fix .ssh permissions, and require a working key login before disabling passwords."
      ;;
    ssh_hardening)
      echo "Write 00-ssh-hardening.conf (no root/password SSH, limits, forwarding off), validate with sshd -t/-T, then reload SSH."
      ;;
    ssh_perms)
      echo "Set correct ownership/modes on sshd_config, drop-ins, host keys, and ADMIN_USER home/.ssh/authorized_keys."
      ;;
    ssh_port)
      echo "Migrate the SSH listener to SSH_PORT (default 2121) via ssh.socket or ssh.service. Requires firewall confirmation; keep this session open."
      ;;
    sysctl)
      echo "Apply kernel/network sysctl hardening (filesystem, BPF, redirects, rp_filter) globally and on each configured INTERFACES NIC."
      ;;
    fail2ban)
      echo "Install Fail2ban SSH jail for SSH_PORT (nftables bans). Optional Postfix/SMTP for alert email — never bans your admin IP in tests."
      ;;
    auditd)
      echo "Install auditd, load persistent watch rules (SSH/identity/sudo/etc.), test while mutable, optional immutable lock (-e 2)."
      ;;
    unattended)
      echo "Enable unattended security upgrades + email reports; keep Automatic-Reboot false (manual reboots only)."
      ;;
    apparmor)
      echo "Ensure AppArmor is installed/enforcing and report recent denials. Does not disable AppArmor."
      ;;
    service_minimize)
      echo "Show listening services; optionally disable units you name. Never auto-disables SSH/networking/security services."
      ;;
    allow_users)
      echo "Restrict SSH with AllowUsers (ADMIN_USER list). Hard gate + reload; can lock out omitted accounts."
      ;;
    tmp_harden)
      echo "Harden /tmp with nodev,nosuid,noexec via tmp.mount drop-in. Can break apps that execute from /tmp."
      ;;
    verify)
      echo "Run the final host checklist (SSH, sysctl, Fail2ban, auditd, AppArmor, /tmp, etc.) and print PASS/FAIL."
      ;;
    docker_check)
      echo "Verify Docker/containerd are installed, active, and enabled at boot. Rejects snap Docker."
      ;;
    docker_deploy_user)
      echo "Optional: create a dedicated deploy user + SSH key, add to docker group, update AllowUsers if needed (CI/CD or panels)."
      ;;
    docker_api)
      echo "Check that the Docker API is not exposed on TCP 2375/2376 (critical if publicly reachable)."
      ;;
    docker_daemon)
      echo "Optionally merge json-file log rotation into daemon.json. Restarts Docker (interrupts containers) if you confirm."
      ;;
    docker_socket)
      echo "Inspect docker.sock permissions and the docker group. Does not blindly change permissions."
      ;;
    docker_inventory)
      echo "List containers, published ports, privileged mode, capabilities, and docker.sock mounts for manual review."
      ;;
    docker_network)
      echo "Inspect Docker networks and host firewall rules. Read-only — never flushes Docker iptables/nftables."
      ;;
    docker_storage)
      echo "Review Docker disk usage and container log sizes. Does not prune volumes or move the data root."
      ;;
    docker_fail2ban)
      echo "Check Fail2ban vs Docker firewall interaction; optional controlled ban of a documentation IP only."
      ;;
    docker_verify)
      echo "Final Docker checklist: daemon active, no API TCP listeners, socket perms, listeners/containers summary."
      ;;
    *)
      echo "No description registered for this module."
      ;;
  esac
}

run_module_guard() {
  # Returns 0 if should continue apply flow; sets CHOICE
  local mod="$1" title="$2"
  section "Module: ${mod} — ${title}"
  echo "What this module does:"
  echo "  $(module_blurb "${mod}")"
  echo
  if module_already_verified "${mod}"; then
    log_ok "Already verified. Re-check only."
  fi
  CHOICE="$(prompt_choice "Action for ${mod}")"
  case "${CHOICE}" in
    skip)
      state_set "${mod}" "skipped"
      log_warn "Skipped ${mod}"
      return 1
      ;;
    abort)
      die "Aborted by operator at module ${mod}"
      ;;
    apply)
      return 0
      ;;
  esac
  return 1
}

require_critical_gate() {
  # require prior module verified or skipped-with-ack
  local prior="$1" reason="$2"
  local st
  st="$(state_get "${prior}")"
  case "${st}" in
    verified) return 0 ;;
    skipped)
      log_warn "Prior module ${prior} was skipped. ${reason}"
      confirm "Acknowledge risk and continue?" "n" || die "Stopped: ${prior} not verified"
      return 0
      ;;
    *)
      log_error "Prior critical module '${prior}' is '${st:-pending}'. ${reason}"
      die "Complete '${prior}' before continuing."
      ;;
  esac
}

source_modules() {
  local f
  for f in "${HARDEN_MODULES}"/*.sh; do
    # shellcheck source=/dev/null
    . "${f}"
  done
}

module_title() {
  local want="$1" entry name title
  for entry in "${MODULE_ORDER[@]}"; do
    name="${entry%%|*}"
    title="${entry#*|}"
    if [[ "${name}" == "${want}" ]]; then
      printf '%s' "${title}"
      return 0
    fi
  done
  printf '%s' "${want}"
}

run_one_module() {
  local name="$1"
  local fn="module_${name}"
  local rc=0
  if ! declare -F "${fn}" >/dev/null; then
    die "Unknown module function: ${fn}"
  fi
  # Security script: any module failure stops the run (explicit [s]kip is OK).
  set +e
  "${fn}"
  rc=$?
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    return 0
  fi
  local st
  st="$(state_get "${name}")"
  if [[ "${st}" != "failed" ]]; then
    state_set "${name}" failed
  fi
  die "Module '${name}' failed (exit ${rc}). Fix, then: sudo ./harden-ubuntu.sh --module ${name}"
}
