#!/usr/bin/env bash
# Module: assess — initial host discovery (runbook §2)

module_assess() {
  if ! run_module_guard assess "Initial assessment"; then
    return 0
  fi

  local snap="${HARDEN_BACKUP_DIR}/assessment.txt"
  {
    echo "=== Assessment ${HARDEN_RUN_TS} ==="
    echo "--- OS ---"
    lsb_release -a 2>/dev/null || cat /etc/os-release
    echo
    echo "--- OpenSSH ---"
    ssh -V 2>&1 || true
    dpkg-query -W openssh-server 2>/dev/null || true
    echo
    echo "--- sshd -T (selected) ---"
    sshd -T 2>/dev/null | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers)' || true
    echo
    echo "--- SSH service / socket ---"
    systemctl is-enabled ssh.socket ssh.service 2>/dev/null || true
    systemctl is-active ssh.socket ssh.service 2>/dev/null || true
    ss -tlnp 2>/dev/null | grep -E 'ssh|:22|:2121' || true
    echo
    echo "--- Networking ---"
    ip -br link || true
    ip -br address || true
    ip -4 route || true
    ip -6 route || true
    echo
    echo "--- Firewall presence ---"
    if command -v ufw >/dev/null 2>&1; then
      timeout 5 ufw status verbose 2>/dev/null || echo "ufw status unavailable"
    else
      echo "ufw not installed"
    fi
    if command -v nft >/dev/null 2>&1; then
      timeout 5 nft list ruleset 2>/dev/null | head -n 40 || echo "nft ruleset unavailable"
    fi
    echo
    echo "--- Time sync ---"
    timedatectl status 2>/dev/null || true
    systemctl is-active chrony.service systemd-timesyncd.service 2>/dev/null || true
    command -v chronyc >/dev/null && chronyc tracking 2>/dev/null || true
    echo
    echo "--- Packages / sudo ---"
    dpkg-query -W openssh-server auditd fail2ban postfix unattended-upgrades apparmor chrony 2>/dev/null || true
    dpkg-query -W 'sudo*' 2>/dev/null || true
    readlink -f /usr/bin/sudo || true
    sudo --version 2>/dev/null | head -n 5 || true
    echo
    echo "--- cloud-init ---"
    command -v cloud-init >/dev/null && cloud-init status --long 2>/dev/null || echo "cloud-init not present"
    echo
    echo "--- /tmp ---"
    findmnt /tmp || true
    echo
    echo "--- Disk ---"
    df -h / || true
  } 2>&1 | tee "${snap}" || true

  log_ok "Assessment snapshot: ${snap}"
  log_warn "Provider firewall is NOT modified by this script. Review inbound rules manually (runbook §12)."
  log_warn "apt full-upgrade is intentional and interactive — run during a maintenance window if needed:"
  echo "  apt update && apt list --upgradable && apt full-upgrade"

  if confirm "Mark assessment verified?" "y"; then
    state_set assess verified
  else
    state_set assess applied
  fi
}
