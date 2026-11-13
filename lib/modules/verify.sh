#!/usr/bin/env bash
# Module: verify — runbook §17 checklist

module_verify() {
  if ! run_module_guard verify "Final verification checklist"; then
    return 0
  fi

  load_config_env
  local pass=0 fail=0
  local report="${HARDEN_BACKUP_DIR}/verification-report.txt"

  _check() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
      echo "PASS  ${name}" | tee -a "${report}"
      pass=$((pass + 1))
    else
      echo "FAIL  ${name}" | tee -a "${report}"
      fail=$((fail + 1))
    fi
  }

  _expect_module() {
    # If module was explicitly skipped, do not fail the checklist for its controls.
    local mod="$1"
    local st
    st="$(state_get "${mod}")"
    case "${st}" in
      skipped)
        echo "INFO  ${mod} was skipped by operator — related checks omitted" | tee -a "${report}"
        return 1
        ;;
      *)
        return 0
        ;;
    esac
  }

  : >"${report}"
  section "Verification report"

  echo "--- 17.1 SSH config ---" | tee -a "${report}"
  _check "sshd -t" sshd -t
  sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|maxsessions|loglevel|tcpkeepalive)' | tee -a "${report}" || true
  if _expect_module ssh_hardening; then
    _check "permitrootlogin=no" bash -c "sshd -T | grep -qiE '^permitrootlogin no\$'"
    _check "passwordauthentication=no" bash -c "sshd -T | grep -qiE '^passwordauthentication no\$'"
    _check "pubkeyauthentication=yes" bash -c "sshd -T | grep -qiE '^pubkeyauthentication yes\$'"
  fi
  if _expect_module ssh_port; then
    _check "SSH_PORT listener ${SSH_PORT}" bash -c "ss -tlnp | grep -qE ':${SSH_PORT}\\s'"
  fi

  echo "--- 17.2 Permissions ---" | tee -a "${report}"
  if _expect_module ssh_perms; then
    _check "sshd_config 644" bash -c "stat -c '%a' /etc/ssh/sshd_config | grep -qx 644"
    if [[ -f /etc/ssh/sshd_config.d/00-ssh-hardening.conf ]]; then
      _check "hardening drop-in 600" bash -c "stat -c '%a' /etc/ssh/sshd_config.d/00-ssh-hardening.conf | grep -qx 600"
    else
      echo "FAIL  hardening drop-in missing" | tee -a "${report}"
      fail=$((fail + 1))
    fi
  fi
  if _expect_module ssh_keys; then
    if [[ -f "/home/${ADMIN_USER}/.ssh/authorized_keys" ]]; then
      _check "authorized_keys 600" bash -c "stat -c '%a' /home/${ADMIN_USER}/.ssh/authorized_keys | grep -qx 600"
    else
      echo "FAIL  authorized_keys missing" | tee -a "${report}"
      fail=$((fail + 1))
    fi
  fi

  echo "--- 17.3 Listeners / firewall presence ---" | tee -a "${report}"
  ss -tlnp | tee -a "${report}" || true
  ufw status verbose 2>/dev/null | tee -a "${report}" || true
  echo "NOTE: Provider firewall not validated by this script." | tee -a "${report}"

  echo "--- 17.4 Sysctl ---" | tee -a "${report}"
  if _expect_module sysctl; then
    _check "fs.protected_fifos=2" bash -c "[[ \$(sysctl -n fs.protected_fifos) == 2 ]]"
    _check "kernel.kptr_restrict=2" bash -c "[[ \$(sysctl -n kernel.kptr_restrict) == 2 ]]"
  fi

  echo "--- 17.5 Fail2ban ---" | tee -a "${report}"
  if _expect_module fail2ban; then
    if command -v fail2ban-client >/dev/null; then
      _check "fail2ban active" systemctl is-active fail2ban
      _check "fail2ban enabled" systemctl is-enabled fail2ban
      fail2ban-client status 2>/dev/null | tee -a "${report}" || true
    else
      echo "FAIL  fail2ban-client not installed" | tee -a "${report}"
      fail=$((fail + 1))
    fi
  fi

  echo "--- 17.6 Postfix ---" | tee -a "${report}"
  if systemctl is-active --quiet postfix 2>/dev/null; then
    postconf -n | grep -E 'inet_interfaces|relayhost|smtp_sasl_auth_enable' | tee -a "${report}" || true
    _check "postfix loopback-only" bash -c "postconf -h inet_interfaces | grep -q loopback"
    _check "postfix enabled" systemctl is-enabled postfix
  else
    echo "INFO  postfix inactive (OK if you declined SMTP relay)" | tee -a "${report}"
  fi

  echo "--- 17.7 Unattended upgrades ---" | tee -a "${report}"
  if _expect_module unattended; then
    apt-config dump 2>/dev/null | grep -E 'APT::Periodic::Unattended-Upgrade|Unattended-Upgrade::Automatic-Reboot' | tee -a "${report}" || true
    _check "Automatic-Reboot false" bash -c "apt-config dump | grep -q 'Unattended-Upgrade::Automatic-Reboot \"false\"'"
    _check "Unattended-Upgrade 1" bash -c "apt-config dump | grep -q 'APT::Periodic::Unattended-Upgrade \"1\"'"
  fi

  echo "--- 17.9 Auditd ---" | tee -a "${report}"
  if _expect_module auditd; then
    if command -v auditctl >/dev/null; then
      _check "auditd active" systemctl is-active auditd
      _check "auditd enabled" systemctl is-enabled auditd
      auditctl -s 2>/dev/null | tee -a "${report}" || true
    else
      echo "FAIL  auditctl not installed" | tee -a "${report}"
      fail=$((fail + 1))
    fi
  fi

  echo "--- 17.11 AppArmor ---" | tee -a "${report}"
  if _expect_module apparmor; then
    _check "apparmor enabled" aa-enabled
    _check "apparmor active" systemctl is-active apparmor
  fi

  echo "--- 17.13 AllowUsers ---" | tee -a "${report}"
  if _expect_module allow_users; then
    if sshd -T | grep -qi '^allowusers'; then
      sshd -T | grep -i '^allowusers' | tee -a "${report}"
      _check "allowusers includes ADMIN_USER" bash -c "sshd -T | awk '/^allowusers /{print tolower(\$0)}' | grep -q \"$(echo "${ADMIN_USER}" | tr '[:upper:]' '[:lower:]')\""
    else
      echo "FAIL  allowusers not set" | tee -a "${report}"
      fail=$((fail + 1))
    fi
  fi

  echo "--- 17.14 /tmp ---" | tee -a "${report}"
  if _expect_module tmp_harden; then
    findmnt /tmp | tee -a "${report}" || true
    _check "/tmp noexec" bash -c "findmnt -no OPTIONS /tmp | tr ',' '\n' | grep -qx noexec"
    _check "/tmp nosuid" bash -c "findmnt -no OPTIONS /tmp | tr ',' '\n' | grep -qx nosuid"
    _check "/tmp nodev" bash -c "findmnt -no OPTIONS /tmp | tr ',' '\n' | grep -qx nodev"
  fi

  echo "--- 17.15 Time sync ---" | tee -a "${report}"
  timedatectl status 2>/dev/null | tee -a "${report}" || true

  echo "--- 17.16 Reboot flag ---" | tee -a "${report}"
  if [[ -f /var/run/reboot-required ]]; then
    echo "WARN  reboot required" | tee -a "${report}"
  else
    echo "OK    no reboot-required flag" | tee -a "${report}"
  fi

  echo | tee -a "${report}"
  echo "Summary: PASS=${pass} FAIL=${fail}" | tee -a "${report}"
  print_status | tee -a "${report}"
  log_info "Full report: ${report}"

  if [[ "${fail}" -eq 0 ]]; then
    state_set verify verified
    log_ok "All verification checks passed"
  else
    module_fail verify "Verification found ${fail} failure(s) — review ${report}"
  fi
}
