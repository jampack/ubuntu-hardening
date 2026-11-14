#!/usr/bin/env bash
# Module: fail2ban — runbook §13 (+ optional Postfix)

_fail2ban_configure_postfix() {
  load_config_env
  log_info "Optional Postfix outbound relay for Fail2ban/unattended mail"
  if [[ "${ASSUME_YES}" -eq 1 && -z "${SMTP_USERNAME:-}" ]]; then
    log_warn "ASSUME_YES without SMTP_USERNAME — Postfix relay not configured (explicit skip)"
    return 0
  fi
  # --no-confirm must still stop here: credentials and the test mail come next.
  if ! confirm_test "Configure Postfix + Gmail-style SMTP relay now?" "n"; then
    log_info "Postfix relay declined by operator"
    if systemctl is-active --quiet postfix 2>/dev/null; then
      _fail2ban_send_test_mail
    fi
    return 0
  fi

  local user pass
  user="$(prompt_value "SMTP username" "${SMTP_USERNAME:-}")"
  pass="$(prompt_secret "SMTP app password (hidden)")"
  if [[ -z "${user}" || -z "${pass}" ]]; then
    module_fail fail2ban "SMTP credentials incomplete — cannot configure Postfix after you chose to apply it"
  fi

  local relay
  relay="$(prompt_value "SMTP relayhost" "${SMTP_RELAY:-[smtp.gmail.com]:587}")"
  config_set SMTP_RELAY "${relay}"
  config_set SMTP_USERNAME "${user}"
  # Do not store app password in config.env

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN: would configure Postfix relay ${relay}"
    return 0
  fi

  install_packages postfix mailutils libsasl2-modules ca-certificates
  require_cmd postconf postmap systemctl

  run_or_die "postconf relayhost" postconf -e "relayhost = ${relay}"
  run_or_die "postconf smtp_sasl_auth_enable" postconf -e 'smtp_sasl_auth_enable = yes'
  run_or_die "postconf smtp_sasl_password_maps" postconf -e 'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd'
  run_or_die "postconf smtp_sasl_security_options" postconf -e 'smtp_sasl_security_options = noanonymous'
  run_or_die "postconf smtp_tls_security_level" postconf -e 'smtp_tls_security_level = encrypt'
  run_or_die "postconf inet_interfaces" postconf -e 'inet_interfaces = loopback-only'
  run_or_die "postconf mynetworks" postconf -e 'mynetworks = 127.0.0.0/8 [::1]/128'
  run_or_die "postconf smtpd_relay_restrictions" postconf -e 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination'
  run_or_die "postconf smtpd_banner" postconf -e 'smtpd_banner = $myhostname ESMTP'

  umask 077
  printf '%s %s:%s\n' "${relay}" "${user}" "${pass}" >/etc/postfix/sasl_passwd
  run_or_die "chown sasl_passwd" chown root:root /etc/postfix/sasl_passwd
  run_or_die "chmod sasl_passwd" chmod 600 /etc/postfix/sasl_passwd
  run_or_die "postmap sasl_passwd" postmap /etc/postfix/sasl_passwd
  run_or_die "chown sasl_passwd.db" chown root:root /etc/postfix/sasl_passwd.db
  run_or_die "chmod sasl_passwd.db" chmod 600 /etc/postfix/sasl_passwd.db
  run_or_die "enable postfix" systemctl enable --now postfix
  run_or_die "restart postfix" systemctl restart postfix
  require_service_enabled postfix
  require_service_active postfix

  log_ok "Postfix configured and enabled on boot (credentials not logged)"
  echo "Listeners on :25 (expect loopback only):"
  ss -tulpn | grep ':25' || log_warn "No :25 listener visible (check postconf inet_interfaces)"
  local inet
  inet="$(postconf -h inet_interfaces)"
  if ! assert_eq "postfix inet_interfaces" "${inet}" "loopback-only"; then
    module_fail fail2ban "postfix inet_interfaces must be loopback-only (got: ${inet})"
  fi

  _fail2ban_send_test_mail
}

_fail2ban_send_test_mail() {
  load_config_env
  [[ -n "${SECURITY_EMAIL}" ]] || module_fail fail2ban "SECURITY_EMAIL is empty — cannot send a test message"
  if confirm_test "Send a test email to ${SECURITY_EMAIL}?" "y"; then
    require_cmd mail
    if ! echo "Postfix outbound-only test from harden-ubuntu.sh" | mail -s "VPS email test" "${SECURITY_EMAIL}"; then
      module_fail fail2ban "mail command failed — Postfix/SMTP relay not confirmed working"
    fi
    log_ok "Test mail submitted to ${SECURITY_EMAIL}"
  fi
}

module_fail2ban() {
  if ! run_module_guard fail2ban "Fail2ban and optional Postfix"; then
    return 0
  fi

  load_config_env

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN: would install/configure fail2ban for port ${SSH_PORT}"
    command -v fail2ban-client >/dev/null && fail2ban-client status 2>/dev/null || true
    state_set fail2ban skipped
    return 0
  fi

  install_packages fail2ban
  require_cmd fail2ban-client systemctl

  echo "Fail2ban / banaction discovery:"
  fail2ban-client --version
  grep -RniE '^(banaction|banaction_allports|backend|action)\s*=' /etc/fail2ban/jail.conf /etc/fail2ban/jail.d/ 2>/dev/null || true

  local banaction="nftables"
  if ! command -v nft >/dev/null; then
    log_error "nft (nftables) not found — required for default banaction"
    banaction="$(prompt_value "banaction to use (must exist on this host)" "iptables")"
    [[ -n "${banaction}" ]] || module_fail fail2ban "banaction required"
  else
    log_ok "nftables client present"
  fi

  if [[ -f /etc/fail2ban/jail.local ]]; then
    backup_path /etc/fail2ban/jail.local >/dev/null
  fi

  render_template "${HARDEN_TEMPLATES}/jail.local" /etc/fail2ban/jail.local
  if [[ "${banaction}" != "nftables" ]]; then
    sed -i "s/^banaction = .*/banaction = ${banaction}/" /etc/fail2ban/jail.local
    sed -i "s/^banaction_allports = .*/banaction_allports = ${banaction}[type=allports]/" /etc/fail2ban/jail.local
  fi
  run_or_die "chmod jail.local" chmod 644 /etc/fail2ban/jail.local

  _fail2ban_configure_postfix

  if ! fail2ban-client -t; then
    module_fail fail2ban "fail2ban-client -t failed — jail.local invalid"
  fi
  run_or_die "enable fail2ban" systemctl enable --now fail2ban
  run_or_die "restart fail2ban" systemctl restart fail2ban
  require_service_enabled fail2ban
  require_service_active fail2ban

  # systemd can report active before /var/run/fail2ban/fail2ban.sock exists.
  log_info "Waiting up to 15s for the fail2ban socket"
  local waited=0
  while [[ "${waited}" -lt 15 ]]; do
    if [[ -S /var/run/fail2ban/fail2ban.sock ]] && fail2ban-client ping >/dev/null 2>&1; then
      log_ok "fail2ban socket ready (${waited}s)"
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  if [[ ! -S /var/run/fail2ban/fail2ban.sock ]] || ! fail2ban-client ping >/dev/null 2>&1; then
    module_fail fail2ban "fail2ban socket not ready after 15s — check: systemctl status fail2ban"
  fi

  echo "Jail status:"
  if ! fail2ban-client status; then
    module_fail fail2ban "fail2ban-client status failed"
  fi
  if ! fail2ban-client status sshd 2>/dev/null && ! fail2ban-client status ssh 2>/dev/null; then
    module_fail fail2ban "sshd/ssh jail status unavailable — jail may not be loaded"
  fi

  # `get sshd port` is not implemented in Fail2ban 1.x (it prints
  # "Invalid command (no get action...)"). The running daemon keeps the
  # port on each action: get <jail> actions, then get <jail> action <name> port.
  local actions_raw action port saw_ban=0
  actions_raw="$(fail2ban-client get sshd actions 2>/dev/null || true)"
  if [[ -z "${actions_raw}" || "${actions_raw}" == *Invalid* || "${actions_raw}" == *Error* ]]; then
    module_fail fail2ban "Running fail2ban did not list sshd actions (got: ${actions_raw:-<empty>})"
  fi
  log_info "Running sshd actions: ${actions_raw}"
  # Fail2ban 1.1 prints prose, not a Python list:
  #   The jail sshd has the following actions:
  #   nftables, sendmail-whois-lines
  while read -r action; do
    [[ -z "${action}" || "${action}" == "sshd" ]] && continue
    case "${action}" in
      *nftables*|*iptables*|*firewall*|*ufw*|*nft*) ;;
      *)
        log_info "Skipping non-ban action ${action}"
        continue
        ;;
    esac
    port="$(fail2ban-client get sshd action "${action}" port 2>&1 || true)"
    port="$(printf '%s' "${port}" | tr -d "\r'\"[:space:]" | head -n1)"
    if [[ -z "${port}" || "${port}" == *Invalid* || "${port}" == *Error* || "${port}" == *Exception* ]]; then
      module_fail fail2ban "Running action '${action}' did not return a port (got: ${port:-<empty>})"
    fi
    saw_ban=1
    if [[ "${port}" != *"${SSH_PORT}"* ]]; then
      module_fail fail2ban "Running ban action '${action}' port='${port}' — expected ${SSH_PORT}"
    fi
    log_ok "Running ban action '${action}' port=${port}"
  done < <(printf '%s\n' "${actions_raw}" | awk '
    /following actions:/ { next }
    {
      n = split($0, a, /[,[:space:]]+/)
      for (i = 1; i <= n; i++) {
        if (a[i] ~ /^[A-Za-z][A-Za-z0-9_.-]*$/) print a[i]
      }
    }
  ')
  if [[ "${saw_ban}" -ne 1 ]]; then
    module_fail fail2ban "Running sshd jail has no nftables/iptables action exposing port ${SSH_PORT}"
  fi

  local myip
  myip="$(current_ssh_client_ip)"
  log_warn "Never test bans against your admin IP (${myip:-unknown}). Ban/unban validation is manual (runbook §13.12)."

  state_set fail2ban verified
}
