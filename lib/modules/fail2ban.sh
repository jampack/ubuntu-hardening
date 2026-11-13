#!/usr/bin/env bash
# Module: fail2ban — runbook §13 (+ optional Postfix)

_fail2ban_configure_postfix() {
  load_config_env
  log_info "Optional Postfix outbound relay for Fail2ban/unattended mail"
  if [[ "${ASSUME_YES}" -eq 1 && -z "${SMTP_USERNAME:-}" ]]; then
    log_warn "ASSUME_YES without SMTP_USERNAME — Postfix relay not configured (explicit skip)"
    return 0
  fi
  if ! confirm "Configure Postfix + Gmail-style SMTP relay now?" "n"; then
    log_info "Postfix relay declined by operator"
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

  if confirm "Send a test email to ${SECURITY_EMAIL}?" "y"; then
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

  echo "Jail status:"
  if ! fail2ban-client status; then
    module_fail fail2ban "fail2ban-client status failed"
  fi
  if ! fail2ban-client status sshd 2>/dev/null && ! fail2ban-client status ssh 2>/dev/null; then
    module_fail fail2ban "sshd/ssh jail status unavailable — jail may not be loaded"
  fi

  local jail_port
  jail_port="$(fail2ban-client get sshd port 2>/dev/null || fail2ban-client get ssh port 2>/dev/null || true)"
  if [[ -z "${jail_port}" ]]; then
    module_fail fail2ban "Could not read fail2ban sshd jail port"
  fi
  if [[ "${jail_port}" != *"${SSH_PORT}"* ]]; then
    module_fail fail2ban "fail2ban sshd jail port='${jail_port}' — expected to include ${SSH_PORT}"
  fi
  log_ok "fail2ban sshd jail port includes ${SSH_PORT} (got: ${jail_port})"

  local myip
  myip="$(current_ssh_client_ip)"
  log_warn "Never test bans against your admin IP (${myip:-unknown}). Ban/unban validation is manual (runbook §13.12)."

  state_set fail2ban verified
}
