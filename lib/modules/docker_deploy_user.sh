#!/usr/bin/env bash
# Module: docker_deploy_user — optional dedicated deploy user + SSH key

_is_ssh_pubkey_line() {
  local line="$1"
  [[ "${line}" =~ ^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+[A-Za-z0-9+/=]+ ]]
}

_ensure_allowusers_includes() {
  local user="$1"
  local dropin="/etc/ssh/sshd_config.d/00-ssh-hardening.conf"
  local eff
  eff="$(sshd -T 2>/dev/null | awk '/^allowusers /{print; exit}')"
  if [[ -z "${eff}" ]]; then
    log_info "No AllowUsers in effect — deploy user can SSH without AllowUsers change"
    return 0
  fi
  if awk '{for(i=2;i<=NF;i++) if($i==u) found=1} END{exit !found}' u="${user}" <<<"${eff}"; then
    log_ok "AllowUsers already includes ${user}"
    return 0
  fi
  log_warn "AllowUsers is active and does NOT include ${user} — deploy SSH will fail until fixed."
  if [[ ! -f "${dropin}" ]]; then
    log_error "Missing ${dropin}; add ${user} to AllowUsers manually"
    return 1
  fi
  if ! confirm "Append ${user} to AllowUsers in ${dropin} and reload SSH?" "y"; then
    return 1
  fi
  backup_path "${dropin}" >/dev/null || return 1
  if grep -qE '^\s*AllowUsers\b' "${dropin}"; then
    local tmp
    tmp="$(mktemp)"
    chmod 600 "${tmp}"
    awk -v u="${user}" '
      BEGIN{done=0}
      /^\s*AllowUsers\b/ {
        line=$0
        if (index(" " line " ", " " u " ")==0) { line=line " " u }
        print line
        done=1
        next
      }
      { print }
      END{ if(!done) print "AllowUsers " u }
    ' "${dropin}" >"${tmp}"
    mv "${tmp}" "${dropin}"
  else
    printf '\nAllowUsers %s %s\n' "${ADMIN_USER:-}" "${user}" >>"${dropin}"
  fi
  chown root:root "${dropin}"
  chmod 600 "${dropin}"
  if ! sshd -t; then
    log_error "sshd -t failed after AllowUsers edit"
    return 1
  fi
  if ! confirm_token "reload SSH to apply AllowUsers including ${user}"; then
    log_error "AllowUsers updated but SSH not reloaded — deploy login will fail until reload"
    return 1
  fi
  systemctl reload ssh 2>/dev/null || systemctl reload ssh.service || return 1
  eff="$(sshd -T 2>/dev/null | awk '/^allowusers /{print tolower($0); exit}')"
  local user_l
  user_l="$(printf '%s' "${user}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${eff}" != *"${user_l}"* ]]; then
    log_error "After reload, allowusers still missing ${user}: ${eff:-<missing>}"
    return 1
  fi
  log_ok "SSH reloaded with AllowUsers including ${user}"
}

module_docker_deploy_user() {
  if ! run_module_guard docker_deploy_user "Deploy user + SSH key (optional)"; then
    return 0
  fi

  load_config_env
  require_cmd id adduser usermod getent install

  local duser
  duser="$(config_get DEPLOY_USER "")"
  duser="$(prompt_value "Deploy username (CI/CD or panel)" "${duser:-deploy}")"
  config_set DEPLOY_USER "${duser}"

  if [[ "${duser}" == "root" ]]; then
    die "Refusing to use root as deploy user"
  fi
  if [[ -n "${ADMIN_USER:-}" && "${duser}" == "${ADMIN_USER}" ]]; then
    log_warn "Deploy user equals ADMIN_USER (${duser}) — shared admin/deploy identity"
    if ! confirm "Continue with the same account?" "n"; then
      state_set docker_deploy_user skipped
      return 0
    fi
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN: would ensure user ${duser}, docker group, authorized_keys"
    state_set docker_deploy_user skipped
    return 0
  fi

  if id "${duser}" &>/dev/null; then
    log_ok "User ${duser} already exists"
  else
    log_info "Creating system-style deploy user ${duser} (no interactive GECOS)"
    run_or_die "adduser ${duser}" adduser --disabled-password --gecos "Deploy" "${duser}"
    id "${duser}" >/dev/null || module_fail docker_deploy_user "User ${duser} missing after adduser"
  fi

  if ! getent group docker >/dev/null; then
    module_fail docker_deploy_user "docker group missing — install/start Docker first"
  fi
  if id -nG "${duser}" | tr ' ' '\n' | grep -qx docker; then
    log_ok "${duser} already in docker group"
  else
    run_or_die "add ${duser} to docker" usermod -aG docker "${duser}"
    id -nG "${duser}" | tr ' ' '\n' | grep -qx docker \
      || module_fail docker_deploy_user "${duser} not in docker group after usermod"
  fi

  if id -nG "${duser}" | tr ' ' '\n' | grep -qx sudo; then
    log_warn "${duser} is in sudo group — consider removing if not required"
  fi

  local home sshdir ak
  home="$(getent passwd "${duser}" | cut -d: -f6)"
  [[ -n "${home}" ]] || module_fail docker_deploy_user "Could not resolve home for ${duser}"
  sshdir="${home}/.ssh"
  ak="${sshdir}/authorized_keys"
  run_or_die "ensure .ssh" install -d -o "${duser}" -g "${duser}" -m 700 "${sshdir}"
  run_or_die "chown home" chown "${duser}:${duser}" "${home}"
  run_or_die "chmod home" chmod 750 "${home}"

  echo
  log_info "Install the public key your deploy tool will use to SSH as ${duser}."
  echo "Paste a controlled keypair .pub line (panel 'Add Server', CI, or your admin keypair)."
  echo

  local mode
  echo "Key source:"
  echo "  [1] Paste public key (.pub line)"
  echo "  [2] Generate ed25519 keypair on this host (copy private key to the deploy tool; less ideal)"
  read -r -p "Choice [1]: " mode || true
  mode="${mode:-1}"

  case "${mode}" in
    2)
      require_cmd ssh-keygen
      local keyfile="${sshdir}/deploy_key"
      if [[ -f "${keyfile}" ]]; then
        log_warn "Key ${keyfile} already exists — reusing pubkey"
      else
        run_or_die "ssh-keygen deploy key" ssh-keygen -t ed25519 -a 100 -f "${keyfile}" -N "" -C "deploy@${HOSTNAME:-host}"
        run_or_die "chown key" chown "${duser}:${duser}" "${keyfile}" "${keyfile}.pub"
        run_or_die "chmod private key" chmod 600 "${keyfile}"
        run_or_die "chmod public key" chmod 644 "${keyfile}.pub"
      fi
      cat "${keyfile}.pub" >>"${ak}"
      sort -u -o "${ak}" "${ak}"
      run_or_die "chown authorized_keys" chown "${duser}:${duser}" "${ak}"
      run_or_die "chmod authorized_keys" chmod 600 "${ak}"
      echo
      log_warn "PRIVATE KEY (copy into your deploy tool once, then store offline — it is shown here):"
      echo "-----"
      cat "${keyfile}"
      echo "-----"
      log_warn "Consider deleting ${keyfile} from disk after importing elsewhere."
      if confirm "Delete private key file from server now (pubkey stays in authorized_keys)?" "n"; then
        shred -u "${keyfile}" 2>/dev/null || rm -f "${keyfile}"
        [[ ! -f "${keyfile}" ]] || module_fail docker_deploy_user "Failed to delete private key ${keyfile}"
        log_ok "Private key removed from disk"
      fi
      ;;
    *)
      local pubkey=""
      echo "Paste the public key line, then Enter:"
      read -r pubkey || true
      pubkey="${pubkey//$'\r'/}"
      pubkey="$(sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//' <<<"${pubkey}")"
      if [[ -z "${pubkey}" ]] || ! _is_ssh_pubkey_line "${pubkey}"; then
        module_fail docker_deploy_user "Invalid or empty public key"
      fi
      if [[ -f "${ak}" ]] && grep -Fqx "${pubkey}" "${ak}"; then
        log_ok "Public key already in authorized_keys"
      else
        printf '%s\n' "${pubkey}" >>"${ak}"
        log_ok "Installed public key for ${duser}"
      fi
      run_or_die "chown authorized_keys" chown "${duser}:${duser}" "${ak}"
      run_or_die "chmod authorized_keys" chmod 600 "${ak}"
      ;;
  esac

  [[ -s "${ak}" ]] || module_fail docker_deploy_user "authorized_keys empty after key install"
  if command -v ssh-keygen >/dev/null; then
    ssh-keygen -lf "${ak}" || module_fail docker_deploy_user "ssh-keygen -lf failed — key file may be corrupt"
  fi
  local mode_ak
  mode_ak="$(stat -c '%a' "${ak}")"
  assert_eq "authorized_keys mode" "${mode_ak}" "600" \
    || module_fail docker_deploy_user "authorized_keys mode wrong"
  stat -c '%a %U:%G %n' "${home}" "${sshdir}" "${ak}"

  if ! _ensure_allowusers_includes "${duser}"; then
    module_fail docker_deploy_user "AllowUsers does not include ${duser} — deploy SSH would fail"
  fi

  local port
  port="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"
  port="${port:-22}"
  echo
  log_ok "Deploy user ready: ${duser}"
  echo "Test:"
  echo "  ssh -i <deploy-private-key> -p ${port} ${duser}@SERVER_IP"
  echo "Do not reuse the admin (${ADMIN_USER:-ADMIN_USER}) private key for deploy if you can avoid it."

  if confirm "Confirm you can SSH as ${duser} with the key?" "n"; then
    state_set docker_deploy_user verified
  else
    state_set docker_deploy_user applied
    log_warn "Marked applied — verify SSH as ${duser} before relying on this account"
  fi
}
