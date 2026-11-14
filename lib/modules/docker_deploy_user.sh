#!/usr/bin/env bash
# Module: docker_deploy_user — optional dedicated deploy user + SSH key

_is_ssh_pubkey_line() {
  local line="$1"
  [[ "${line}" =~ ^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+[A-Za-z0-9+/=]+ ]]
}

_coolify_present() {
  [[ -d /data/coolify ]]
}

_coolify_keys_dir() {
  printf '%s' "/data/coolify/ssh/keys"
}

# Append one pubkey line to authorized_keys if missing.
# Returns: 0=added, 1=invalid, 2=already present.
_ak_add_pubkey_line() {
  local ak="$1" line="$2"
  line="${line//$'\r'/}"
  line="$(sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//' <<<"${line}")"
  [[ -n "${line}" ]] || return 1
  _is_ssh_pubkey_line "${line}" || return 1
  if [[ -f "${ak}" ]] && grep -Fqx "${line}" "${ak}"; then
    return 2
  fi
  printf '%s\n' "${line}" >>"${ak}"
  return 0
}

# Import Coolify private/.pub material into deploy authorized_keys (additive).
# Existing keys on the deploy user are kept. Returns number imported via stdout last line count in log.
_coolify_import_pubkeys_into() {
  local ak="$1"
  local keys_dir pub priv line tmp added=0
  keys_dir="$(_coolify_keys_dir)"
  if [[ ! -d "${keys_dir}" ]]; then
    log_error "Coolify keys directory missing: ${keys_dir}"
    return 1
  fi
  require_cmd ssh-keygen

  # Prefer .pub files when present
  local f
  shopt -s nullglob
  local rc
  for pub in "${keys_dir}"/*.pub; do
    while IFS= read -r line || [[ -n "${line}" ]]; do
      [[ "${line}" =~ ^[[:space:]]*(#|$) ]] && continue
      rc=0
      _ak_add_pubkey_line "${ak}" "${line}" || rc=$?
      case "${rc}" in
        0)
          log_ok "Authorized Coolify pubkey from $(basename "${pub}")"
          added=$((added + 1))
          ;;
        2) log_info "Already present: pubkey from $(basename "${pub}")" ;;
        *) log_warn "Skipped invalid line in $(basename "${pub}")" ;;
      esac
    done <"${pub}"
  done

  # Private key files (no .pub): derive public half
  for priv in "${keys_dir}"/*; do
    [[ -f "${priv}" ]] || continue
    [[ "${priv}" == *.pub ]] && continue
    [[ "${priv}" == *.lock ]] && continue
    if ! grep -qE 'BEGIN .*PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY' "${priv}" 2>/dev/null; then
      continue
    fi
    tmp="$(mktemp)"
    chmod 600 "${tmp}"
    if ! ssh-keygen -y -f "${priv}" >"${tmp}" 2>/dev/null; then
      rm -f "${tmp}"
      log_warn "Could not derive pubkey from $(basename "${priv}") — skipped"
      continue
    fi
    line="$(tr -d '\r' <"${tmp}" | head -n1)"
    rm -f "${tmp}"
    rc=0
    _ak_add_pubkey_line "${ak}" "${line}" || rc=$?
    case "${rc}" in
      0)
        log_ok "Authorized Coolify key derived from $(basename "${priv}")"
        added=$((added + 1))
        ;;
      2) log_info "Already present: derived from $(basename "${priv}")" ;;
      *) log_warn "Skipped invalid derived pubkey from $(basename "${priv}")" ;;
    esac
  done
  shopt -u nullglob

  # "Already present" still counts as success if ak is non-empty and Coolify keys dir had material
  if [[ "${added}" -eq 0 ]]; then
    if [[ -s "${ak}" ]] && compgen -G "${keys_dir}/*" >/dev/null; then
      log_ok "Coolify keys already present in authorized_keys (nothing new to add)"
      return 0
    fi
    log_error "No Coolify SSH keys found under ${keys_dir}"
    return 1
  fi
  log_info "Coolify keys newly authorized: ${added} (other authorized_keys lines were kept)"
  return 0
}

_print_coolify_ui_hint() {
  local duser="$1" port="$2"
  echo
  log_info "Coolify UI (after this module):"
  echo "  Host:  172.17.0.1   (or this server LAN/public IP; avoid host.docker.internal if it mis-resolves)"
  echo "  Port:  ${port}"
  echo "  User:  ${duser}"
  echo "  Key:   Coolify default / localhost key (the one whose pubkey we just authorized)"
  echo "Do not use root — root SSH is disabled by host hardening."
  echo "Coolify requires passwordless sudo for ${duser} (configured in Coolify mode)."
}

# Coolify non-root servers need: user ALL=(ALL) NOPASSWD: ALL
_coolify_ensure_nopasswd_sudo() {
  local user="$1"
  local drop="/etc/sudoers.d/ubuntu-hardening-${user}"
  local tmp
  require_cmd visudo
  if [[ ! -x /usr/bin/sudo ]] && ! command -v sudo >/dev/null; then
    install_packages sudo
  fi
  tmp="$(mktemp)"
  chmod 600 "${tmp}"
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${user}" >"${tmp}"
  if ! visudo -cf "${tmp}" >/dev/null; then
    rm -f "${tmp}"
    log_error "Generated sudoers fragment failed visudo -cf"
    return 1
  fi
  if [[ -f "${drop}" ]]; then
    backup_path "${drop}" >/dev/null || true
  fi
  install -o root -g root -m 440 "${tmp}" "${drop}"
  rm -f "${tmp}"
  if ! visudo -cf "${drop}" >/dev/null; then
    log_error "Installed ${drop} but visudo -cf failed — removing"
    rm -f "${drop}"
    return 1
  fi
  if ! su - "${user}" -c 'sudo -n whoami' 2>/dev/null | grep -qx root; then
    log_error "Passwordless sudo check failed for ${user} (sudo -n whoami)"
    return 1
  fi
  log_ok "Passwordless sudo for ${user} via ${drop}"
}

# Print "path<newline>lineno" for the first global AllowUsers in include order.
_ssh_first_allowusers() {
  local file="$1" raw line lineno=0 in_match=0 rest pat inc
  [[ -n "${_SSH_SEEN["${file}"]:-}" ]] && return 1
  _SSH_SEEN["${file}"]=1
  [[ -f "${file}" ]] || return 1
  while IFS= read -r raw || [[ -n "${raw}" ]]; do
    lineno=$((lineno + 1))
    line="${raw%$'\r'}"
    [[ "${line}" =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ "${line}" =~ ^[[:space:]]*[Ii][Nn][Cc][Ll][Uu][Dd][Ee][[:space:]]+(.+)$ ]]; then
      rest="${BASH_REMATCH[1]}"
      local -a pats=()
      read -r -a pats <<<"${rest}" || true
      for pat in "${pats[@]}"; do
        [[ "${pat}" == \#* ]] && break
        pat="${pat%\"}"; pat="${pat#\"}"; pat="${pat%\'}"; pat="${pat#\'}"
        [[ "${pat}" == /* ]] || pat="$(dirname "${file}")/${pat}"
        local -a expanded=()
        mapfile -t expanded < <(compgen -G "${pat}" | LC_ALL=C sort || true)
        for inc in "${expanded[@]}"; do
          _ssh_first_allowusers "${inc}" && return 0
        done
      done
      continue
    fi
    if [[ "${line}" =~ ^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]+(.*)$ ]]; then
      if [[ "${BASH_REMATCH[1]}" =~ ^[Aa][Ll][Ll][[:space:]]*$ ]]; then
        in_match=0
      else
        in_match=1
      fi
      continue
    fi
    if [[ "${in_match}" -eq 0 && "${line}" =~ ^[[:space:]]*[Aa][Ll][Ll][Oo][Ww][Uu][Ss][Ee][Rr][Ss][[:space:]] ]]; then
      printf '%s\n%s\n' "${file}" "${lineno}"
      return 0
    fi
  done <"${file}"
  return 1
}

_ensure_allowusers_includes() {
  local user="$1"
  local eff target lineno snap tmp
  eff="$(sshd_allowusers_effective)"
  if [[ -z "${eff}" ]]; then
    log_info "No AllowUsers in effect — deploy user can SSH without AllowUsers change"
    return 0
  fi
  if sshd_allowusers_includes "${user}"; then
    log_ok "AllowUsers already includes ${user} (effective: ${eff})"
    return 0
  fi
  log_warn "AllowUsers is active and does NOT include ${user} — deploy SSH will fail until fixed."
  log_info "Effective now: ${eff}"

  unset _SSH_SEEN
  declare -gA _SSH_SEEN=()
  local hit_file="" hit_line=""
  if mapfile -t _hit < <(_ssh_first_allowusers /etc/ssh/sshd_config); then
    hit_file="${_hit[0]:-}"
    hit_line="${_hit[1]:-}"
  fi
  unset _hit
  if [[ -z "${hit_file}" || -z "${hit_line}" ]]; then
    log_error "sshd -T has AllowUsers, but no global AllowUsers line was found in include order"
    grep -RniE '^[[:space:]]*AllowUsers\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true
    return 1
  fi
  target="${hit_file}"
  lineno="${hit_line}"
  log_info "First AllowUsers line: ${target}:${lineno}"

  if ! confirm "Add ${user} to that AllowUsers line and reload SSH?" "y"; then
    return 1
  fi

  snap="$(mktemp)"
  cp -a -- "${target}" "${snap}"
  backup_path "${target}" >/dev/null || { rm -f "${snap}"; return 1; }

  tmp="$(mktemp)"
  awk -v n="${lineno}" -v u="${user}" '
    NR==n {
      out="AllowUsers"
      found=0
      lu=tolower(u)
      for (i=2;i<=NF;i++) {
        if ($i ~ /^#/) break
        out=out " " $i
        if (tolower($i)==lu) found=1
      }
      if (!found) out=out " " u
      print out
      next
    }
    { sub(/\r$/, ""); print }
  ' "${target}" >"${tmp}"
  cat "${tmp}" >"${target}"
  rm -f "${tmp}"

  if ! sshd -t; then
    log_error "sshd -t failed after AllowUsers edit — restoring ${target}"
    cat "${snap}" >"${target}"
    rm -f "${snap}"
    return 1
  fi

  eff="$(sshd_allowusers_effective)"
  if ! sshd_allowusers_includes "${user}"; then
    log_error "Edited ${target}:${lineno} but sshd -T still missing ${user}: ${eff:-<missing>}"
    log_error "AllowUsers lines on disk:"
    grep -RniE '^[[:space:]]*AllowUsers\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true
    log_warn "Restoring ${target}"
    cat "${snap}" >"${target}"
    rm -f "${snap}"
    return 1
  fi
  rm -f "${snap}"
  log_ok "sshd -T now: ${eff}"

  if ! confirm_token "reload SSH to apply AllowUsers including ${user}"; then
    log_error "AllowUsers updated on disk but SSH not reloaded — deploy login will fail until reload"
    return 1
  fi
  systemctl reload ssh 2>/dev/null || systemctl reload ssh.service || return 1
  log_ok "SSH reloaded with AllowUsers including ${user}"
}

module_docker_deploy_user() {
  if ! run_module_guard docker_deploy_user "Deploy user + SSH key (optional)"; then
    return 0
  fi

  load_config_env
  require_cmd id adduser usermod getent install

  # Slave path: user already from harden-ubuntu --coolify-remote — do not recreate.
  local existing_deploy
  existing_deploy="$(config_get DEPLOY_USER "")"
  if [[ "${COOLIFY_MODE}" -eq 0 && -n "${existing_deploy}" ]] \
    && id "${existing_deploy}" &>/dev/null \
    && [[ -f "/etc/sudoers.d/ubuntu-hardening-${existing_deploy}" ]]; then
    log_info "Deploy user ${existing_deploy} already prepared (e.g. coolify_remote / prior run)"
    if [[ "${NO_CONFIRM}" -eq 1 || "${ASSUME_YES}" -eq 1 ]] \
      || confirm "Skip docker_deploy_user (keep existing ${existing_deploy})?" "y"; then
      state_set docker_deploy_user skipped
      log_ok "Skipped docker_deploy_user — existing deploy user left unchanged"
      return 0
    fi
  fi

  local duser default_user="deploy"
  if [[ "${COOLIFY_MODE}" -eq 1 ]]; then
    default_user="coolify"
  fi
  duser="$(config_get DEPLOY_USER "")"
  duser="$(prompt_value "Deploy username (CI/CD or panel)" "${duser:-${default_user}}")"
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
    if [[ "${COOLIFY_MODE}" -eq 1 ]]; then
      log_info "${duser} is in sudo group (expected for Coolify passwordless sudo setup)"
    else
      log_warn "${duser} is in sudo group — consider removing if not required"
    fi
  fi

  # Coolify validates with sudo; without NOPASSWD it reports: "I'm sorry … I can't do that"
  if [[ "${COOLIFY_MODE}" -eq 1 ]]; then
    if [[ "${NO_CONFIRM}" -eq 1 || "${ASSUME_YES}" -eq 1 ]] \
      || confirm "Grant ${duser} passwordless sudo (required by Coolify non-root SSH)?" "y"; then
      if ! _coolify_ensure_nopasswd_sudo "${duser}"; then
        module_fail docker_deploy_user "Coolify needs passwordless sudo for ${duser}"
      fi
    else
      log_warn "Skipped passwordless sudo — Coolify validation will fail until you add it"
    fi
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
  log_info "Existing lines in authorized_keys are kept unless you replace the file yourself."
  echo

  local mode="" use_coolify_keys=0
  # Coolify key import only for --coolify-master (or opted in when /data/coolify detected).
  if [[ "${COOLIFY_MODE}" -eq 1 ]]; then
    if [[ "${NO_CONFIRM}" -eq 1 || "${ASSUME_YES}" -eq 1 ]]; then
      use_coolify_keys=1
      log_info "Coolify master mode: importing keys from $(_coolify_keys_dir) for ${duser}"
    elif confirm "Import Coolify SSH keys from $(_coolify_keys_dir) for ${duser}? (adds; keeps existing keys)" "y"; then
      use_coolify_keys=1
    fi
  fi

  if [[ "${use_coolify_keys}" -eq 1 ]]; then
    mode="coolify"
  else
    echo "Key source:"
    echo "  [1] Paste public key (.pub line)"
    echo "  [2] Generate ed25519 keypair on this host (copy private key to the deploy tool; less ideal)"
    if _coolify_present; then
      echo "  [3] Import Coolify keys from $(_coolify_keys_dir) (add; keep existing)"
    fi
    read -r -p "Choice [1]: " mode || true
    mode="${mode:-1}"
  fi

  case "${mode}" in
    coolify|3)
      if ! _coolify_present; then
        module_fail docker_deploy_user "Coolify not found under /data/coolify — install Coolify or pick another key source"
      fi
      if ! _coolify_import_pubkeys_into "${ak}"; then
        module_fail docker_deploy_user "Failed to import Coolify keys into ${ak}"
      fi
      run_or_die "chown authorized_keys" chown "${duser}:${duser}" "${ak}"
      run_or_die "chmod authorized_keys" chmod 600 "${ak}"
      ;;
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
  if [[ "${mode}" == "coolify" || "${mode}" == "3" ]]; then
    _print_coolify_ui_hint "${duser}" "${port}"
  fi
  if [[ "${COOLIFY_MODE}" -eq 1 ]]; then
    config_set COOLIFY_ROLE master
  fi

  if confirm_test "Confirm you can SSH as ${duser} with the key?" "n"; then
    state_set docker_deploy_user verified
  else
    state_set docker_deploy_user applied
    log_warn "Marked applied — verify SSH as ${duser} before relying on this account"
  fi
}
