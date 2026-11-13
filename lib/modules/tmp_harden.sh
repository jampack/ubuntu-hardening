#!/usr/bin/env bash
# Module: tmp_harden — runbook §23

module_tmp_harden() {
  if ! run_module_guard tmp_harden "/tmp mount hardening"; then
    return 0
  fi

  require_cmd findmnt systemctl

  echo "Current /tmp:"
  findmnt /tmp || true
  systemctl cat tmp.mount 2>/dev/null | head -n 40 || true

  if findmnt -no OPTIONS /tmp 2>/dev/null | tr ',' '\n' | grep -qx noexec \
    && findmnt -no OPTIONS /tmp 2>/dev/null | tr ',' '\n' | grep -qx nosuid \
    && findmnt -no OPTIONS /tmp 2>/dev/null | tr ',' '\n' | grep -qx nodev; then
    log_ok "/tmp already has nodev,nosuid,noexec"
    state_set tmp_harden verified
    return 0
  fi

  log_warn "HARD GATE: noexec on /tmp can break installers/apps that execute from /tmp."
  if ! confirm_token "harden /tmp with noexec (can break apps that execute from /tmp)"; then
    state_set tmp_harden skipped
    return 0
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "DRY-RUN: would add nodev,nosuid,noexec to tmp.mount"
    state_set tmp_harden skipped
    return 0
  fi

  if ! systemctl cat tmp.mount &>/dev/null; then
    module_fail tmp_harden "/tmp is not managed by systemd tmp.mount — cannot auto-apply (adapt fstab manually, then re-run)"
  fi

  local cur_opts
  cur_opts="$(systemctl show -p Options --value tmp.mount 2>/dev/null || true)"
  if [[ -z "${cur_opts}" ]]; then
    cur_opts="$(systemctl cat tmp.mount | awk -F= '/^Options=/{print $2; exit}')"
  fi
  [[ -n "${cur_opts}" ]] || module_fail tmp_harden "Could not discover current tmp.mount Options"

  local new_opts="${cur_opts}"
  local flag
  for flag in nodev nosuid noexec; do
    if ! tr ',' '\n' <<<"${new_opts}" | grep -qx "${flag}"; then
      new_opts="${new_opts},${flag}"
    fi
  done

  log_info "Current Options=${cur_opts}"
  log_info "New Options=${new_opts}"

  if [[ -d /etc/systemd/system/tmp.mount.d ]]; then
    backup_path /etc/systemd/system/tmp.mount.d >/dev/null
  fi
  run_or_die "mkdir tmp.mount.d" mkdir -p /etc/systemd/system/tmp.mount.d
  local drop="/etc/systemd/system/tmp.mount.d/noexec.conf"
  cat >"${drop}" <<EOF
[Mount]
Options=${new_opts}
EOF
  run_or_die "chmod tmp.mount drop-in" chmod 644 "${drop}"

  run_or_die "daemon-reload" systemctl daemon-reload
  systemctl cat tmp.mount | grep -E '^Options=' \
    || module_fail tmp_harden "tmp.mount Options= not visible after drop-in"

  if ! confirm "Restart tmp.mount now (may fail if busy)?" "y"; then
    state_set tmp_harden applied
    log_warn "Drop-in written but tmp.mount not restarted yet."
    return 0
  fi

  if ! systemctl restart tmp.mount; then
    module_fail tmp_harden "tmp.mount restart failed — investigate processes using /tmp"
  fi

  findmnt /tmp

  local opts
  opts="$(findmnt -no OPTIONS /tmp)"
  echo "${opts}" | tr ',' '\n' | grep -qx noexec || module_fail tmp_harden "/tmp missing noexec after restart (got: ${opts})"
  echo "${opts}" | tr ',' '\n' | grep -qx nosuid || module_fail tmp_harden "/tmp missing nosuid after restart (got: ${opts})"
  echo "${opts}" | tr ',' '\n' | grep -qx nodev || module_fail tmp_harden "/tmp missing nodev after restart (got: ${opts})"
  log_ok "/tmp options verified: ${opts}"

  # Functional tests — must pass
  echo 'echo TEST' >/tmp/harden-tmp-test.sh
  chmod +x /tmp/harden-tmp-test.sh
  set +e
  /tmp/harden-tmp-test.sh
  local direct_rc=$?
  bash /tmp/harden-tmp-test.sh
  local bash_rc=$?
  set -e
  rm -f /tmp/harden-tmp-test.sh

  if [[ "${direct_rc}" -ne 126 ]]; then
    module_fail tmp_harden "Expected direct /tmp exec exit 126, got ${direct_rc}"
  fi
  log_ok "Direct /tmp execution denied (exit 126) as expected"
  if [[ "${bash_rc}" -ne 0 ]]; then
    module_fail tmp_harden "bash /tmp script failed unexpectedly rc=${bash_rc}"
  fi
  log_ok "bash /tmp script still works"

  state_set tmp_harden verified
}
