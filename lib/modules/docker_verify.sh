#!/usr/bin/env bash
# Module: docker_verify — §25.8 summary checklist

module_docker_verify() {
  if ! run_module_guard docker_verify "Docker hardening verification"; then
    return 0
  fi

  local pass=0 fail=0
  local report="${HARDEN_BACKUP_DIR}/docker-verification-report.txt"
  : >"${report}"

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

  section "Docker verification"
  _check "docker CLI present" command -v docker
  _check "docker active" systemctl is-active docker
  _check "docker enabled" systemctl is-enabled docker
  _check "containerd active" systemctl is-active containerd
  if _expect_module docker_api; then
    _check "no :2375 listener" bash -c "! ss -tulpen | grep -qE '(:2375)\\s'"
    _check "no :2376 listener" bash -c "! ss -tulpen | grep -qE '(:2376)\\s'"
  fi
  if _expect_module docker_socket; then
    _check "docker.sock exists" bash -c '[[ -S /var/run/docker.sock ]]'
    _check "docker.sock not 666/777" bash -c 'm=$(stat -c %a /var/run/docker.sock); [[ $m != 666 && $m != 777 ]]'
  fi
  if _expect_module docker_deploy_user; then
    local duser
    duser="$(config_get DEPLOY_USER deploy)"
    _check "deploy user exists" id "${duser}"
    _check "deploy user in docker group" bash -c "id -nG '${duser}' | tr ' ' '\n' | grep -qx docker"
    _check "deploy authorized_keys present" bash -c "[[ -s \$(getent passwd '${duser}' | cut -d: -f6)/.ssh/authorized_keys ]]"
  fi

  echo "--- listeners of interest ---" | tee -a "${report}"
  ss -tulpen | grep -E ':(80|443|8000|6001|6002|2375|2376|2121|22)\s' | tee -a "${report}" || true
  echo "--- containers ---" | tee -a "${report}"
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | tee -a "${report}" \
    || module_fail docker_verify "docker ps failed during verification"

  echo | tee -a "${report}"
  echo "Summary: PASS=${pass} FAIL=${fail}" | tee -a "${report}"
  print_status | tee -a "${report}"
  log_info "Report: ${report}"
  log_info "After any daemon change: retest apps, proxy (80/443 if used), and one deploy."

  if [[ "${fail}" -eq 0 ]]; then
    state_set docker_verify verified
    log_ok "All Docker verification checks passed"
  else
    module_fail docker_verify "Docker verification found ${fail} failure(s) — review ${report}"
  fi
}
