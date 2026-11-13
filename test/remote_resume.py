#!/usr/bin/env python3
"""Resume remaining hardening modules after partial apply."""
from __future__ import annotations

import os
import shlex
import sys
import time
from pathlib import Path

import paramiko

HOST = os.environ.get("HARDEN_HOST", "")
USER = os.environ.get("HARDEN_USER", "khan")
PASSWORD = os.environ.get("HARDEN_PASS", "")
REMOTE = "/home/khan/ubuntu-hardening"
KEY_PATH = Path.home() / ".ssh" / "id_ed25519_harden_test"
# Remaining after auditd verified; unattended may be incomplete
MODULES = [
    "unattended",
    "apparmor",
    "service_minimize",
    "allow_users",
    "tmp_harden",
    "verify",
]


def connect() -> paramiko.SSHClient:
    pkey = paramiko.Ed25519Key.from_private_key_file(str(KEY_PATH))
    last = None
    for port in (2121, 22):
        for auth, kwargs in (("key", {"pkey": pkey}), ("password", {"password": PASSWORD})):
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                c.connect(
                    HOST,
                    port=port,
                    username=USER,
                    timeout=30,
                    banner_timeout=60,
                    auth_timeout=30,
                    allow_agent=False,
                    look_for_keys=False,
                    **kwargs,
                )
                print(f"connected {auth}:{port}", flush=True)
                return c
            except Exception as exc:
                last = exc
                print(f"fail {auth}:{port}: {exc}", flush=True)
    raise RuntimeError(f"connect failed: {last}")


def run(client: paramiko.SSHClient, cmd: str, timeout: int = 900) -> tuple[int, str]:
    print(">>>", cmd[:180], flush=True)
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout, get_pty=True)
    out = stdout.read().decode(errors="replace")
    rc = stdout.channel.recv_exit_status()
    print(out[-4000:] if len(out) > 4000 else out, flush=True)
    print("rc=", rc, flush=True)
    return rc, out


def sudo(client: paramiko.SSHClient, cmd: str, timeout: int = 900) -> tuple[int, str]:
    wrapped = f"echo {shlex.quote(PASSWORD)} | sudo -S -p '' bash -lc {shlex.quote(cmd)}"
    return run(client, wrapped, timeout=timeout)


def reconnect() -> paramiko.SSHClient:
    last = None
    for i in range(12):
        try:
            return connect()
        except Exception as exc:
            last = exc
            print(f"reconnect {i+1}/12: {exc}", flush=True)
            time.sleep(5)
    raise RuntimeError(str(last))


def main() -> int:
    client = reconnect()
    sudo(client, "cat /var/lib/ubuntu-hardening/state.env; free -h | head -n2")
    for name in MODULES:
        print(f"\n===== MODULE {name} =====", flush=True)
        try:
            sudo(client, f"cd {REMOTE} && ./harden-ubuntu.sh --yes --module {name}", timeout=1200)
        except Exception as exc:
            print("transport error:", exc, flush=True)
            try:
                client.close()
            except Exception:
                pass
            time.sleep(5)
            client = reconnect()
            sudo(client, f"cd {REMOTE} && ./harden-ubuntu.sh --yes --module {name}", timeout=1200)
        if name in {"allow_users", "tmp_harden"}:
            try:
                client.close()
            except Exception:
                pass
            time.sleep(2)
            client = reconnect()
        time.sleep(2)

    sudo(client, f"cd {REMOTE} && ./harden-ubuntu.sh --status")
    sudo(
        client,
        "sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|allowusers)'; "
        "ss -tlnp | grep -E ':(22|2121)\\s'; findmnt /tmp; "
        "systemctl is-active fail2ban auditd apparmor; free -h | head -n2",
    )
    client.close()
    print("RESUME_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
