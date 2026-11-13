#!/usr/bin/env python3
import os
import shlex
from pathlib import Path

import paramiko

HOST = os.environ.get("HARDEN_HOST", "")
USER = os.environ.get("HARDEN_USER", "khan")
PASSWORD = os.environ.get("HARDEN_PASS", "")
KEY_PATH = Path.home() / ".ssh" / "id_ed25519_harden_test"


def connect():
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
                    timeout=20,
                    allow_agent=False,
                    look_for_keys=False,
                    **kwargs,
                )
                print(f"connected {auth}:{port}")
                return c
            except Exception as exc:
                last = exc
                print(f"fail {auth}:{port}: {exc}")
    raise SystemExit(f"connect failed: {last}")


def main():
    c = connect()
    cmd = r"""
free -h | head -n 2
echo '--- state ---'
cat /var/lib/ubuntu-hardening/state.env 2>/dev/null || echo none
echo '--- listeners ---'
ss -tlnp | grep -E ':(22|2121)\s' || true
echo '--- sshd -T ---'
sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers)' || true
echo '--- services ---'
systemctl is-active fail2ban auditd apparmor 2>/dev/null || true
dpkg-query -W fail2ban auditd unattended-upgrades 2>/dev/null || true
echo '--- logs ---'
ls -lt /var/log/ubuntu-hardening 2>/dev/null | head
echo '--- processes ---'
ps -eo pid,cmd --sort=start_time | grep -E 'harden-ubuntu|apt-get|dpkg|unattended' | grep -v grep || true
"""
    wrapped = f"echo {shlex.quote(PASSWORD)} | sudo -S -p '' bash -lc {shlex.quote(cmd)}"
    stdin, stdout, stderr = c.exec_command(wrapped, get_pty=True, timeout=60)
    print(stdout.read().decode(errors="replace"))
    c.close()


if __name__ == "__main__":
    main()
