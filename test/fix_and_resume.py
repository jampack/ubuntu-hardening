#!/usr/bin/env python3
from __future__ import annotations

import os
import shlex
import time
from pathlib import Path

import paramiko

HOST = os.environ.get("HARDEN_HOST", "")
PASSWORD = os.environ.get("HARDEN_PASS", "")
REMOTE = "/home/khan/ubuntu-hardening"
KEY_PATH = Path.home() / ".ssh" / "id_ed25519_harden_test"
ROOT = Path(__file__).resolve().parents[1]
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
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            c.connect(
                HOST,
                port=port,
                username="khan",
                pkey=pkey,
                timeout=25,
                banner_timeout=60,
                allow_agent=False,
                look_for_keys=False,
            )
            print(f"connected key:{port}", flush=True)
            return c
        except Exception as e:
            last = e
            print(f"fail key:{port}: {e}", flush=True)
    raise RuntimeError(last)


def run(client: paramiko.SSHClient, cmd: str, timeout: int = 120) -> str:
    print(">>>", cmd[:180], flush=True)
    _i, stdout, _e = client.exec_command(cmd, get_pty=True, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    print(out[-3500:] if len(out) > 3500 else out, flush=True)
    return out


def sudo(client: paramiko.SSHClient, cmd: str, timeout: int = 900) -> str:
    wrapped = f"echo {shlex.quote(PASSWORD)} | sudo -S -p '' bash -lc {shlex.quote(cmd)}"
    return run(client, wrapped, timeout=timeout)


def main() -> int:
    unattended = ROOT / "lib" / "modules" / "unattended.sh"
    unattended.write_bytes(
        unattended.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    )

    client = connect()
    # Hard-kill wedged systemctl/harden processes
    sudo(
        client,
        "kill -9 $(pgrep -f 'systemctl list-timers') 2>/dev/null || true; "
        "kill -9 $(pgrep -f 'harden-ubuntu.sh --yes --module') 2>/dev/null || true; "
        "sleep 1; "
        "ps -eo pid,etime,cmd | grep -E 'harden-ubuntu|list-timers' | grep -v grep || echo no_stuck",
        timeout=60,
    )
    sftp = client.open_sftp()
    sftp.put(str(unattended), f"{REMOTE}/lib/modules/unattended.sh")
    sftp.close()
    print("uploaded fixed unattended.sh", flush=True)
    sudo(client, f"grep -n 'Skip list-timers' {REMOTE}/lib/modules/unattended.sh || true")

    for name in MODULES:
        print(f"\n===== MODULE {name} =====", flush=True)
        try:
            sudo(client, f"cd {REMOTE} && ./harden-ubuntu.sh --yes --module {name}", timeout=600)
        except Exception as e:
            print("transport error:", e, flush=True)
            try:
                client.close()
            except Exception:
                pass
            time.sleep(3)
            client = connect()
            sudo(client, f"cd {REMOTE} && ./harden-ubuntu.sh --yes --module {name}", timeout=600)
        if name in {"allow_users", "tmp_harden"}:
            try:
                client.close()
            except Exception:
                pass
            time.sleep(2)
            client = connect()

    sudo(client, f"cd {REMOTE} && ./harden-ubuntu.sh --status")
    sudo(
        client,
        "sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|allowusers)'; "
        "ss -tln | grep -E ':(22|2121)\\s' || true; "
        "findmnt /tmp || true; "
        "cat /var/lib/ubuntu-hardening/state.env",
    )
    client.close()
    print("RESUME_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
