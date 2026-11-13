#!/usr/bin/env python3
"""Re-upload scripts and apply safer modules, then SSH hardening with key auth."""
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
LOCAL = Path(__file__).resolve().parents[1]
REMOTE = "/home/khan/ubuntu-hardening"
KEY_PATH = Path.home() / ".ssh" / "id_ed25519_harden_test"
SSH_PORTS = [22, 2121]


def connect(ports: list[int] | None = None) -> paramiko.SSHClient:
    ports = ports or SSH_PORTS
    pkey = paramiko.Ed25519Key.from_private_key_file(str(KEY_PATH))
    last: Exception | None = None
    for port in ports:
        for auth_name, kwargs in (
            ("key", {"pkey": pkey}),
            ("password", {"password": PASSWORD}),
        ):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    HOST,
                    port=port,
                    username=USER,
                    timeout=20,
                    allow_agent=False,
                    look_for_keys=False,
                    **kwargs,
                )
                print(f"connected via {auth_name} on port {port}")
                return client
            except Exception as exc:
                last = exc
                print(f"connect {auth_name}:{port} failed: {exc}")
                try:
                    client.close()
                except Exception:
                    pass
    raise RuntimeError(f"unable to connect: {last}")


def run(client: paramiko.SSHClient, cmd: str, timeout: int = 300) -> tuple[int, str]:
    print(">>>", cmd if len(cmd) < 200 else cmd[:200] + "...")
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout, get_pty=True)
    out = stdout.read().decode(errors="replace")
    rc = stdout.channel.recv_exit_status()
    print(out)
    print("rc=", rc)
    return rc, out


def sudo(client: paramiko.SSHClient, cmd: str, timeout: int = 600) -> tuple[int, str]:
    wrapped = f"echo {shlex.quote(PASSWORD)} | sudo -S -p '' bash -lc {shlex.quote(cmd)}"
    return run(client, wrapped, timeout=timeout)


def mkdir_p(sftp: paramiko.SFTPClient, remote: str) -> None:
    parts = remote.split("/")
    cur = ""
    for p in parts:
        if not p:
            continue
        cur += "/" + p
        try:
            sftp.stat(cur)
        except OSError:
            sftp.mkdir(cur)


def upload(client: paramiko.SSHClient) -> None:
    run(client, f"rm -rf {REMOTE} && mkdir -p {REMOTE}/lib/modules {REMOTE}/templates")
    sftp = client.open_sftp()
    files = [LOCAL / "harden-ubuntu.sh", LOCAL / "README.md", LOCAL / "lib" / "common.sh"]
    files += sorted((LOCAL / "lib" / "modules").glob("*.sh"))
    files += sorted(p for p in (LOCAL / "templates").iterdir() if p.is_file())
    for lp in files:
        rel = lp.relative_to(LOCAL).as_posix()
        rp = f"{REMOTE}/{rel}"
        mkdir_p(sftp, "/".join(rp.split("/")[:-1]))
        sftp.put(str(lp), rp)
        print("put", rp)
    sftp.chmod(f"{REMOTE}/harden-ubuntu.sh", 0o755)
    sftp.close()


def reconnect() -> paramiko.SSHClient:
    last = None
    for i in range(8):
        try:
            return connect()
        except Exception as exc:
            last = exc
            print(f"reconnect {i+1}/8 failed: {exc}")
            time.sleep(2)
    raise RuntimeError(f"reconnect failed: {last}")


def module(client: paramiko.SSHClient, name: str, dry: bool = False) -> paramiko.SSHClient:
    flags = "--yes --module " + name
    if dry:
        flags = "--yes --dry-run --module " + name
    print(f"\n===== MODULE {name} dry={dry} =====")
    try:
        sudo(client, f"cd {REMOTE} && ./harden-ubuntu.sh {flags}", timeout=900)
    except Exception as exc:
        print("module transport error:", exc)
        client.close()
        client = reconnect()
        sudo(client, f"cd {REMOTE} && ./harden-ubuntu.sh {flags}", timeout=900)
    # Always refresh connection after SSH-affecting modules
    if name in {"ssh_hardening", "ssh_port", "allow_users"}:
        try:
            client.close()
        except Exception:
            pass
        time.sleep(2)
        client = reconnect()
    return client


def install_key(client: paramiko.SSHClient) -> None:
    pub = (Path.home() / ".ssh" / "id_ed25519_harden_test.pub").read_text().strip()
    run(client, "mkdir -p ~/.ssh && chmod 700 ~/.ssh")
    sftp = client.open_sftp()
    ak = f"/home/{USER}/.ssh/authorized_keys"
    try:
        with sftp.open(ak, "r") as f:
            existing = f.read().decode()
    except OSError:
        existing = ""
    if pub not in existing:
        with sftp.open(ak, "a") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write(pub + "\n")
        print("installed authorized_keys")
    else:
        print("authorized_keys already has test key")
    sftp.close()
    run(client, "chmod 600 ~/.ssh/authorized_keys")


def main() -> int:
    client = connect()
    install_key(client)
    upload(client)

    # Ensure config + key perms
    sudo(
        client,
        """
mkdir -p /etc/ubuntu-hardening /var/lib/ubuntu-hardening /var/log/ubuntu-hardening
cat >/etc/ubuntu-hardening/config.env <<'EOF'
ADMIN_USER=khan
SSH_PORT=2121
SECURITY_EMAIL=test@example.com
FAIL2BAN_SENDER_EMAIL=test@example.com
INTERFACE=eth0
SERVER_HOST=khan-server
ADMIN_CLIENT_IP=
SMTP_RELAY=[smtp.gmail.com]:587
EOF
chmod 600 /etc/ubuntu-hardening/config.env
touch /var/lib/ubuntu-hardening/state.env
chmod 600 /var/lib/ubuntu-hardening/state.env
chown -R khan:khan /home/khan/.ssh
chmod 700 /home/khan/.ssh
chmod 600 /home/khan/.ssh/authorized_keys
""",
    )

    # Apply order: safe first, then SSH, then rest (skip fail2ban mail / audit lock interaction where possible)
    def memcheck(c: paramiko.SSHClient) -> None:
        sudo(c, "free -h | head -n 2; echo ---")

    for name in [
        "assess",
        "backup_ssh",
        "admin_user",
        "ssh_keys",
        "ssh_hardening",
        "ssh_perms",
        "ssh_port",
        "sysctl",
        "fail2ban",
        "auditd",
        "unattended",
        "apparmor",
        "service_minimize",
        "allow_users",
        "tmp_harden",
        "verify",
    ]:
        memcheck(client)
        client = module(client, name, dry=False)
        # Brief pause after apt-heavy modules to let caches settle
        if name in {"fail2ban", "auditd", "unattended", "apparmor"}:
            time.sleep(3)

    sudo(client, f"cd {REMOTE} && ./harden-ubuntu.sh --status")
    run(client, "sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers)' || sudo sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers)'")
    sudo(client, "ss -tlnp | grep -E '(:22|:2121)\\s' || true; sysctl fs.protected_fifos kernel.kptr_restrict; systemctl is-active fail2ban auditd apparmor || true")
    client.close()
    print("APPLY_DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
