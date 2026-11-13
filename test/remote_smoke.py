#!/usr/bin/env python3
"""Upload hardening scripts to the Hyper-V guest and run smoke tests."""
from __future__ import annotations

import os
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
PUB_PATH = Path(str(KEY_PATH) + ".pub")


def ensure_key() -> str:
    import subprocess

    KEY_PATH.parent.mkdir(mode=0o700, exist_ok=True)
    if not KEY_PATH.exists() or not PUB_PATH.exists():
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-a",
                "100",
                "-f",
                str(KEY_PATH),
                "-N",
                "",
                "-C",
                "harden-test@voyager",
            ],
            check=True,
        )
        print("Generated", KEY_PATH)
    else:
        print("Using existing", KEY_PATH)
    return PUB_PATH.read_text().strip()


def connect(password: bool = True, key: bool = False) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=HOST,
        username=USER,
        timeout=20,
        allow_agent=False,
        look_for_keys=False,
    )
    if key:
        kwargs["pkey"] = paramiko.Ed25519Key.from_private_key_file(str(KEY_PATH))
    else:
        kwargs["password"] = PASSWORD
    client.connect(**kwargs)
    return client


def run(client: paramiko.SSHClient, cmd: str, timeout: int = 180) -> tuple[int, str, str]:
    print(">>>", cmd)
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout, get_pty=True)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    rc = stdout.channel.recv_exit_status()
    if out:
        print(out)
    if err and err.strip():
        print("STDERR:", err)
    print("rc=", rc)
    return rc, out, err


def sudo(client: paramiko.SSHClient, cmd: str, timeout: int = 300) -> tuple[int, str, str]:
    import shlex

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
    files: list[Path] = [LOCAL / "harden-ubuntu.sh", LOCAL / "README.md", LOCAL / "lib" / "common.sh"]
    files += sorted((LOCAL / "lib" / "modules").glob("*.sh"))
    files += sorted((LOCAL / "templates").iterdir())
    for lp in files:
        if not lp.is_file():
            continue
        rel = lp.relative_to(LOCAL).as_posix()
        rp = f"{REMOTE}/{rel}"
        mkdir_p(sftp, str(Path(rp).parent).replace("\\", "/"))
        sftp.put(str(lp), rp)
        print("put", rp)
    sftp.chmod(f"{REMOTE}/harden-ubuntu.sh", 0o755)
    sftp.close()


def install_authorized_key(client: paramiko.SSHClient, pub: str) -> None:
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
        print("Installed authorized_keys entry")
    else:
        print("authorized_keys already present")
    sftp.close()
    run(client, "chmod 600 ~/.ssh/authorized_keys")


def main() -> int:
    pub = ensure_key()
    client = connect(password=True)
    try:
        install_authorized_key(client, pub)
        upload(client)
        rc, _, _ = sudo(client, "whoami")
        if rc != 0:
            print("sudo failed", file=sys.stderr)
            return 1
        sudo(
            client,
            f"bash -n {REMOTE}/harden-ubuntu.sh && "
            f"bash -n {REMOTE}/lib/common.sh && "
            f"for f in {REMOTE}/lib/modules/*.sh; do bash -n \"$f\" || exit 1; done; "
            f"echo SYNTAX_OK",
        )
        sudo(client, f"cd {REMOTE} && ./harden-ubuntu.sh --help | head -n 50")
    finally:
        client.close()

    # Verify key login works
    print("Testing key-based SSH...")
    kclient = connect(key=True)
    try:
        run(kclient, "echo KEY_LOGIN_OK; whoami")
    finally:
        kclient.close()

    # Non-interactive dry-run of early modules via expect-like answers is hard;
    # run assess with pre-seeded config using --yes --dry-run --module
    client = connect(key=True)
    try:
        # Seed config so prompts are skipped on --module runs after ensure_config path
        # First run: create config non-interactively by writing files as root
        seed = f"""
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
"""
        sudo(client, seed)
        for mod in ["assess", "backup_ssh", "admin_user", "ssh_keys", "ssh_perms"]:
            print(f"\n===== DRY-RUN MODULE {mod} =====")
            sudo(
                client,
                f"cd {REMOTE} && ./harden-ubuntu.sh --yes --dry-run --module {mod}",
                timeout=300,
            )
        sudo(client, f"cd {REMOTE} && ./harden-ubuntu.sh --status")
    finally:
        client.close()

    print("SMOKE_DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
