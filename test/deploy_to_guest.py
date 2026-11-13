#!/usr/bin/env python3
"""Copy the hardening tree to a guest home directory.

Usage:
  python test/deploy_to_guest.py
  python test/deploy_to_guest.py 172.30.69.73
  python test/deploy_to_guest.py --host 172.30.69.73 --user khan --port 22

If host/user/password are not given on the CLI or via env, the script prompts.
"""
from __future__ import annotations

import argparse
import getpass
import os
import time
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parents[1]


def prompt_value(
    label: str, default: str = "", secret: bool = False, allow_empty: bool = False
) -> str:
    if default and not secret:
        hint = f" [{default}]"
    elif default and secret:
        hint = " [Enter keeps existing]"
    elif allow_empty:
        hint = " [optional]"
    else:
        hint = ""
    while True:
        if secret:
            value = getpass.getpass(f"{label}{hint}: ")
            if not value and default:
                return default
        else:
            value = input(f"{label}{hint}: ").strip()
            if not value and default:
                return default
        if value or allow_empty:
            return value
        print("Value required.")


def connect(host: str, user: str, password: str, ports: list[int]) -> paramiko.SSHClient:
    pkey_path = Path.home() / ".ssh" / "id_ed25519_harden_test"
    last: Exception | None = None
    for attempt in range(5):
        for port in ports:
            for auth in ("password", "key"):
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    kwargs: dict = dict(
                        hostname=host,
                        port=port,
                        username=user,
                        timeout=25,
                        banner_timeout=60,
                        auth_timeout=30,
                        allow_agent=False,
                        look_for_keys=False,
                    )
                    if auth == "password":
                        kwargs["password"] = password
                    else:
                        if not pkey_path.exists():
                            continue
                        kwargs["pkey"] = paramiko.Ed25519Key.from_private_key_file(
                            str(pkey_path)
                        )
                    client.connect(**kwargs)
                    print(f"connected {auth}:{port} (attempt {attempt + 1})", flush=True)
                    return client
                except Exception as exc:
                    last = exc
                    print(f"fail {auth}:{port}: {exc}", flush=True)
                    try:
                        client.close()
                    except Exception:
                        pass
        time.sleep(2)
    raise SystemExit(f"connect failed: {last}")


def run(client: paramiko.SSHClient, cmd: str) -> None:
    print(">>>", cmd, flush=True)
    _i, stdout, _e = client.exec_command(cmd, get_pty=True, timeout=60)
    print(stdout.read().decode(errors="replace"), flush=True)


def mkdir_p(sftp: paramiko.SFTPClient, remote: str) -> None:
    cur = ""
    for part in remote.split("/"):
        if not part:
            continue
        cur += "/" + part
        try:
            sftp.stat(cur)
        except OSError:
            sftp.mkdir(cur)


def deploy(host: str, user: str, password: str, ports: list[int]) -> int:
    remote = f"/home/{user}/ubuntu-hardening"
    client = connect(host, user, password, ports)
    try:
        run(client, f"rm -rf {remote} && mkdir -p {remote}/lib/modules {remote}/templates")
        sftp = client.open_sftp()
        files = [
            ROOT / "harden-ubuntu.sh",
            ROOT / "harden-docker.sh",
            ROOT / "README.md",
            ROOT / "lib" / "common.sh",
        ]
        files += sorted((ROOT / "lib" / "modules").glob("*.sh"))
        files += sorted(p for p in (ROOT / "templates").iterdir() if p.is_file())
        runbook = ROOT / "Ubuntu-26.04-Server-Hardening-Runbook.md"
        if runbook.exists():
            files.append(runbook)

        for lp in files:
            rel = lp.relative_to(ROOT).as_posix()
            rp = f"{remote}/{rel}"
            mkdir_p(sftp, "/".join(rp.split("/")[:-1]))
            data = lp.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            with sftp.open(rp, "wb") as fh:
                fh.write(data)
            print("put", rp, flush=True)

        sftp.chmod(f"{remote}/harden-ubuntu.sh", 0o755)
        sftp.chmod(f"{remote}/harden-docker.sh", 0o755)
        sftp.close()
        run(
            client,
            f"bash -n {remote}/harden-ubuntu.sh && "
            f"bash -n {remote}/harden-docker.sh && "
            f"bash -n {remote}/lib/common.sh && "
            f"bash -n {remote}/lib/modules/ssh_keys.sh && "
            f"bash -n {remote}/lib/modules/docker_check.sh && "
            f"echo SYNTAX_OK && ls -la {remote}",
        )
    finally:
        client.close()
    print(f"COPY_DONE -> {user}@{host}:{remote}", flush=True)
    print("On guest: cd ~/ubuntu-hardening && sudo ./harden-ubuntu.sh", flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy hardening scripts to a guest")
    parser.add_argument("host_pos", nargs="?", help="Guest IP/hostname")
    parser.add_argument("--host", default=os.environ.get("HARDEN_HOST", ""))
    parser.add_argument("--user", default=os.environ.get("HARDEN_USER", ""))
    parser.add_argument("--password", default=os.environ.get("HARDEN_PASS", ""))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("HARDEN_PORT", "0") or "0"),
        help="SSH port (default: ask, or try 22 then 2121)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Do not prompt when values are already provided via CLI/env",
    )
    args = parser.parse_args()

    print("Deploy ubuntu-hardening scripts to guest", flush=True)
    host = args.host_pos or args.host
    user = args.user
    password = args.password
    port = args.port

    if not args.yes or not host:
        host = prompt_value("Host / IP", host)
    if not args.yes or not user:
        user = prompt_value("SSH user", user or "khan")
    if not args.yes or not password:
        password = prompt_value("SSH password", password, secret=True)

    if port:
        ports = [port]
    else:
        port_in = prompt_value(
            "SSH port (Enter = try 22 then 2121)", allow_empty=True
        )
        ports = [int(port_in)] if port_in else [22, 2121]

    print(f"Deploying to {user}@{host} ports={ports} ...", flush=True)
    return deploy(host, user, password, ports)


if __name__ == "__main__":
    raise SystemExit(main())
