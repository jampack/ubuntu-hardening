#!/usr/bin/env python3
"""Copy the hardening tree to a guest home directory.

Usage:
  python test/deploy_to_guest.py
  python test/deploy_to_guest.py 192.0.2.10
  python test/deploy_to_guest.py --host 192.0.2.10 --user admin --port 22
  python test/deploy_to_guest.py --host 192.0.2.10 --user voyager --port 2121 --key ~/.ssh/id_ed25519 --yes

After host hardening, password auth is usually off — pass --user (ADMIN_USER),
--key (path to private key file), and --port (SSH_PORT, often 2121).
--key is a filesystem path (or inline PEM); prefer a key file.

Env overrides: HARDEN_HOST, HARDEN_USER, HARDEN_PASS, HARDEN_PORT, HARDEN_KEY.
"""
from __future__ import annotations

import argparse
import getpass
import os
import time
from io import StringIO
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parents[1]


def is_inline_private_key(value: str) -> bool:
    v = value.strip()
    return "BEGIN" in v and "PRIVATE KEY" in v


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


def load_private_key(path_or_pem: str, passphrase: str | None = None) -> paramiko.PKey:
    """Load from a key file path, or from inline PEM / OpenSSH private key text."""
    errors: list[str] = []
    label = "inline-key"
    file_obj: StringIO | None = None
    key_path: Path | None = None

    if is_inline_private_key(path_or_pem):
        pem = path_or_pem.strip().replace("\\n", "\n")
        if not pem.endswith("\n"):
            pem += "\n"
        file_obj = StringIO(pem)
    else:
        key_path = Path(path_or_pem).expanduser()
        label = str(key_path)
        if not key_path.is_file():
            raise SystemExit(
                f"Private key not found: {key_path}\n"
                "Pass a key *file path*, e.g. --key $env:USERPROFILE\\.ssh\\id_ed25519"
            )

    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            if file_obj is not None:
                file_obj.seek(0)
                return cls.from_private_key(file_obj, password=passphrase)
            assert key_path is not None
            return cls.from_private_key_file(str(key_path), password=passphrase)
        except paramiko.PasswordRequiredException:
            if passphrase:
                errors.append(f"{cls.__name__}: bad passphrase")
                continue
            phrase = getpass.getpass(f"Passphrase for {label}: ")
            try:
                if file_obj is not None:
                    file_obj.seek(0)
                    return cls.from_private_key(file_obj, password=phrase or None)
                assert key_path is not None
                return cls.from_private_key_file(str(key_path), password=phrase or None)
            except Exception as exc:
                errors.append(f"{cls.__name__}: {exc}")
        except Exception as exc:
            errors.append(f"{cls.__name__}: {exc}")
    raise SystemExit(
        "Could not load private key (tried Ed25519/RSA/ECDSA):\n  " + "\n  ".join(errors)
    )


def connect(
    host: str,
    user: str,
    password: str,
    ports: list[int],
    pkey: paramiko.PKey | None,
) -> paramiko.SSHClient:
    last: Exception | None = None
    # Prefer key when provided (post-harden); otherwise password then optional lab key.
    auth_order: list[str] = []
    if pkey is not None:
        auth_order.append("key")
    if password:
        auth_order.append("password")
    if pkey is None:
        lab = Path.home() / ".ssh" / "id_ed25519_harden_test"
        if lab.is_file():
            auth_order.append("lab_key")

    if not auth_order:
        raise SystemExit("Provide --key and/or a password (password auth may be disabled after harden)")

    for attempt in range(5):
        for port in ports:
            for auth in auth_order:
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
                    elif auth == "key":
                        kwargs["pkey"] = pkey
                    else:
                        kwargs["pkey"] = paramiko.Ed25519Key.from_private_key_file(
                            str(Path.home() / ".ssh" / "id_ed25519_harden_test")
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


def deploy(
    host: str,
    user: str,
    password: str,
    ports: list[int],
    pkey: paramiko.PKey | None,
) -> int:
    remote = f"/home/{user}/ubuntu-hardening"
    client = connect(host, user, password, ports, pkey)
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
        "--key",
        "-i",
        default=os.environ.get("HARDEN_KEY", ""),
        help="Private key file path (preferred), or inline PEM/OpenSSH private key text",
    )
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
    key_path = args.key
    port = args.port

    if not args.yes or not host:
        host = prompt_value("Host / IP", host)
    if not args.yes or not user:
        user = prompt_value("SSH user", user or "ubuntu")
    # Do not re-prompt when --key/HARDEN_KEY already set (especially inline PEM).
    if not key_path:
        key_path = prompt_value(
            "Private key path (Enter to skip / use password)",
            allow_empty=True,
        )
    if not key_path and (not args.yes or not password):
        password = prompt_value("SSH password", password, secret=True)
    elif key_path and not args.yes and not password and not is_inline_private_key(key_path):
        password = prompt_value(
            "SSH password fallback (Enter to skip)",
            password,
            secret=True,
            allow_empty=True,
        )

    if port:
        ports = [port]
    elif args.yes:
        ports = [22, 2121]
    else:
        port_in = prompt_value(
            "SSH port (Enter = try 22 then 2121)", allow_empty=True
        )
        ports = [int(port_in)] if port_in else [22, 2121]

    pkey = load_private_key(key_path) if key_path else None
    if key_path and is_inline_private_key(key_path):
        auth_note = "key=inline"
    elif key_path:
        auth_note = f"key={key_path}"
    else:
        auth_note = "password/lab-key"
    print(f"Deploying to {user}@{host} ports={ports} auth={auth_note} ...", flush=True)
    return deploy(host, user, password, ports, pkey)


if __name__ == "__main__":
    raise SystemExit(main())
