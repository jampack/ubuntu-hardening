# Ubuntu server hardening toolkit

Interactive, **fail-hard**, idempotent tooling for Ubuntu **26.04** hosts: core OS/SSH hardening, optional Docker checks, and optional Coolify master/slave prep. Built around
[`Ubuntu-26.04-Server-Hardening-Runbook.md`](Ubuntu-26.04-Server-Hardening-Runbook.md).

| Script | Purpose |
|--------|---------|
| `harden-ubuntu.sh` | **Primary** — host hardening (SSH, sysctl, Fail2ban, auditd, …); optional `--coolify-remote` for Coolify **slave** deploy user |
| `harden-docker.sh` | **Optional** — after Docker is installed; use `--coolify-master` on the Coolify **host** |

**Not automated:** provider/VPS firewall APIs, installing Docker or Coolify itself (use each product’s installer).

---

## Recommended order

1. Run **`harden-ubuntu.sh`** on a fresh Ubuntu 26.04 server.
2. Install apps / Docker / Coolify using each product’s docs.
3. If Docker is present, run **`harden-docker.sh`**.

For **Coolify**, follow the exact master/slave order in **Coolify setup** below (timing of “connect server” matters).

---

## Safety model (both scripts)

- Runs as **root**; Ubuntu only. Non-26.04 → loud warn + confirm (or abort).
- Missing baseline tools (`ip`, `ss`, `systemctl`, …) → **stop**.
- Each module: check → confirm → backup → apply → **verify**.
- Apply/verify failure → **STOP** the whole run (no silent success). State = `failed`.
- Explicit **[s]kip** or declining a hard gate is OK (state = `skipped` / `applied`).
- Typed gate: type **`CONFIRM`** for lockout-risk steps (SSH reload, port migrate,
  AllowUsers, audit `-e 2`, `/tmp` noexec, Docker daemon restart, …).
- Keep the current SSH session open; test a **new** session before closing.
- Never auto-bans your SSH client IP.
- SMTP app passwords: prompted hidden → Postfix maps only (not logged, not in `config.env`).

### Effective config checks

Where OpenSSH **first-value-wins** matters, modules compare intent to
`sshd -T` and stop if a competing drop-in wins. Services we install
(`fail2ban`, `auditd`, `apparmor`, optional `postfix`, Docker) are checked
**active** and **enabled at boot**.

---

## Host modules (`harden-ubuntu.sh`)

| Module | What it does |
|--------|----------------|
| `assess` | Read-only inventory |
| `backup_ssh` | Backup `sshd_config` / drop-ins + effective `sshd -T` |
| `admin_user` | Create `ADMIN_USER` + sudo |
| `ssh_keys` | Paste pubkey; require working key login |
| `ssh_hardening` | `00-ssh-hardening.conf`; `sshd -t` / `sshd -T` verify; reload |
| `ssh_perms` | Modes/ownership on SSH files + home `.ssh` |
| `ssh_port` | Migrate listener to `SSH_PORT` (default 2121) via `ssh.socket` or service |
| `sysctl` | Global + per-`INTERFACES` sysctl; runtime verify |
| `fail2ban` | SSH jail for `SSH_PORT`; optional Postfix SMTP relay |
| `auditd` | Rules + optional immutable `-e 2` |
| `unattended` | Security upgrades; **Automatic-Reboot false** |
| `apparmor` | Enforce + status |
| `service_minimize` | Inventory; **never** auto-disables critical units |
| `allow_users` | Restrict SSH; effective `allowusers` check |
| `coolify_remote` | Only with `--coolify-remote`: Coolify slave user + master pubkey + passwordless sudo |
| `tmp_harden` | `/tmp` `nodev,nosuid,noexec` via `tmp.mount` |
| `verify` | Final checklist; any FAIL → stop |

---

## Docker modules (`harden-docker.sh`) — optional

Prerequisite: Docker/containerd already installed and running (however you installed them).
This script does **not** install Docker.

| Module | What it does |
|--------|----------------|
| `docker_check` | Docker/containerd active + enabled; reject snap Docker |
| `docker_deploy_user` | Optional deploy user + SSH key. `--coolify-master`: import local Coolify keys + sudo. On slaves, auto-skip if user already from `coolify_remote` |
| `docker_api` | Fail if TCP **2375/2376** exposed |
| `docker_daemon` | Optional log rotation in `daemon.json` (restarts Docker) |
| `docker_socket` | Socket mode / docker group inspect |
| `docker_inventory` | Containers, privileges, socket mounts |
| `docker_network` | Inspect only — **never** flush Docker firewall rules |
| `docker_storage` | Disk/log review (no prune) |
| `docker_fail2ban` | Fail2ban vs Docker; optional doc-IP ban/unban test |
| `docker_verify` | Final Docker checklist; FAIL → stop |

Skip `docker_deploy_user` if you do not need a dedicated deploy account (CI/CD or a panel such as Coolify).

### Coolify setup

Do these steps **in order**. Connecting Coolify too early (before docker harden on the master) is what causes the SSH/sudo loops.

#### Master (this host runs Coolify)

1. **Host harden** (no Coolify flags):
   ```bash
   sudo ./harden-ubuntu.sh
   ```
2. **Install Coolify** with Coolify’s installer (it brings Docker).  
   **Do not** validate / connect the localhost server in the Coolify UI yet.
3. **Docker harden with master switch** (imports Coolify keys, deploy user, passwordless sudo):
   ```bash
   sudo ./harden-docker.sh --coolify-master
   ```
4. **Now** connect Coolify to this server in the UI:
   - User: `coolify` (or the deploy user the script used)
   - Port: your `SSH_PORT` (default **2121**)
   - Host: `172.17.0.1` or this machine’s LAN/public IP  
     (avoid `host.docker.internal` if it fails)
   - Key: Coolify’s default / localhost key (the one the script authorized)

#### Slave (remote server managed by a Coolify master)

1. **Host harden with remote switch** (creates Coolify-only user, paste **master** public key, passwordless sudo; Docker not required yet):
   ```bash
   sudo ./harden-ubuntu.sh --coolify-remote
   ```
2. **On the Coolify master UI** → Add Server → this slave’s IP, port `SSH_PORT`, user `coolify`, matching private key.  
   Let Coolify connect so it can **install Docker** (and anything else it needs) on the slave.
3. **Docker harden on the slave** — **without** `--coolify-master`:
   ```bash
   sudo ./harden-docker.sh
   ```
   The deploy user from step 1 is kept; `docker_deploy_user` skips. This pass hardens/checks Docker only.

If you run `--coolify-master` on a host that already used `--coolify-remote`, the script **warns** and asks before continuing.

---

## Paths

| | Host | Docker |
|--|------|--------|
| Config | `/etc/ubuntu-hardening/config.env` (mode `600`) | same file |
| State | `/var/lib/ubuntu-hardening/state.env` | `…/docker-state.env` |
| Logs | `/var/log/ubuntu-hardening/harden-*.log` | same dir |
| Backups | `/root/hardening-backups/<timestamp>/` | same |

Typical config keys: `ADMIN_USER`, `SSH_PORT`, `SECURITY_EMAIL`,
`FAIL2BAN_SENDER_EMAIL`, `INTERFACES` (uplink NICs for sysctl),
`SERVER_HOST`, `ADMIN_CLIENT_IP`, optional SMTP settings, optional `DEPLOY_USER`.

---

## Copy to the server

Prefer cloning from GitHub on the server:

```bash
git clone https://github.com/jampack/ubuntu-hardening.git
cd ubuntu-hardening
chmod +x harden-ubuntu.sh harden-docker.sh
```

Then follow **Coolify setup** (or plain host → Docker harden) — do not connect Coolify on the master until after `--coolify-master`.


Or copy from your admin machine (adjust the local path):

```bash
scp -r ./ubuntu-hardening user@SERVER:~/ubuntu-hardening
```

Optional lab helper:

```bash
python test/deploy_to_guest.py
# After harden (password auth off) — use ADMIN_USER + private key + SSH_PORT:
python test/deploy_to_guest.py --host SERVER --user voyager --port 2121 --key ~/.ssh/id_ed25519 --yes
```

`--key` is a **file path** (preferred). Inline PEM also works, but a key file is easier on PowerShell.


---

## Usage

```bash
sudo ./harden-ubuntu.sh              # first: wizard; later: menu
sudo ./harden-ubuntu.sh --wizard
sudo ./harden-ubuntu.sh --menu
sudo ./harden-ubuntu.sh --resume     # after a STOP / failed module
sudo ./harden-ubuntu.sh --module sysctl
sudo ./harden-ubuntu.sh --status
sudo ./harden-ubuntu.sh --dry-run --menu
sudo ./harden-ubuntu.sh --no-confirm   # skip accept/CONFIRM; still asks for values and lockout tests
sudo ./harden-ubuntu.sh --coolify-remote   # Coolify slave deploy user

sudo ./harden-docker.sh
sudo ./harden-docker.sh --coolify-master
sudo ./harden-docker.sh --module docker_check
sudo ./harden-docker.sh --status
sudo ./harden-docker.sh --resume
```

On failure the script prints **STOPPED** and how to resume
(`--module NAME` or `--resume`). Fix the issue first (e.g. competing
`sshd_config.d` drop-in), then re-run that module.

---

## Idempotency

Re-run anytime. Already-correct settings are detected (`verified`) and
redundant writes are skipped. Use `--status` / menu to see
`pending` / `applied` / `verified` / `skipped` / `failed`.

---

## Rollback hints

- **SSH:** restore under latest `/root/hardening-backups/<ts>/`, then `sshd -t`
  and `systemctl reload ssh` (or restore `ssh.socket.d` + `daemon-reload` /
  `restart ssh.socket`).
- **Sysctl:** restore `99-hardening.conf`, `sysctl --system`.
- **Fail2ban:** restore `jail.local`, `fail2ban-client -t`, restart fail2ban.
- **Audit immutable:** edit `rules.d`, `augenrules --check`, controlled **reboot**
  (do not `--load` while `enabled 2`).
- **Docker daemon.json:** restore backup, `systemctl restart docker`, retest apps/proxy.

---

## Provider firewall

Before SSH port migration, ensure the provider/lab firewall already allows
TCP `SSH_PORT` (default **2121**). This script does not open provider rules.

Lynis may report an empty host nftables ruleset if you filter only at the
provider — that can be intentional; confirm your real edge filter still allows
admin SSH and required services.
