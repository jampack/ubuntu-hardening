# Ubuntu 26.04 LTS – Server Hardening & Implementation Runbook

**Purpose:** Reusable implementation procedure for a fresh Ubuntu 26.04 LTS server. This document describes intended controls and expected outcomes; it is not evidence that any control has been applied or validated.

**SSH policy source of truth:** Section 6 defines the SSH daemon hardening drop-in. Sections 7–11 and 14 apply, migrate, or monitor that policy — they must not introduce competing `sshd_config` / drop-in directives for the same keywords.

**Target SSH port:** `2121` (change consistently if your deployment requires another port)
**Administrative account placeholder:** `ADMIN_USER` (replace with the chosen account name before executing commands)
**Authentication target:** Ed25519 public key authentication; password and direct root SSH login disabled
**Firewall target:** Hosting-provider firewall with default-deny inbound policy; review the provider and host networking before applying changes

Use Vim for interactive editing. Replace every placeholder before execution: `ADMIN_USER` (administrator username; use its primary group unless different), `SERVER_IP` (public or reachable server address), `SECURITY_EMAIL` (notification recipient), `FAIL2BAN_SENDER_EMAIL` (sender address), `SMTP_USERNAME` and `SMTP_APP_PASSWORD` (relay credentials), and `INTERFACE` (discovered network interface), `SERVER_HOST` and `ADMIN_CLIENT_IP` (for Match-context checks), and `SERVICE_NAME` (one reviewed service in Section 21). Keep private keys on the administrator’s client. Expected output describes the intended result, not evidence of implementation.

---

## 1. Security objectives

For each control, follow its objective, implementation/configuration commands, validation procedure, expected result, and recovery guidance where provided. If a subsection lacks an explicit recovery command, use the documented backup or provider-console recovery path; do not proceed with a change that could lock out administration or disrupt workloads without a rollback plan.

**Control structure:** Objective describes why the control is needed; Implementation describes the sequence; Configuration identifies files and settings; Validation contains checks; Expected result describes the intended output; Recovery/rollback explains how to restore service safely. A step that is not applicable should be omitted or explicitly marked not applicable for that deployment.

- Disable direct root SSH login.
- Disable SSH password authentication.
- Enforce SSH public-key authentication.
- Use a dedicated administrative account.
- Restrict SSH connection attempts and sessions.
- Disable unnecessary SSH forwarding features.
- Use strong cryptographic algorithms.
- Protect SSH configuration and private keys.
- Change SSH port from 22 to 2121.
- Restrict inbound connections through the provider firewall.
- Install and configure Fail2ban.
- Configure automatic IP banning and email notifications.
- Monitor authentication events and periodically audit SSH security.

## 2. Initial server assessment

**Objective:** Discover the image, networking, access method, and installed security components before changing them. Do not apply settings based on assumed interface names, firewall state, package versions, or configuration paths. Keep provider-console access available.

Check Ubuntu version:

```bash
lsb_release -a

```

Check OpenSSH version:

```bash
ssh -V

```

Check SSH configuration:

```bash
sudo sshd -T

```

Check SSH service:

```bash
sudo systemctl status ssh

```

Check listening ports:

```bash
sudo ss -tlnp | grep ssh
```

Discover interfaces, routes (IPv4 and IPv6), and firewall state (inspect before changing):

```bash
ip -br link
ip -br address
ip -4 route
ip -6 route
ip -6 addr show scope global
sudo ss -tulpen
sudo ufw status verbose
command -v nft >/dev/null && sudo nft list ruleset
command -v iptables >/dev/null && sudo iptables -S
command -v ip6tables >/dev/null && sudo ip6tables -S
systemctl status ssh.socket ssh --no-pager
systemctl is-enabled ssh.socket ssh.service 2>/dev/null
findmnt /tmp
df -h /
```

**Time synchronization (mandatory discovery):** Correct time is required for audit records, authentication logs, TLS certificates, and incident investigation. Ubuntu 26.04 LTS fresh installs default to Chrony (replacing `systemd-timesyncd`). Discover the active time service before changing it:

```bash
timedatectl status
systemctl is-active chrony.service systemd-timesyncd.service 2>/dev/null
systemctl is-enabled chrony.service systemd-timesyncd.service 2>/dev/null
command -v chronyc >/dev/null && chronyc tracking
command -v chronyc >/dev/null && chronyc sources -v
```

Expected on a typical fresh Ubuntu 26.04 LTS install: Chrony active, system clock synchronized (`System clock synchronized: yes` / Chrony reporting a valid source). Do not disable Chrony casually. If an upgraded host still uses `systemd-timesyncd`, record that fact; migrating to Chrony is optional on upgraded hosts and is described in the Ubuntu 26.04 release notes.

Check installed security-related package versions, the sudo implementation, and cloud-init status where present:

```bash
dpkg-query -W openssh-server auditd fail2ban postfix unattended-upgrades apparmor chrony 2>/dev/null
ssh -V
dpkg-query -W 'sudo*' 2>/dev/null
readlink -f /usr/bin/sudo
sudo --version | head -n 5
command -v cloud-init >/dev/null && cloud-init status --long
```

**Ubuntu 26.04 notes (verify on the installed image):** Official release notes list OpenSSH `1:10.2p1` (DSA removed; hybrid post-quantum KEX `mlkem768x25519-sha256` available by default) and `sudo-rs` as the default sudo provider (classic sudo available as `sudo.ws`). Confirm the packages actually installed before relying on those defaults.

**Update the base OS:** Before applying hardening, review and install available updates during a maintenance window. Keep console access available and reboot if the kernel or required services need it:

```bash
sudo apt update
apt list --upgradable
sudo apt full-upgrade
```

After any required reboot, reconnect and repeat the assessment commands. This is a planned implementation step, not a record of completed work.

## 3. Back up SSH configuration

Inspect the paths and ensure the backup destination is unique. Back up the main file and the drop-in directory if it exists; record the effective settings for comparison.

```bash
sudo ls -la /etc/ssh/sshd_config /etc/ssh/sshd_config.d
sudo cp -a /etc/ssh/sshd_config "/root/sshd_config.bkp.$(date +%Y%m%d-%H%M%S)"
if sudo test -d /etc/ssh/sshd_config.d; then sudo cp -a /etc/ssh/sshd_config.d "/root/sshd_config.d.bkp.$(date +%Y%m%d-%H%M%S)"; fi
sudo sshd -T | sudo tee "/root/sshd-effective-config.$(date +%Y%m%d-%H%M%S).bkp" >/dev/null
```

The timestamped backup files are stored under `/root/`. Verify the exact filenames and root ownership before proceeding.

## 4. Create administrative account

Create the dedicated administrator:

```bash
sudo adduser ADMIN_USER

```

Grant sudo privileges:

```bash
sudo usermod -aG sudo ADMIN_USER

```

Verify:

```bash
id ADMIN_USER

```

Test sudo:

```bash
su - ADMIN_USER
sudo whoami

```

Expected result:

```text
root
```

Verify the account and sudo group membership:

```bash
id ADMIN_USER
sudo -l -U ADMIN_USER
```

Expected: `ADMIN_USER` exists, belongs to the `sudo` group, and has the intended sudo privileges. The interactive `sudo whoami` test above should return `root`.

**Ubuntu 26.04 sudo provider:** Fresh installs default to `sudo-rs`. Verify which binary is active:

```bash
readlink -f /usr/bin/sudo
sudo --version | head -n 5
dpkg-query -W sudo sudo-rs 2>/dev/null
```

For routine `sudo` usage the commands above remain valid. Do not assume classic-sudo-only features or log formats without checking. When adding audit execution watches later, watch the resolved executable path from `readlink -f /usr/bin/sudo`, not a guessed path.

## 5. Generate Ed25519 SSH key on Windows

Open Windows PowerShell.

Generate the key (use a strong passphrase when prompted; do not create an empty-passphrase key for production administrative access):

```powershell
ssh-keygen -t ed25519 -a 100 -C "ADMIN_USER@ubuntu-server"

```

Default key locations (replace `USERNAME` with the Windows account name if different from `$HOME`):

```text
C:\Users\USERNAME\.ssh\id_ed25519
C:\Users\USERNAME\.ssh\id_ed25519.pub

```

The **private** key must remain on the administrator’s client (Windows). Never copy, SCP, email, or paste the private key onto the server. Only the **public** key is installed in `authorized_keys`.

Display the public key:

```powershell
Get-Content $HOME\.ssh\id_ed25519.pub

```

Install the public key on Ubuntu:

```bash
mkdir -p /home/ADMIN_USER/.ssh

chmod 700 /home/ADMIN_USER/.ssh

vim /home/ADMIN_USER/.ssh/authorized_keys

```

Paste the public key into the file.

Set permissions:

```bash
chmod 600 /home/ADMIN_USER/.ssh/authorized_keys

chown -R ADMIN_USER:ADMIN_USER /home/ADMIN_USER/.ssh

```

Test Windows SSH login:

```powershell
ssh -i $HOME\.ssh\id_ed25519 ADMIN_USER@SERVER_IP

```

Verify:

```bash
whoami
sudo whoami

```

Expected: `whoami` returns `ADMIN_USER`; `sudo whoami` returns `root`. Verify the installed public key file and fingerprint:

```bash
sudo stat -c '%a %U:%G %n' /home/ADMIN_USER/.ssh /home/ADMIN_USER/.ssh/authorized_keys
sudo ssh-keygen -lf /home/ADMIN_USER/.ssh/authorized_keys
```

Expected permissions: `.ssh` is `700 ADMIN_USER:ADMIN_USER`; `authorized_keys` is `600 ADMIN_USER:ADMIN_USER`. Compare the displayed fingerprint with the public key on the administrator's Windows machine (`ssh-keygen -lf $HOME\.ssh\id_ed25519.pub`). The private key must remain on the client.

## 6. Configure centralized SSH hardening

**Objective:** Apply a consistent SSH access policy while preserving provider-required settings and preventing configuration precedence surprises.

**Prerequisites:** Complete Sections 3–5. Keep the initial SSH session open and ensure provider-console access is available. Inspect `/etc/ssh/sshd_config`, its `Include` directives, and every included drop-in before modifying anything. Ubuntu commonly includes `/etc/ssh/sshd_config.d/*.conf`, but confirm the installed configuration.

```bash
sudo grep -nE '^\s*Include|^\s*(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|MaxSessions|LogLevel|TCPKeepAlive)\b' /etc/ssh/sshd_config
sudo find /etc/ssh/sshd_config.d -maxdepth 1 -type f -name '*.conf' -print 2>/dev/null | sort
sudo grep -RniE '^\s*(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|MaxSessions|LogLevel|TCPKeepAlive)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null
```

OpenSSH uses the **first value obtained** for most keywords (including across `Include`d files). The order of `Include` directives and the lexicographic order of included drop-ins therefore matter. A later file such as `99-hardening.conf` does **not** override an earlier matching directive. Resolve duplicates deliberately; do not assume last-wins. Review cloud-init-related files only if they exist; Section 7 covers that separately.

**Ubuntu 26.04 OpenSSH baseline:** Confirm with `ssh -V` / `dpkg-query -W openssh-server`. Release notes for Ubuntu 26.04 LTS document OpenSSH `1:10.2p1`, removal of DSA, and availability of the hybrid post-quantum key exchange `mlkem768x25519-sha256` by default. Prefer preserving distribution cryptographic defaults (ciphers, KEX, host-key algorithms) unless an organizational policy requires a justified override. Unnecessary algorithm restrictions can break clients and discard useful defaults such as post-quantum hybrid KEX.

**Configured vs negotiated algorithms:** `sshd -T` shows the **server-offered** algorithm lists. The algorithms used on a live connection are the intersection negotiated with that specific client. Validate both the offered lists and a real client connection (client verbose output) when crypto policy matters.

Create or edit a **single** early hardening drop-in with Vim so first-value-wins can take effect after reconciling earlier directives. The example filename `00-ssh-hardening.conf` is intentionally early; use it only after confirming the main file includes this directory and that earlier matching directives are reconciled. Prefer putting required policy keywords in one early drop-in rather than splitting them across `00-` and `99-` files (a late file is ineffective if the same keyword already appeared earlier).

```bash
sudo vim /etc/ssh/sshd_config.d/00-ssh-hardening.conf
```

### Complete SSH hardening configuration

```sshconfig
# ====================================
# SSH NETWORK CONFIGURATION
# ====================================

# Port is recorded here for daemon consistency and Match/context checks.
# When ssh.socket is active (Ubuntu default), the systemd socket ListenStream
# controls the TCP listen port — see Section 11. Do not assume Port alone
# migrates the listener under socket activation.
Port 2121
AddressFamily any

# ====================================
# AUTHENTICATION HARDENING
# ====================================

PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
PermitEmptyPasswords no

# ====================================
# CONNECTION LIMITS
# ====================================

LoginGraceTime 30
MaxAuthTries 3
MaxSessions 2
MaxStartups 10:30:60

# ====================================
# SESSION MANAGEMENT
# ====================================

ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
TCPKeepAlive no

# ====================================
# FORWARDING RESTRICTIONS
# ====================================

X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
AllowStreamLocalForwarding no

# ====================================
# ADDITIONAL SECURITY
# ====================================

PermitUserEnvironment no
IgnoreRhosts yes
HostbasedAuthentication no
GSSAPIAuthentication no

# ====================================
# CRYPTOGRAPHIC POLICY (OPTIONAL)
# ====================================
# Prefer Ubuntu/OpenSSH defaults unless policy requires otherwise.
# If SHA-1-based MACs must be excluded, uncomment the next line AFTER
# verifying client compatibility. Do not restrict Ciphers / KexAlgorithms /
# HostKeyAlgorithms casually — that can remove post-quantum hybrid KEX and
# break modern clients.
# MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
```

Set permissions:

```bash
sudo chown root:root /etc/ssh/sshd_config.d/00-ssh-hardening.conf
sudo chmod 600 /etc/ssh/sshd_config.d/00-ssh-hardening.conf
```

**Do not create a competing `99-hardening.conf` for the same keywords.** If an older draft left `/etc/ssh/sshd_config.d/99-hardening.conf` with `LogLevel` / `TCPKeepAlive`, inspect it and remove or reconcile those duplicates so the early drop-in is effective:

```bash
sudo ls -la /etc/ssh/sshd_config.d/
sudo grep -RniE '^\s*(LogLevel|TCPKeepAlive|Port|PasswordAuthentication)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/
```

OpenSSH uses the first value obtained, so later duplicate directives do not override earlier ones. Check for duplicate definitions and inspect effective settings with `sshd -T` before and after applying the configuration.

Validate before applying:

```bash
sudo sshd -t
```

No output and exit status 0 means the configuration parses successfully. Do not reload SSH if validation fails.

Inspect the effective configuration (this is more important than inspecting only the source files):

```bash
sudo sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|maxsessions|maxauthtries|maxstartups|loglevel|tcpkeepalive|allowtcpforwarding|allowagentforwarding|x11forwarding)'
```

Cryptographic algorithm lists are verified in **Section 9** (do not add a second crypto drop-in). Also validate with a **connection-specific** context when Match blocks or user/address restrictions exist (replace placeholders; do not leave them unresolved):

```bash
sudo sshd -T -C user=ADMIN_USER,host=SERVER_HOST,addr=ADMIN_CLIENT_IP,lport=2121 | grep -E '^(allowusers|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|maxsessions|loglevel)'
```

`sshd -T` without `-C` shows global defaults. `sshd -T -C ...` evaluates Match criteria for that connection. Use both when Match or `AllowUsers` is configured (Section 22).

Expected key values include:

```text
port 2121
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
kbdinteractiveauthentication no
maxsessions 2
loglevel VERBOSE
tcpkeepalive no
allowtcpforwarding no
allowagentforwarding no
x11forwarding no
```

OpenSSH generally uses the first value obtained for a keyword. Check for duplicate definitions when an effective value does not match the intended value:

```bash
sudo grep -RniE '^\s*(MaxSessions|LogLevel|TCPKeepAlive)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/
```

If conflicting duplicate directives are found, back up the relevant file and edit it deliberately with Vim. Do not run a blind `sed` deletion against an unknown configuration. Re-run `sshd -t` and `sshd -T` after the edit.

Do **not** reload yet if validation failed. When `sshd -t` succeeds and effective values match this section, proceed to **Section 8** to reload and confirm. Keep the original administrative session open until a second SSH connection has succeeded. **Recovery:** restore the timestamped SSH backups from Section 3 via the open session/provider console, validate with `sshd -t`, then reload (Section 8).

## 7. Cloud-init SSH configuration review

**Objective:** Prevent cloud-init from reintroducing weaker SSH authentication settings during provisioning or reboot.

**Implementation:** Discover cloud-init SSH configuration; do not assume a particular file exists or contains specific values.

```bash
sudo grep -RniE '^\s*(ssh_pwauth|disable_root|ssh_deletekeys):' /etc/cloud/cloud.cfg /etc/cloud/cloud.cfg.d 2>/dev/null
sudo grep -RniE 'ssh_pwauth|disable_root|ssh_deletekeys' /var/lib/cloud/instance 2>/dev/null
```

Review the installed cloud-init documentation and provider image behavior before changing cloud-init values. If password SSH authentication is to be disabled at provisioning, a suitable cloud-init configuration may include:

```yaml
ssh_pwauth: false
```

Do not set `disable_root` or `ssh_deletekeys` based on assumptions; these options affect cloud-init behavior and are not substitutes for effective OpenSSH settings. Back up the file before editing with Vim.

**Validation:**

```bash
sudo sshd -t
sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication)'
```

**Expected result:** Effective SSH daemon settings, not cloud-init file contents alone, show the intended access policy. Recheck after provisioning-related changes and reboot.

**Recovery:** Restore the cloud-init backup through the provider console if provisioning or SSH access is affected; validate with `sshd -t` before reloading SSH.

## 8. Reload SSH (apply Section 6 — do not reconfigure)

**Objective:** Load the Section 6 policy into the running daemon. Do not edit SSH drop-ins in this section.

**Prerequisites:** Section 6 complete; `sudo sshd -t` succeeded. Keep the existing administrative session open.

```bash
sudo systemctl reload ssh
```

This does not migrate the listen port under socket activation — see Section 11.

Confirm the activation model (do not require both units active):

```bash
systemctl is-enabled ssh.socket ssh.service 2>/dev/null
systemctl is-active ssh.socket ssh.service 2>/dev/null
systemctl status ssh.socket ssh.service --no-pager
sudo ss -tlnp | grep -E '(:22|:2121)\s'
```

| Model | Typical state | Listener owner |
|---|---|---|
| Socket-activated (Ubuntu 26.04 default) | `ssh.socket` listening; `ssh.service` may be inactive until a connection | systemd via `ssh.socket` |
| Traditional service-managed | `ssh.service` running; `ssh.socket` disabled/inactive | `sshd` directly |

Re-check **effective** values against Section 6 (do not add new directives here):

```bash
sudo sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|permitemptypasswords|maxsessions|loglevel|tcpkeepalive) '
```

Expected: same values as Section 6. Then open a second SSH session before closing the first.

## 9. SSH cryptography verification (no additional drop-ins)

**Objective:** Verify cryptography already governed by Section 6 / distribution defaults. Do **not** create another drop-in or re-state `MACs`/`Ciphers`/`KexAlgorithms` here.

**Mandatory vs optional:** Preserving Ubuntu/OpenSSH defaults is the baseline. Optional MAC restrictions belong only in Section 6’s commented block, after client testing.

| View | Command / meaning |
|---|---|
| Server-offered | `sudo sshd -T \| grep -E '^(ciphers\|macs\|kexalgorithms\|hostkeyalgorithms\|pubkeyacceptedalgorithms) '` |
| Negotiated for a session | Client `ssh -vvv` from the administrator workstation |

Expected: modern algorithms for the installed OpenSSH package (Ubuntu 26.04: commonly ChaCha20-Poly1305, AES-GCM, Curve25519, hybrid PQ KEX such as `mlkem768x25519-sha256`); DSA absent. Host private key modes are checked in Section 10.

## 10. SSH filesystem permissions

**Objective:** Ensure SSH configuration and key files cannot be modified or read by unauthorized users.

**Implementation:** Inspect ownership and modes first. Apply the intended values only to the listed files and directories; do not recursively change `/etc/ssh` or an entire home directory.

```bash
sudo chown root:root /etc/ssh/sshd_config
sudo chmod 644 /etc/ssh/sshd_config
sudo chown root:root /etc/ssh/sshd_config.d
sudo chmod 755 /etc/ssh/sshd_config.d
sudo chown root:root /etc/ssh/sshd_config.d/00-ssh-hardening.conf
sudo chmod 600 /etc/ssh/sshd_config.d/00-ssh-hardening.conf
sudo chmod 600 /etc/ssh/ssh_host_*_key
sudo chown root:root /etc/ssh/ssh_host_*_key
sudo chown ADMIN_USER:ADMIN_USER /home/ADMIN_USER
sudo chmod 750 /home/ADMIN_USER
sudo install -d -o ADMIN_USER -g ADMIN_USER -m 700 /home/ADMIN_USER/.ssh
sudo chown ADMIN_USER:ADMIN_USER /home/ADMIN_USER/.ssh/authorized_keys
sudo chmod 600 /home/ADMIN_USER/.ssh/authorized_keys
```

If the primary group differs from the username, replace the group in the commands. Confirm OpenSSH’s strict-mode requirements before altering ownership of other files.

**Validation:**


```bash
stat -c '%a %U:%G %n' /etc/ssh

stat -c '%a %U:%G %n' /etc/ssh/sshd_config

stat -c '%a %U:%G %n' /etc/ssh/sshd_config.d

stat -c '%a %U:%G %n' /etc/ssh/sshd_config.d/00-ssh-hardening.conf

```

Verify user SSH permissions:

```bash
stat -c '%a %U:%G %n' /home/ADMIN_USER

stat -c '%a %U:%G %n' /home/ADMIN_USER/.ssh

stat -c '%a %U:%G %n' /home/ADMIN_USER/.ssh/authorized_keys

```

Expected:

| Path                    | Permissions |
| ----------------------- | ----------- |
| `/etc/ssh`              | 755         |
| `sshd_config`           | 644         |
| Hardening configuration | 600         |
| Host private keys       | 600         |
| `/home/ADMIN_USER`         | 750         |
| `.ssh`                  | 700         |
| `authorized_keys`       | 600         |

## 11. Change SSH port to 2121

**Objective:** Move SSH to TCP 2121 without losing administrative access and without leaving port 22 exposed or creating competing listeners.

**Prerequisites:** Keep the original administrative session and provider console available. Confirm the provider firewall already allows TCP 2121 **before** removing TCP 22. Determine the activation model on this image. Do not assume socket activation is enabled or that the listener is bound to all interfaces.

### 11.1 Discover the active SSH listen model

```bash
systemctl is-enabled ssh.socket ssh.service 2>/dev/null
systemctl is-active ssh.socket ssh.service 2>/dev/null
systemctl status ssh.socket ssh.service --no-pager
sudo systemctl cat ssh.socket
sudo systemctl show ssh.socket -p Listen -p FragmentPath -p DropInPaths
sudo ss -tlnp | grep -E '(:22|:2121)\s'
sudo sshd -T | grep '^port '
```

| Observation | Model | Port migration path |
|---|---|---|
| `ssh.socket` is `enabled` and `active (listening)`; `ss` shows `systemd` owning `:22` | Socket-activated | Override `ssh.socket` ListenStream (Section 11.2). `Port` in `sshd_config` alone does **not** move the listener. |
| `ssh.service` is enabled/active and `ssh.socket` is disabled/inactive; `ss` shows `sshd` owning `:22` | Traditional service | Ensure `Port 2121` is effective in sshd config, then reload/restart `ssh.service` only (Section 11.3). Do **not** enable `ssh.socket`. |

Do **not** require both `ssh.service` and `ssh.socket` to be active as a universal success criterion.

### 11.2 Socket-activated migration (typical Ubuntu 26.04)

Back up any existing override directory first:

```bash
if sudo test -d /etc/systemd/system/ssh.socket.d; then sudo cp -a /etc/systemd/system/ssh.socket.d "/root/ssh.socket.d.bkp.$(date +%Y%m%d-%H%M%S)"; fi
sudo mkdir -p /etc/systemd/system/ssh.socket.d
sudo vim /etc/systemd/system/ssh.socket.d/listen.conf
```

Contents:

```ini
[Socket]
ListenStream=
ListenStream=0.0.0.0:2121
ListenStream=[::]:2121
```

The empty `ListenStream=` clears inherited listeners (critical — without it, systemd may keep listening on 22 **and** 2121). Retain only the address families appropriate to the host (omit the IPv6 line if the host has no usable IPv6, or bind to specific addresses if required). Confirm provider firewall access on TCP 2121 before applying.

Also keep `Port 2121` in the validated sshd drop-in (Section 6) so daemon/Match context matches the listen port, then:

```bash
sudo sshd -t
sudo systemctl daemon-reload
sudo systemctl cat ssh.socket
sudo systemctl restart ssh.socket
```

Verify immediately (keep the old session open):

```bash
sudo systemctl status ssh.socket --no-pager
sudo systemctl show ssh.socket -p Listen
sudo ss -tlnp | grep -E '(:22|:2121)\s'
```

Expected: TCP 2121 is listening on the intended addresses; **port 22 is not listening**. If both 22 and 2121 appear, the empty `ListenStream=` reset was missed or another override remains — fix before closing the old session.

### 11.3 Traditional service-managed migration (non-socket)

Only if Section 11.1 confirmed socket activation is **not** in use:

```bash
sudo sshd -t
sudo systemctl reload ssh
# If reload does not apply the listen port change on this image:
# sudo systemctl restart ssh
sudo ss -tlnp | grep -E '(:22|:2121)\s'
```

Expected: sshd listens on 2121 only. Do not enable `ssh.socket` during this path.

### 11.4 Verify a new client connection before closing the old session

From Windows:

```powershell
ssh -p 2121 -i $HOME\.ssh\id_ed25519 ADMIN_USER@SERVER_IP
```

Only after the new session succeeds, close the original session and remove the provider firewall rule for TCP 22 if that is the intended end state.

### 11.5 Rollback

If the new port does not accept connections, use the still-open session or provider console:

**Socket path rollback:**

```bash
sudo rm -f /etc/systemd/system/ssh.socket.d/listen.conf
# Or restore the timestamped ssh.socket.d backup from /root/
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket
sudo ss -tlnp | grep -E '(:22|:2121)\s'
```

**Service path rollback:** restore the Section 3 SSH config backups, `sudo sshd -t`, then `sudo systemctl reload ssh` (or restart if required).

Re-open provider firewall access to the previous SSH port if needed. Test a fresh connection before ending the recovery session.

## 12. External firewall

Use the firewall arrangement supported by the hosting provider and deployment. Review provider rules and the host firewall before changing either; do not assume UFW is inactive or that no local firewall is required.

Initial host-hardening policy (adapt to the provider and required services):

| Direction | Protocol | Port | Action |
|---|---|---:|---|
| Inbound | TCP | 2121 | ALLOW, preferably restricted to administrator source IPs |
| Inbound | All other ports | All | DROP unless explicitly required |
| Outbound | As required | All | Preserve required package, DNS, SMTP relay, time, and application egress |

This is the pre-Coolify policy. Section 24 identifies additional Coolify ports that may be required during setup; expose only those required and remove temporary dashboard ports after access is moved behind a domain. Restrict SSH to trusted source IPs wherever possible. Verify provider-firewall access to TCP 2121 before removing access to port 22.

### 12.1 Verify the provider firewall and local firewall state

The provider firewall is authoritative for inbound traffic. Verify its rules in the hosting provider control panel; a local command cannot prove that the provider-side rules are correct.

Expected provider policy (adapt to the selected SSH port and required services):

- SSH allowed, preferably only from trusted administrator IPs.
- All other inbound ports denied unless explicitly required.
- No public SMTP port 25 for a local outbound-only Postfix relay.
- Add Coolify and application ports only as described in Section 24 and the provider's documented requirements; avoid opening all ports for Docker.

Inspect the local firewall state before deciding whether it should be active or inactive for the deployment. Do **not** assume UFW must be active or inactive — record the chosen design:

```bash
sudo ufw status verbose
command -v nft >/dev/null && sudo nft list ruleset
command -v iptables >/dev/null && sudo iptables -S
command -v ip6tables >/dev/null && sudo ip6tables -S
```

Expected result depends on the chosen firewall design. If UFW is selected, ensure its rules permit the intended SSH port (IPv4 and IPv6 as applicable) before enabling it. If the provider firewall is the selected inbound boundary and UFW is intentionally inactive, document that choice. Do not enable or disable a host firewall without planning equivalent rules and testing a second session.

**IPv4 and IPv6 must both be considered.** An IPv6 listener or route can bypass an IPv4-only provider or host firewall policy:

```bash
ip -4 addr show scope global
ip -6 addr show scope global
ip -4 route
ip -6 route
sudo ss -tulpen
```

Review all listening sockets and investigate any unexpected public listener on either address family. After Coolify/Docker is installed, also review Docker-published ports (Section 25); do not flush Docker-managed firewall rules.

From a separate machine outside the VPS, test public exposure for both families when the host has public IPv6 (install/use `nmap` on the external machine):

```bash
nmap -Pn -p 22,25,2121 SERVER_IP
# If the host has a public IPv6 address (SERVER_IPV6), also test:
# nmap -6 -Pn -p 22,25,2121 SERVER_IPV6
```

Expected: TCP 2121 open from intended sources; ports 22 and 25 closed or filtered on both families that are publicly routed. Provider firewall behavior can make denied ports appear as `filtered` rather than `closed`. A local `ufw status` or `nft list` command does **not** prove provider-side rules.

### 12.2 Kernel and network sysctl hardening

**Objective:** Apply selected filesystem, kernel, and network hardening values persistently.

**Prerequisites:** Discover the interface and routing configuration first. Back up the target file if it exists, and inspect competing sysctl files because values may be overridden by later files or interface-specific settings.

```bash
sudo ls -l /etc/sysctl.d/99-hardening.conf 2>/dev/null
if sudo test -f /etc/sysctl.d/99-hardening.conf; then sudo cp -a /etc/sysctl.d/99-hardening.conf "/root/99-hardening.conf.bkp.$(date +%Y%m%d-%H%M%S)"; fi
sudo grep -RniE '^(fs\.protected_fifos|fs\.suid_dumpable|kernel\.kptr_restrict|kernel\.unprivileged_bpf_disabled|net\.core\.bpf_jit_harden|net\.ipv4\.conf|net\.ipv6\.conf)' /etc/sysctl.conf /etc/sysctl.d 2>/dev/null
```

Edit with Vim:

```bash
sudo vim /etc/sysctl.d/99-hardening.conf
```

Merge the following intended settings after reviewing conflicts:

```ini
# Filesystem hardening
fs.protected_fifos = 2
fs.suid_dumpable = 0

# Kernel hardening
kernel.kptr_restrict = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# IPv4 network hardening
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 2

# IPv6 network hardening
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Replace INTERFACE with the interface discovered using: ip -br link (do not leave the literal placeholder)
net.ipv4.conf.INTERFACE.accept_redirects = 0
net.ipv4.conf.INTERFACE.send_redirects = 0
net.ipv4.conf.INTERFACE.log_martians = 1
net.ipv6.conf.INTERFACE.accept_redirects = 0
```

Apply settings after editing:

```bash
sudo sysctl --system
```

**Recovery:** If a key is unsupported or routing/connectivity is affected, restore the backup (or remove the newly created file if no prior file existed), run `sudo sysctl --system`, and recheck connectivity and runtime values.

Verify the effective runtime values (including the active interface):

```bash
sudo sysctl \
fs.protected_fifos fs.suid_dumpable \
kernel.kptr_restrict kernel.unprivileged_bpf_disabled net.core.bpf_jit_harden \
net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects \
net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects \
net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians \
net.ipv4.conf.all.rp_filter \
net.ipv4.conf.INTERFACE.accept_redirects net.ipv4.conf.INTERFACE.send_redirects net.ipv4.conf.INTERFACE.log_martians \
net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects net.ipv6.conf.INTERFACE.accept_redirects
```

Expected values:

| Setting | Expected |
|---|---:|
| `fs.protected_fifos` | `2` |
| `fs.suid_dumpable` | `0` |
| `kernel.kptr_restrict` | `2` |
| `kernel.unprivileged_bpf_disabled` | `1` |
| `net.core.bpf_jit_harden` | `2` |
| All listed IPv4/IPv6 `accept_redirects` | `0` |
| All listed IPv4 `send_redirects` | `0` |
| All listed `log_martians` | `1` |
| `net.ipv4.conf.all.rp_filter` | `2` (loose reverse-path filtering) |

Before saving, discover interface names with `ip -br link` and substitute the selected interface for `INTERFACE` in every interface-specific line and validation command. Remove interface-specific lines for interfaces that do not exist. If `sysctl --system` reports an unsupported key or unexpected routing impact, restore the backup of `/etc/sysctl.d/99-hardening.conf`, reload with `sudo sysctl --system`, and verify runtime values. Interface-specific values can differ from `all` and `default`; verify the actual interface's effective values.

Check persistence in the configuration file as well as the live values:

```bash
sudo grep -nEv '^\s*(#|$)' /etc/sysctl.d/99-hardening.conf
```

After a reboot, repeat the `sysctl` verification command. Do not set `kernel.modules_disabled=1` casually; it prevents loading additional kernel modules until reboot. Do not change `rp_filter` to strict mode without validating the VPS routing design.

---

# 13. Install Fail2ban

**Objective:** Automatically detect repeated SSH authentication failures, ban offending IP addresses, and send email notifications.

### 13.1 Install packages

```bash
sudo apt update

sudo apt install fail2ban

```

For email notifications, we also need a working mail transport agent (MTA) or SMTP relay.

A recommended production setup is to use an authenticated SMTP relay.

### 13.2 Verify Fail2ban installation

```bash
sudo fail2ban-client --version

sudo systemctl status fail2ban

```

Enable at startup:

```bash
sudo systemctl enable fail2ban

```

### 13.3 Configure Fail2ban defaults

Create:

```bash
sudo vim /etc/fail2ban/jail.local

```

**First discover the package defaults and firewall backend** (Ubuntu 26.04 Fail2ban packages commonly use nftables via `jail.d/defaults-debian.conf` — verify rather than assume):

```bash
sudo fail2ban-client --version
sudo grep -RniE '^(banaction|banaction_allports|backend|action)\s*=' /etc/fail2ban/jail.conf /etc/fail2ban/jail.d/ 2>/dev/null
sudo ls /etc/fail2ban/action.d/ | head
command -v nft >/dev/null && echo 'nftables client present'
```

Add a single consistent `/etc/fail2ban/jail.local` (replace email placeholders before saving):

```ini
[DEFAULT]

bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

# Explicit firewall backend for this host (verify against discovery above).
# On current Ubuntu Fail2ban packages this is commonly nftables.
banaction = nftables
banaction_allports = nftables[type=allports]

destemail = SECURITY_EMAIL
sender = FAIL2BAN_SENDER_EMAIL
mta = sendmail

# action_mwl = firewall ban (via banaction) + email with whois + matching log lines.
# Do NOT also add a separate sendmail-* action alongside action_mwl — that duplicates notifications.
action = %(action_mwl)s

[sshd]
enabled = true
port = 2121
filter = sshd
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
```

Replace:

- `SECURITY_EMAIL` with the actual security notification address.
- `FAIL2BAN_SENDER_EMAIL` with an appropriate sender address.

Document the selected `banaction` in the implementation checklist. If discovery shows a different required backend (for example UFW-managed hosts that intentionally use `ufw`), set `banaction` / `banaction_allports` to that backend consistently and validate ban insertion against that backend in Section 13.12.

Inspect the installed definition of `action_mwl` once:

```bash
sudo grep -n 'action_mwl' /etc/fail2ban/jail.conf
```

Confirm it expands to the firewall action plus the mail action. With `action = %(action_mwl)s`, **do not** add a second mail action in Section 13.7.

### 13.4 Configure email delivery with Postfix and Gmail SMTP

Fail2ban uses the local `sendmail` interface. Postfix can deliver messages through an authenticated SMTP relay.

Install the required packages:

```bash
sudo apt install postfix mailutils libsasl2-modules ca-certificates
```

Configure Postfix to relay through Gmail:

```bash
sudo postconf -e 'relayhost = [smtp.gmail.com]:587'
sudo postconf -e 'smtp_sasl_auth_enable = yes'
sudo postconf -e 'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd'
sudo postconf -e 'smtp_sasl_security_options = noanonymous'
sudo postconf -e 'smtp_tls_security_level = encrypt'
```

Create the SMTP credentials file:

```bash
sudo vim /etc/postfix/sasl_passwd
```

Contents (use a Gmail App Password, not the account password):

```text
[smtp.gmail.com]:587 SMTP_USERNAME:SMTP_APP_PASSWORD
```

Secure and hash the credentials, then restart Postfix:

```bash
sudo chown root:root /etc/postfix/sasl_passwd
sudo chmod 600 /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd
sudo chown root:root /etc/postfix/sasl_passwd.db
sudo chmod 600 /etc/postfix/sasl_passwd.db
sudo systemctl restart postfix
```

Keep the credentials file private. Do not include the real address or App Password in documentation, scripts, or logs.

### 13.5 Restrict Postfix to outbound-only email

For system notifications, this procedure configures Postfix as a local outbound transport through an authenticated SMTP relay (Gmail is the example). It should not accept SMTP connections from other machines. Bind its SMTP listener to loopback only:

```bash
sudo postconf -e 'inet_interfaces = loopback-only'
sudo postconf -e 'mynetworks = 127.0.0.0/8 [::1]/128'
sudo postconf -e 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination'
```

Reduce SMTP banner disclosure:

```bash
sudo postconf -e 'smtpd_banner = $myhostname ESMTP'
```

Restart Postfix:

```bash
sudo systemctl restart postfix
```

Verify that port 25 is listening only on localhost:

```bash
sudo ss -tulpn | grep ':25'
sudo postconf -n | grep -E 'inet_interfaces|mynetworks|smtpd_banner|smtpd_relay_restrictions'
```

Expected listeners are `127.0.0.1:25` and `[::1]:25`. There should be no `0.0.0.0:25` or `[::]:25` listener. Keep the relay restrictions in place; the configured `mynetworks` should trust only loopback addresses.

This setting prevents remote hosts from connecting to Postfix directly. Outbound delivery through Gmail SMTP on TCP 587 continues to work. Test delivery after applying the change:

```bash
echo "Postfix outbound-only test" | mail -s "VPS email test" SECURITY_EMAIL
```

Confirm receipt. Do not expose TCP 25 in the provider firewall.

Additional Postfix verification:

```bash
sudo systemctl is-active postfix
sudo postconf inet_interfaces mynetworks smtpd_relay_restrictions relayhost smtp_sasl_auth_enable smtp_tls_security_level smtpd_banner
sudo ss -ltnp '( sport = :25 )'
sudo postqueue -p
sudo journalctl -u postfix -n 100 --no-pager
```

Expected: Postfix is `active`; `inet_interfaces = loopback-only`; `mynetworks` contains only loopback networks; relay restrictions prevent unauthenticated external relay; relay host is `[smtp.gmail.com]:587`; SASL authentication is enabled; TLS security level is `encrypt`; port 25 listens only on `127.0.0.1` and/or `[::1]`; no messages are stuck in the queue after successful delivery. A queue entry may be normal while delivery is pending, but investigate persistent deferred messages.

A successful direct `mail` test and receipt in the destination mailbox verify end-to-end outbound delivery. A successful `postconf` output alone does not prove Gmail authentication or delivery.

**Provider restriction:** Many VPS providers block or throttle outbound TCP 25 and sometimes restrict outbound submission. This configuration uses outbound TCP **587** to Gmail. If delivery fails with connection timeouts, check the provider’s SMTP policy and ask them to allow authenticated submission to the relay host. Do not open inbound TCP 25 on the provider firewall for this outbound-only relay.

### 13.6 Test email delivery

Send a direct test message:

```bash
echo "Mail delivery test from $(hostname) at $(date)" | mail -s "Ubuntu mail test" SECURITY_EMAIL
```

Confirm receipt. This tests the SMTP transport independently of Fail2ban and unattended-upgrades.

### 13.7 Verify the effective Fail2ban action (no duplicate mail actions)

With Section 13.3’s `action = %(action_mwl)s`, the jail already combines **firewall ban + email (whois + log lines)**. Do **not** add a second `sendmail-whois-lines` (or similar) action on top of `action_mwl` — that produces duplicate notifications.

After Fail2ban is restarted (Section 13.8), inspect the effective actions:

```bash
sudo fail2ban-client get sshd actions
sudo fail2ban-client get sshd banaction 2>/dev/null || true
sudo grep -n 'action_mwl' /etc/fail2ban/jail.conf
```

Expected: the action list reflects the `action_mwl` expansion (firewall action derived from `banaction`, plus one mail action). If only a mail action appears, the firewall ban was lost — fix `action`/`banaction` before relying on Fail2ban. Validate syntax with `fail2ban-client -t`; test Postfix delivery, Fail2ban notifications, and ban/unban separately in Sections 13.6 / 13.11 / 13.12.

### 13.8 Validate Fail2ban configuration

```bash
sudo fail2ban-client -t

```

Expected:

```text
OK

```

Restart Fail2ban:

```bash
sudo systemctl restart fail2ban

```

Check:

```bash
sudo systemctl status fail2ban --no-pager

```

### 13.9 Verify SSH jail

```bash
sudo fail2ban-client status

```

Expected jail list:

```text
Jail list: sshd

```

Inspect the SSH jail:

```bash
sudo fail2ban-client status sshd

```

Check configured parameters:

```bash
sudo fail2ban-client get sshd maxretry

sudo fail2ban-client get sshd findtime

sudo fail2ban-client get sshd bantime

```

Expected:

```text
5
600
3600

```

### 13.10 Check Fail2ban logs

```bash
sudo journalctl -u fail2ban -n 100 --no-pager

```

Follow logs:

```bash
sudo journalctl -u fail2ban -f

```

### 13.11 Email notification testing

Keep the two checks distinct:

**A. Mail transport test (Postfix only)**

Use the direct email test in Section 13.6 and confirm receipt. This verifies outbound mail delivery only; it does not prove Fail2ban generated a notification.

**B. Actual Fail2ban notification test**

First confirm the `sshd` jail’s effective actions include the mail component from `action_mwl` (Section 13.7: `sudo fail2ban-client get sshd actions`). Trigger one controlled ban using the reserved TEST-NET address, then confirm the notification arrives. Do not use your own administrative IP or any real host address:

```bash
sudo fail2ban-client set sshd banip 198.51.100.25
sudo journalctl -u fail2ban -n 50 --no-pager
sudo postqueue -p
sudo fail2ban-client set sshd unbanip 198.51.100.25
sudo fail2ban-client status sshd
```

Confirm the email reaches the notification mailbox selected for this deployment and the test address is no longer banned. If no notification arrives, inspect Fail2ban and Postfix logs/queue. Treat this as proof of notification delivery only. The firewall rule insertion/removal is separately validated with its own controlled test in Section 13.12.

### 13.12 Verify Fail2ban firewall backend and ban/unban behavior

**Objective:** Independently verify that the active SSH jail action inserts and removes a firewall ban. This is separate from the Fail2ban email notification test in Section 13.11.B. Do not assume nftables is the active backend merely because it is installed.

Inspect the action and current firewall rules:

```bash
sudo fail2ban-client get sshd actions
sudo fail2ban-client status sshd
sudo grep -RniE '^(action|actionban|actionunban|banaction)' /etc/fail2ban/action.d/ /etc/fail2ban/jail.local /etc/fail2ban/jail.d/ 2>/dev/null
sudo nft list ruleset
sudo iptables -S
sudo iptables -t nat -S
```

Perform a separate controlled firewall test with the reserved TEST-NET address. Do not use an administrator or real client address:

```bash
sudo fail2ban-client set sshd banip 198.51.100.25
sudo fail2ban-client status sshd
sudo nft list ruleset
sudo iptables -S
sudo iptables -t nat -S
sudo fail2ban-client set sshd unbanip 198.51.100.25
sudo fail2ban-client status sshd
```

While the address is banned, identify the rule/chain created by the configured action and confirm it contains the test address; after unbanning, confirm it is removed. If the action is not nftables, validate its actual backend. Docker compatibility is deferred until Coolify has installed Docker and is checked in Section 25.7. Never flush or replace firewall rules as part of verification.


---

# 14. SSH logging and monitoring

**Do not edit SSH configuration in this section.** `LogLevel VERBOSE`, `MaxSessions 2`, and `TCPKeepAlive no` are set only in Section 6. Confirm they are effective:

```bash
sudo sshd -T | grep -E '^(loglevel|maxsessions|tcpkeepalive)'
```

Expected: `loglevel VERBOSE`, `maxsessions 2`, `tcpkeepalive no`. If not, fix Section 6 / precedence — do not add a second drop-in here.

Inspect authentication logs:

```bash
sudo journalctl -u ssh -n 100 --no-pager

```

Monitor failed login attempts:

```bash
sudo journalctl -u ssh | grep -i failed

```

Monitor successful logins:

```bash
sudo journalctl -u ssh | grep -i accepted

```

Monitor current SSH sessions:

```bash
who

w

ss -tnp

```

---

# 15. SSH key management

Recommended operational controls:

1. Keep private keys on the administrator's local device.
2. Protect private keys with a passphrase.
3. Never share private keys.
4. Remove unused public keys from `authorized_keys`.
5. Revoke compromised keys immediately.
6. Use separate keys for separate environments.
7. Audit authorized keys regularly.
8. Consider SSH certificates for larger environments.
9. Rotate keys according to organizational policy.

Inspect authorized keys:

```bash
cat /home/ADMIN_USER/.ssh/authorized_keys

```

Inspect key fingerprints:

```bash
ssh-keygen -lf /home/ADMIN_USER/.ssh/authorized_keys

```

---


## 15.1 Linux Audit Framework (auditd)

**Objective:** Record security-relevant system activity, including changes to identity files, SSH and security configuration, privileged command execution, scheduled tasks, kernel module operations, time changes, mount operations, and SSH key directory changes.

### 15.1.1 Install and enable auditd

```bash
sudo apt update
sudo apt install auditd
sudo systemctl enable --now auditd
```

Verify the daemon:

```bash
sudo systemctl is-enabled auditd
sudo systemctl is-active auditd
sudo auditctl -s
```

The service should be enabled and active. `No plugins found, not dispatching events` in the auditd journal is informational when no dispatcher plugins are configured; audit records are still written to `/var/log/audit/audit.log`.

### 15.1.2 Audit daemon log and storage configuration

Review the settings in the installed configuration:

```bash
sudo grep -Ev '^\s*(#|$)' /etc/audit/auditd.conf
```

Example hardening configuration. Inspect the package defaults and the installed file first; merge settings deliberately and preserve any provider-required configuration:

```ini
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 8
num_logs = 5
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
```

The target rotation is 8 MB per file with 5 files retained. The disk-space actions below are deliberately conservative: auditd can suspend auditing when critically low on space or when a disk error occurs. Monitor free space and auditd journal messages so this condition is detected and handled promptly.


#### Audit log retention capacity review

**Suggested initial baseline:** `max_log_file = 8`, `num_logs = 5`, and `max_log_file_action = ROTATE`—approximately 8 MB × 5 files (about 40 MB of rotated audit-log capacity, excluding filesystem/metadata overhead). This is a proposed starting choice, not a statement about the server’s current settings; inspect the installed configuration and available disk space before selecting it.

The following are **optional proposed alternatives** to select before implementation:

| Proposed retention | Configuration | Approximate total capacity | Considerations |
|---|---|---:|---|
| Smaller increase | `max_log_file = 40`, `num_logs = 5` | 200 MB | About 5× the 8 MB × 5 default capacity; lower disk footprint, shorter retention at high event rates |
| Larger increase | `max_log_file = 100`, `num_logs = 5` | 500 MB | About 12.5× the 8 MB × 5 default capacity; potentially longer retention, but consumes more disk space |

Actual retention time depends on audit event volume. Consider free space on the filesystem holding `/var/log/audit`, system workload, log growth, and the selected disk-full actions (`SUSPEND`) before choosing a larger size. Larger files do not replace monitoring of free disk space, audit backlog, or lost events. If a retention change is approved, update the active values, plan the required service/reboot procedure appropriate to the locked audit configuration, and verify the effective settings and rotation afterward.

Off-server audit forwarding is **optional** and is not required for this baseline; no forwarding service or additional setup is implied.

Check disk space, log files, and permissions:

```bash
sudo df -h /var/log/audit
sudo ls -lh /var/log/audit/
sudo stat -c '%U:%G %a %n' /var/log/audit /var/log/audit/audit.log
```

A possible permission target is directory ownership `root:adm` mode `750` and `audit.log` ownership `root:adm` mode `640`. These are not universal defaults: inspect package defaults and local policy before changing permissions, and validate the resulting ownership and mode.

### 15.1.3 Configure audit rules

Persistent rules live in `/etc/audit/rules.d/` and are compiled by `augenrules` into `/etc/audit/audit.rules`.

| View | Location / command | Meaning |
|---|---|---|
| Persistent source | `/etc/audit/rules.d/*.rules` | Edited by administrators; survives reboot |
| Generated | `/etc/audit/audit.rules` (via `augenrules`) | Compiled from source files |
| Currently loaded | `sudo auditctl -l` / `sudo auditctl -s` | Active kernel audit configuration |

Directory watches (for example `-w /home/ADMIN_USER/.ssh/`) are **not** comprehensive recursive monitoring; they watch the named inode for the configured permission mask.

#### Implementation sequence (follow in order)

**Step 0 — Discover and back up**

```bash
sudo auditctl -s
sudo ls -la /etc/audit/rules.d/
sudo cp -a /etc/audit/rules.d "/root/audit-rules.d.backup.$(date +%Y%m%d-%H%M%S)"
if sudo test -f /etc/audit/audit.rules; then sudo cp -a /etc/audit/audit.rules "/root/audit.rules.backup.$(date +%Y%m%d-%H%M%S)"; fi
readlink -f /usr/bin/sudo
uname -m
```

| `auditctl -s` → `enabled` | What to do |
|---|---|
| `2` (immutable) | **Do not** run `augenrules --load` or `auditctl -R`. Edit persistent files only, compile/review with `augenrules` / `augenrules --check`, then apply via **controlled reboot** (Step 5). |
| `1` (enabled, mutable) | Use Steps 1–4 below (edit → compile → load mutable → test → then lock). |
| `0` | Start/enable auditd (Section 15.1.1), then continue. |

Also inspect for a package `never,task` rule that disables task auditing; remove it only after understanding the package arrangement. Do not blind-overwrite existing rule files.

**Step 1 — Write the full persistent rule set (include `authorized_keys`; keep `-e 2` commented until after tests)**

```bash
sudo vim /etc/audit/rules.d/99-hardening.rules
```

Merge applicable rules. Confirm paths exist on this image; omit absent paths. Use the resolved sudo path from Step 0 when it differs from `/usr/bin/sudo`. This example is 64-bit (`arch=b64`); add `b32` only if required.

Include explicit `authorized_keys` watches in this **same** file now (do not defer them until after immutable lock):

```text
# Failure mode and backlog (examples — tune backlog for workload)
# -D   # only if intentionally clearing every existing rule first
-f 1
-b 8192

# Identity and privilege policy
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# SSH and security service configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config
-w /etc/audit/ -p wa -k audit_config
-w /etc/fail2ban/ -p wa -k fail2ban_config
-w /etc/systemd/system/ -p wa -k systemd_config

# SSH keys (directory watches are not full recursive coverage)
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/ADMIN_USER/.ssh/ -p wa -k ssh_keys
-w /home/ADMIN_USER/.ssh/authorized_keys -p wa -k ssh_authorized_keys
# -w /root/.ssh/authorized_keys -p wa -k ssh_authorized_keys   # only if that file exists / is maintained

# Authentication logs — add only paths that exist and are used
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/btmp -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/lastlog -p wa -k logins

# Cron (retain only directories present)
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron

# Shell / dynamic linker
-w /etc/profile -p wa -k shell_config
-w /etc/profile.d/ -p wa -k shell_config
-w /etc/bash.bashrc -p wa -k shell_config
-w /etc/ld.so.conf -p wa -k ld_config
-w /etc/ld.so.conf.d/ -p wa -k ld_config

# Privilege tools — adjust sudo path if readlink differs
-w /usr/bin/sudo -p x -k sudo_execution
-w /usr/bin/su -p x -k su_execution

# Syscalls (b64)
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time-change
-a always,exit -F arch=b64 -S mount -S umount2 -k mounts
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k modules

# IMMUTABLE LOCK — keep commented until Step 4 succeeds
# -e 2
```

Discover log paths before keeping those watches: `sudo ls -la /var/log/auth.log /var/log/faillog /var/log/lastlog /var/log/btmp /var/log/wtmp 2>/dev/null`.

```bash
sudo chown root:root /etc/audit/rules.d/99-hardening.rules
sudo chmod 640 /etc/audit/rules.d/99-hardening.rules
```

**Step 2 — Compile and review generated rules (still mutable)**

```bash
sudo augenrules
sudo augenrules --check
sudo grep -nE 'ssh_authorized_keys|-e 2|^-f |^-b ' /etc/audit/audit.rules
sudo tail -20 /etc/audit/audit.rules
```

Expected: intended watches present; `-e 2` **not** active in the generated file yet (still commented in source). Fix parser errors before loading.

**Step 3 — Load into the kernel only if not immutable**

```bash
sudo auditctl -s   # must NOT show enabled 2
sudo augenrules --load
sudo auditctl -l
sudo auditctl -s
```

`Old style watch rules are slower` is a performance warning for `-w` rules, not necessarily a load failure.

**Step 4 — Functional tests while still mutable**

Run Section 15.1.4 (and backlog check 15.1.5) **now**, before locking. If tests fail, edit the persistent file, re-run Steps 2–3, and retest. Do not enable `-e 2` until tests pass.

**Step 5 — Enable immutable mode (`-e 2` must be the final generated directive)**

1. In `/etc/audit/rules.d/99-hardening.rules`, uncomment the final line so it is exactly `-e 2` (no directives after it in any later-sorted rules file).
2. Compile and verify:

```bash
sudo augenrules
sudo augenrules --check
sudo tail -5 /etc/audit/audit.rules
```

Expected: generated file **ends** with `-e 2`.

3. Apply:

- If still mutable (`enabled 1`): `sudo augenrules --load` then `sudo auditctl -s` (expect `enabled 2`).
- If already immutable from a prior run: **reboot** in a maintenance window; do not use `--load`.

4. After lock (or after reboot), verify:

```bash
sudo auditctl -s
sudo auditctl -l | grep -E 'ssh_authorized_keys|sudo_execution'
sudo tail -5 /etc/audit/audit.rules
```

**Later rule changes:** while `enabled 2`, only edit `/etc/audit/rules.d/`, run `augenrules` + `--check`, confirm generated output, then controlled reboot. Never `augenrules --load` against an immutable kernel state.

Proceed to Section 15.1.4 if Step 4 tests were not yet completed; otherwise continue to 15.1.5–15.1.6 for health/lock confirmation.

### 15.1.4 Verify audit event capture

Test a watched configuration directory with a temporary file (do not modify a real security configuration):

```bash
sudo touch /etc/audit/.audit-test
sudo rm /etc/audit/.audit-test
sudo ausearch -k audit_config -ts recent -i
```

Test sudo execution logging:

```bash
sudo -k
sudo /usr/bin/id
sudo ausearch -k sudo_execution -ts recent -i
```

Test su execution logging. On Ubuntu the root account is often locked, so an interactive `su root` from an unprivileged shell may fail for authentication reasons unrelated to audit. Become root first, then invoke `su` without needing the root password:

```bash
sudo -i
su -s /bin/sh -c 'id' root
exit
sudo ausearch -k su_execution -ts recent -i
```

Test SSH key directory monitoring:

```bash
sudo touch /home/ADMIN_USER/.ssh/audit-test
sudo rm /home/ADMIN_USER/.ssh/audit-test
sudo ausearch -k ssh_keys -ts recent -i
```

Test the explicit `authorized_keys` watch without replacing the live key (backup first):

```bash
sudo cp -a /home/ADMIN_USER/.ssh/authorized_keys "/root/authorized_keys.audit-test.$(date +%Y%m%d-%H%M%S)"
MARKER="audit-test-$(date +%s)"
printf '# %s\n' "$MARKER" | sudo tee -a /home/ADMIN_USER/.ssh/authorized_keys >/dev/null
sudo sed -i "/^# ${MARKER}$/d" /home/ADMIN_USER/.ssh/authorized_keys
sudo ausearch -k ssh_authorized_keys -ts recent -i
```

Expected: events include the relevant key, path, process/executable, success status, and audit login identity (`auid`) where available. Distinguish `SYSCALL`/`EXECVE`/`PATH` from `CONFIG_CHANGE` records produced when rules load. Restore the `authorized_keys` backup if cleanup fails.

### 15.1.5 Audit backlog and health checks

```bash
sudo auditctl -s
sudo journalctl -u auditd --since '10 minutes ago' --no-pager
sudo df -h /var/log/audit
```

Review these audit status fields:

- `enabled`: `1` means auditing is enabled; `2` means audit configuration is immutable.
- `failure`: must match the configured failure mode. If `-f 1` was set in persistent rules, expect `1` (printk/warning). Do not claim `-f 1` is active unless it appears in the generated rules and in `auditctl -s`.
- `lost`: should remain `0`.
- `backlog`: should return to `0` after bursts of events.
- `backlog_limit`: must match the configured `-b` value when one was set. `8192` is an example requiring workload review, not a universal requirement.

A nonzero backlog immediately after loading rules may be transient; check again after it drains. Investigate any increase in `lost`, a persistently growing backlog, auditd service errors, or low disk space.

### 15.1.6 Confirm immutable lock

Immutable mode is enabled in Section 15.1.3 Step 5. This subsection is confirmation only — do not load a second conflicting rule set here.

```bash
sudo tail -5 /etc/audit/rules.d/99-hardening.rules
sudo tail -5 /etc/audit/audit.rules
sudo auditctl -s
sudo auditctl -l | wc -l
sudo systemctl is-enabled auditd
```

Expected: auditd enabled at boot; `enabled 2`; `lost 0`; backlog returning to `0`; generated rules end with `-e 2`.

`loginuid_immutable` is separate; enable only if policy requires it. After any later controlled reboot for rule changes, re-validate using Sections 15.1.3–15.1.5 and 17.9.


# 16. Configure unattended security updates and email reports

**Objective:** Install security updates automatically, send change reports through the configured mail transport, and retain administrator-controlled reboot timing.

### 16.1 Enable automatic package-list refresh and security upgrades

Install the packages:

```bash
sudo apt update
sudo apt install unattended-upgrades apt-listchanges
```

Inspect `/etc/apt/apt.conf.d/20auto-upgrades` before editing. Configure the periodic values to enable daily package-list refresh and unattended upgrades, preserving any unrelated settings:

```conf
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

Use Vim to edit the file. If it does not exist, create it. These values are day intervals; `0` disables the corresponding periodic operation.

Enable the systemd timers when the image uses them:

```bash
sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer
systemctl list-timers apt-daily.timer apt-daily-upgrade.timer --all
```

### 16.2 Configure email reporting and manual reboot policy

Use a local APT configuration drop-in rather than modifying the package-maintained `50unattended-upgrades` file. Inspect it and later-numbered drop-ins first to avoid duplicate/conflicting directives:

```bash
sudo grep -RniE 'Unattended-Upgrade::(Mail|MailReport|Automatic-Reboot)' /etc/apt/apt.conf.d/ 2>/dev/null
sudo vim /etc/apt/apt.conf.d/60-hardening-unattended-upgrades
```

Add:

```conf
Unattended-Upgrade::Mail "SECURITY_EMAIL";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Automatic-Reboot "false";
```

Replace `SECURITY_EMAIL`. Keep the automatic reboot setting explicitly `false`; security updates may install automatically, but server reboots remain manual. Do not rely on an email notification to initiate a reboot. Preserve the existing `Allowed-Origins` package policy; do not add third-party repositories to automatic upgrades without an explicit decision.

**Validation:**

```bash
systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer
systemctl list-timers apt-daily.timer apt-daily-upgrade.timer --all
sudo apt-config dump | grep -E 'APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)|Unattended-Upgrade::(Mail|MailReport|Automatic-Reboot|Allowed-Origins)'
sudo unattended-upgrade --dry-run --debug
sudo journalctl -u unattended-upgrades -n 100 --no-pager
sudo tail -n 100 /var/log/unattended-upgrades/unattended-upgrades.log
```

Check whether a reboot is pending after updates (manual reboot policy):

```bash
test -f /var/run/reboot-required && echo 'REBOOT REQUIRED' || echo 'No reboot-required flag'
test -f /var/run/reboot-required.pkgs && cat /var/run/reboot-required.pkgs
```

**Expected result:** periodic package-list refresh and unattended upgrades are enabled; both timers are scheduled where timer-based execution is used; the correct mail recipient and `MailReport "on-change"` are effective; `Automatic-Reboot` is `false`; and the dry run reports no configuration errors. No available updates may be normal. A dry run does not prove email delivery — send a direct mail transport test in Section 13.11.A and confirm receipt independently of unattended-upgrades dry-run output. If `/var/run/reboot-required` exists, plan a maintenance-window reboot; do not rely on email alone to notice it.

**Recovery:** Restore the backup of the APT configuration file/drop-in if parsing or update behavior is affected. Re-run `sudo unattended-upgrade --dry-run --debug` and inspect the unattended-upgrades logs. If the host must reboot, review update notifications, backups, service health, and the maintenance window, then reboot manually. Check for any independent reboot scheduler.

# 17. Final server hardening verification checklist

Run these checks after configuration changes and during periodic security reviews. Compare the actual output with the expected values; investigate deviations rather than assuming that a configuration file is active.

### 17.1 SSH effective configuration and service

```bash
sudo sshd -t
sudo sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|maxsessions|maxauthtries|maxstartups|loglevel|tcpkeepalive|allowtcpforwarding|allowagentforwarding|x11forwarding)'
systemctl is-enabled ssh.socket ssh.service 2>/dev/null
systemctl is-active ssh.socket ssh.service 2>/dev/null
sudo ss -ltnp | grep -E '(:22|:2121)\s'
```

Expected key values: port `2121`; root login `no`; password authentication `no`; public-key authentication `yes`; `maxsessions 2`; `loglevel VERBOSE`; `tcpkeepalive no`; forwarding disabled; listener on TCP 2121 and **not** on TCP 22. For socket-activated hosts, `ssh.socket` should be active (listening); `ssh.service` may be inactive until a connection — that is normal. For traditional service hosts, `ssh.service` should be active and `ssh.socket` should remain disabled. Do **not** require both units to be active. Also test a new login from the administrator's workstation before closing the existing session.

### 17.2 SSH account and file permissions

```bash
id ADMIN_USER
sudo stat -c '%a %U:%G %n' /etc/ssh /etc/ssh/sshd_config /etc/ssh/sshd_config.d /etc/ssh/sshd_config.d/00-ssh-hardening.conf /home/ADMIN_USER /home/ADMIN_USER/.ssh /home/ADMIN_USER/.ssh/authorized_keys
sudo stat -c '%a %U:%G %n' /etc/ssh/ssh_host_*_key
```

Compare with the permissions table in section 10. Confirm `ADMIN_USER` is in the `sudo` group and that private host keys are root-owned and not readable by ordinary users.

### 17.3 Listening services and firewall

```bash
sudo ss -tulpen
sudo ufw status verbose
```

Expected: the selected host-firewall policy is in effect; only intended services are listening. If UFW is intentionally inactive because the provider firewall is the chosen control, document that decision and validate provider rules externally. Verify the provider firewall rules in the provider control panel and perform an external port scan as described in section 12.1. Do not treat a local firewall status as proof of provider firewall correctness.

### 17.4 Sysctl runtime values and persistence

Run the complete verification command in section 12.2. Confirm the expected values and confirm the entries exist in `/etc/sysctl.d/99-hardening.conf`. Repeat the runtime check after reboot to prove persistence.

### 17.5 Fail2ban

```bash
sudo fail2ban-client -t
sudo systemctl is-active fail2ban
sudo fail2ban-client status
sudo fail2ban-client status sshd
sudo fail2ban-client get sshd actions
sudo fail2ban-client get sshd maxretry
sudo fail2ban-client get sshd findtime
sudo fail2ban-client get sshd bantime
sudo journalctl -u fail2ban -n 100 --no-pager
```

Expected: config test returns `OK`; service is active; jail list includes `sshd`; action includes the configured ban action and email notification action; expected values are maxretry `5`, findtime `600`, bantime `3600` (seconds). Verify direct mail delivery in Section 13.11.A and the actual Fail2ban notification in Section 13.11.B; the firewall ban behavior is checked separately in Section 13.12.

### 17.6 Postfix outbound mail

```bash
sudo systemctl is-active postfix
sudo postconf inet_interfaces mynetworks smtpd_relay_restrictions relayhost smtp_sasl_auth_enable smtp_tls_security_level smtpd_banner
sudo ss -ltnp '( sport = :25 )'
sudo postqueue -p
sudo journalctl -u postfix -n 100 --no-pager
```

Expected: active; loopback-only listener; relay `[smtp.gmail.com]:587`; SASL enabled; TLS `encrypt`; no public port 25 listener. Send a test email and confirm receipt in the destination mailbox.

### 17.7 Unattended upgrades

```bash
systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer
systemctl list-timers apt-daily.timer apt-daily-upgrade.timer --all
sudo apt-config dump | grep -E 'Unattended-Upgrade::(Mail|MailReport|Allowed-Origins|Automatic-Reboot)'
sudo unattended-upgrade --dry-run --debug
sudo journalctl -u unattended-upgrades -n 100 --no-pager
sudo tail -n 100 /var/log/unattended-upgrades/unattended-upgrades.log
```

Expected: timers enabled and scheduled; correct notification recipient; `MailReport` is `on-change`; dry run completes without configuration errors. A dry run with no applicable updates does not prove that a notification email was sent.

### 17.8 System update status and Lynis

Lynis is an optional assessment utility, not a required security control. Install it if selected:

```bash
sudo apt update
sudo apt install lynis
sudo lynis audit system
apt list --upgradable
```

Review the new Lynis report rather than relying only on the hardening index. Record unresolved warnings and suggestions, distinguish host-level checks from provider-managed controls, and do not apply recommendations blindly (especially kernel module locking, SysRq, and routing-related settings).

### 17.9 Auditd

```bash
sudo systemctl is-enabled auditd
sudo systemctl is-active auditd
sudo auditctl -s
sudo auditctl -l | wc -l
sudo tail -5 /etc/audit/audit.rules
sudo journalctl -u auditd -n 100 --no-pager
```

Expected: auditd enabled and active; `enabled 2`; `lost 0`; backlog returns to `0`; the intended rule set (including `ssh_authorized_keys` if selected); and the generated rules file ends with `-e 2`. Event capture must be validated while mutable (Section 15.1.4) before lock, then re-checked after Step 5 / any controlled reboot (Section 15.1.3).

### 17.10 Post-reboot verification

After a planned reboot, reconnect using SSH port 2121 and repeat Sections 17.1, 17.3–17.7, 17.9, and 17.11–17.16. If audit rules were changed under immutable mode, confirm Step 5 post-reboot checks in Section 15.1.3 (source, generated, and loaded rules; `enabled 2`). Confirm required services, runtime sysctl values, time sync, and listening sockets remain correct.

### 17.11 AppArmor

```bash
sudo aa-status
sudo systemctl is-active apparmor
sudo systemctl is-enabled apparmor
sudo journalctl -u apparmor --since '1 hour ago' --no-pager
```

Expected: AppArmor is loaded and active; profiles are enforcing as required by the deployment; review all relevant denials rather than suppressing them indiscriminately. See Section 20.

### 17.12 Service minimization

```bash
systemctl list-units --type=service --state=running --no-pager
systemctl list-unit-files --type=service --state=enabled --no-pager
systemctl list-units --type=socket --state=running --no-pager
systemctl list-unit-files --type=socket --state=enabled --no-pager
sudo ss -tulpen
```

Expected: required services remain available and no unexplained public listeners exist. See Section 21.

### 17.13 SSH account restriction

```bash
sudo sshd -t
sudo sshd -T | grep -i '^allowusers'
```

Expected: the effective allowed-user list matches the administrator account(s) intended for this host. Test a new session. See Section 22.

### 17.14 `/tmp` mount

```bash
findmnt /tmp
systemctl cat tmp.mount
```

Expected: the intended mount includes `nodev`, `nosuid`, and `noexec` if selected, without losing required mount options. Repeat after reboot. See Section 23.

### 17.15 Time synchronization

```bash
timedatectl status
systemctl is-active chrony.service 2>/dev/null
command -v chronyc >/dev/null && chronyc tracking
command -v chronyc >/dev/null && chronyc sources -v
```

Expected: system clock synchronized; Chrony active on typical fresh Ubuntu 26.04 installs (or the intentionally selected time service on upgraded hosts). Correct time underpins audit timestamps, authentication logs, certificate validity, and incident investigations.

### 17.16 Pending reboot flag

```bash
test -f /var/run/reboot-required && cat /var/run/reboot-required.pkgs || echo 'No reboot-required flag'
```

Expected: no unexpected reboot-required condition after maintenance, or a planned reboot scheduled when the flag is present.

---

# 18. Implementation checklist

Use this checklist during implementation. Every Status and Notes / validation evidence cell is intentionally blank. The administrator may use only these status values when updating it: `Not started`, `In progress`, `Verified`, `Pending`, and `Not applicable`. Mark a control `Verified` only after its validation has actually been performed and the evidence recorded.

| Implementation item | Status | Notes / validation evidence |
|---|---|---|
| Initial host assessment and backups |  |  |
| Time synchronization (Chrony / timedatectl) verified |  |  |
| sudo provider verified (`sudo-rs` / `sudo.ws`) |  |  |
| Administrative account and key-based access |  |  |
| SSH hardening and effective configuration validation |  |  |
| SSH port / socket activation model documented and migrated safely |  |  |
| Provider firewall and exposure review (IPv4 and IPv6) |  |  |
| Kernel, filesystem, and network sysctl controls |  |  |
| Fail2ban SSH jail |  |  |
| SMTP/Postfix transport and direct email test |  |  |
| Fail2ban notification test |  |  |
| Fail2ban firewall ban/unban validation |  |  |
| SSH logging and monitoring |  |  |
| Auditd installation and persistent rules (mutable load + tests) |  |  |
| Auditd immutable mode (`-e 2`) and post-lock validation |  |  |
| Explicit `authorized_keys` audit watches (same rule file, tested before lock) |  |  |
| Audit log retention choice |  |  |
| Optional off-server audit forwarding (if selected) |  |  |
| Unattended security updates and email reports |  |  |
| Automatic reboot explicitly disabled |  |  |
| Final host verification checklist |  |  |
| AppArmor inspection / enforcing mode |  |  |
| Service minimization |  |  |
| SSH `AllowUsers` restriction |  |  |
| `/tmp` hardening and persistence |  |  |
| Coolify installation and test deployment |  |  |
| Coolify instance backup + APP_KEY saved off-server |  |  |
| Coolify restoration test performed |  |  |
| Application/volume backups and restore test |  |  |
| Docker-specific review and hardening |  |  |
| Docker API TCP 2375/2376 not publicly exposed |  |  |
| Coolify + proxy + app retested after Docker changes |  |  |

# 19. Operational safety requirements

- Keep an existing administrative session open when modifying SSH; test a fresh connection before closing the old one.
- Validate with `sshd -t` before reloading and verify effective settings with `sshd -T`.
- Confirm the provider firewall permits the SSH port before changing/restarting SSH; keep the provider console or recovery mechanism available.
- Never test Fail2ban by banning your own administrative IP. Test direct mail delivery separately from Fail2ban notifications and firewall ban behavior (Sections 13.11–13.12).
- Review Fail2ban bans and logs regularly; keep OpenSSH, Ubuntu, and Fail2ban updated.
- Audit rules: test while mutable, then lock with `-e 2` (Section 15.1.3 Steps 4–5). While `enabled 2`, do not `augenrules --load`; plan rule changes for a controlled reboot and verify afterward.
- Monitor `/var/log/audit` disk usage, auditd backlog, and lost-event counters.
- Inspect the merged `tmp.mount` unit with `systemctl cat tmp.mount` before restarting it. Do not remove `/tmp` `noexec` to work around an application; invoke its interpreter or relocate the executable.
- Recheck AppArmor denials after installing/upgrading services; correct profiles rather than disabling AppArmor.
- After disabling services, rerun `ss -tulpen`; reverify reboot persistence for `/tmp`, service minimization, `AllowUsers`, sysctl, and auditd after a planned reboot.

**Intended implementation profile:** Ubuntu 26.04 LTS; OpenSSH on TCP 2121 with Ed25519 key authentication, restricted administrative users, no direct root login, and no password authentication; provider-level default-deny inbound filtering; Fail2ban with email notifications; loopback-only Postfix SMTP listener relaying outbound through an authenticated provider; automatic security updates with reporting and manual reboots; selected sysctl controls; auditd with immutable rules after implementation; AppArmor enforcement; service minimization; and `/tmp` mount restrictions where application compatibility permits. Install Coolify before Docker-specific hardening. Confirm Coolify’s current Ubuntu 26.04 support and installation requirements before deployment; its installer may provision Docker, but do not assume compatibility solely from the OS version.

---

## 20. AppArmor (Mandatory Access Control) verification and enforcement

**Objective:** Keep Ubuntu’s AppArmor mandatory access control framework enabled and ensure required service profiles are enforcing. Do not disable AppArmor to resolve an application denial.

### 20.1 Install and enable AppArmor

```bash
sudo apt update
sudo apt install apparmor apparmor-utils
sudo systemctl enable --now apparmor.service
```

If the kernel command line or provider image disables AppArmor, inspect the boot configuration and image documentation before changing it. A kernel-parameter change may require a controlled reboot; do not alter boot arguments without a recovery path.

### 20.2 Verify loaded and enforcing

```bash
sudo aa-status
sudo systemctl is-active apparmor
sudo systemctl is-enabled apparmor
cat /proc/cmdline
```

Expected: AppArmor is loaded and active; the boot configuration does not disable AppArmor. Distinguish:

- **enforce** — denials are blocked and logged (required for profiles that protect production services once tuned).
- **complain** — violations are logged but allowed (useful briefly while tuning; not a permanent production stance for sensitive profiles).
- **unconfined** — no profile applied (common for many processes; not automatically a defect).

Do **not** require every installed profile to be enforcing indiscriminately — forcing broken profiles can disable required tools. Do **not** disable AppArmor globally to resolve one application denial. Profile counts vary by image and packages.

### 20.3 Check denials affecting deployed services

```bash
sudo journalctl -k --since '1 hour ago' --no-pager | grep -i 'apparmor="DENIED"'
sudo ausearch -m AVC -ts recent 2>/dev/null
```

Review each denial. If a legitimate application requires a permission, adjust its specific profile using `aa-complain`, `aa-logprof`, and then return it to enforce mode. Do not apply blanket complain mode or disable profiles globally.

### 20.4 Example denial review: `who`

If the `who` profile emits denials such as the following, review whether they are expected for the deployment:

```text
apparmor="DENIED" operation="open" profile="who" name="/etc/passwd" ...
apparmor="DENIED" operation="open" profile="who" name="/etc/nsswitch.conf" ...
```

If `who` is not needed, use `w` or `ss -tnp` for session monitoring. If it is needed, assess and tune the profile deliberately:

```bash
sudo aa-complain /usr/bin/who
# Reproduce the denial, then:
sudo aa-logprof
sudo aa-enforce /usr/bin/who
```

**Recovery:** Restore the profile backup or undo the specific profile change if a service is impaired; return the profile to enforce mode after remediation and retest the service.

## 21. Service minimization

### 21.1 Inventory

Include enabled **socket** units as well as services — sockets often own the listen ports:

```bash
systemctl list-units --type=service --state=running --no-pager
systemctl list-unit-files --type=service --state=enabled --no-pager
systemctl list-units --type=socket --state=running --no-pager
systemctl list-unit-files --type=socket --state=enabled --no-pager
sudo ss -tulpen
snap list
```

### 21.2 Disable confirmed-unnecessary services

Review each candidate service individually and check package, hardware, cloud-agent, and application dependencies before disabling it. Do not run a blanket command. For each service selected for removal from the active set, use:

```bash
sudo systemctl disable --now SERVICE_NAME.service
```

Replace `SERVICE_NAME` with one reviewed service. Disable `snapd` only after checking `snap list` and confirming no installed or planned workload depends on snaps. Re-enable a service if it is required by the host or workload.

Never disable: `ssh`, `ssh.socket`, `auditd`, `fail2ban`, `postfix`, `chrony`, `rsyslog`, `cron`, `systemd-*`, `qemu-guest-agent`, `polkit`, `dbus`, `getty`, `networkd-*`, or `unattended-upgrades`.

### 21.3 Verify

```bash
systemctl is-active SERVICE_NAME.service
systemctl is-enabled SERVICE_NAME.service
sudo ss -tulpen
```

Repeat for each service selected for disabling. An `is-active` result of `inactive` and an `is-enabled` result of `disabled` are intended only for services confirmed unnecessary.

Expected: only the services intentionally selected for disabling are inactive/disabled; all required services remain available and the socket inventory has no unexplained public listeners.

## 22. SSH `AllowUsers` restriction

**Objective:** Limit SSH login to explicitly approved administrative accounts.

**Prerequisites:** Confirm every legitimate SSH account, automation identity, and Coolify connection account that needs access. An `AllowUsers` directive can lock out any account omitted from the list. Inspect the main file and drop-ins for existing `AllowUsers`/`AllowGroups` directives first:

```bash
sudo grep -RniE '^\s*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null
```

**Implementation:** Edit the selected hardening drop-in with Vim. Add one `AllowUsers` line listing all approved accounts, separated by spaces; replace the placeholder and do not append duplicate lines:

```sshconfig
AllowUsers ADMIN_USER
```

**Validation:**

```bash
sudo sshd -t
sudo sshd -T | grep -i '^allowusers'
sudo sshd -T -C user=ADMIN_USER,host=SERVER_HOST,addr=ADMIN_CLIENT_IP,lport=2121 | grep -iE '^(allowusers|permitrootlogin|passwordauthentication)'
```

Expected: `sshd -t` produces no output and exits successfully; the effective `allowusers` list includes exactly the intended account(s) in both the global dump and the connection-specific `-C` context. Reload only after validation:

```bash
sudo systemctl reload ssh
```

From a new client session on the selected SSH port using key authentication, confirm each required account can log in before closing the existing session. Test that an account omitted from `AllowUsers` is rejected (from a controlled non-production identity), without locking out the administrator.

**Recovery:** If a required account is denied, use the provider console or still-open administrative session to restore the backup or remove/revise the directive with Vim. Validate with `sshd -t`, reload, and test a fresh connection again.

## 23. `/tmp` hardening (`nodev`, `nosuid`, `noexec`)

**Deployment-dependent:** `nodev`, `nosuid`, and especially `noexec` can break installers or applications that execute from `/tmp`. Treat them as selected controls with compatibility testing (Section 23.4), not universal absolute requirements.

Ubuntu 26.04 commonly ships `/tmp` as `tmpfs` via the upstream `tmp.mount` unit (verify with `findmnt /tmp`). Inspect how `/tmp` is mounted before changing it. If it is managed by `tmp.mount`, use a systemd drop-in that **preserves existing options** and adds the selected restrictions; if it is configured in `/etc/fstab` or by another mechanism, adapt rather than applying both methods.

### 23.1 Inspect

```bash
systemctl cat tmp.mount
findmnt /tmp
```

Preserve required distribution-specific options from the merged `tmp.mount` unit. Do not copy option strings from another server without inspection.

### 23.2 Create drop-in

```bash
sudo mkdir -p /etc/systemd/system/tmp.mount.d
sudo vim /etc/systemd/system/tmp.mount.d/noexec.conf
```

Use this structure only after copying the complete effective options discovered in Section 23.1 and ensuring `nodev`, `nosuid`, and `noexec` are present. Replace the placeholder; do not enter it literally:

```ini
[Mount]
Options=<complete-existing-options-with-nodev,nosuid,noexec>
```

Then reload systemd and inspect the merged unit:

```bash
sudo systemctl daemon-reload
systemctl cat tmp.mount
```

Confirm the merged unit includes `noexec`.

### 23.3 Apply and verify

```bash
sudo systemctl restart tmp.mount
findmnt /tmp
```

Expected: `findmnt /tmp` shows the intended mount type and includes `nosuid`, `nodev`, and `noexec`, while preserving any required options. If restart reports that the mount is busy, investigate which processes use `/tmp`; do not force a remount without understanding the impact.

### 23.4 Functional tests

```bash
echo 'echo TEST' > /tmp/test.sh
chmod +x /tmp/test.sh
/tmp/test.sh ; echo "exit=$?"
bash /tmp/test.sh
sudo apt update
```

Expected result: direct execution is denied (exit code `126`), invoking the script through `bash` prints `TEST`, and package operations work. Record each result after running the tests.

Clean up:

```bash
rm -f /tmp/test.sh
```

### 23.5 Persistence

Repeat `findmnt /tmp` after reboot to confirm `noexec`. If an application fails when executing from `/tmp`, invoke its interpreter explicitly or relocate the executable; do not remove `noexec`.

# 24. Deployment order: install Coolify before Docker hardening

Complete and validate host-level controls in Sections 1–23 first. Then install Coolify. **Do not separately install or configure Docker beforehand.** The Coolify installer may install and configure Docker automatically. Confirm current Coolify support for Ubuntu 26.04 LTS before running it; if support is unclear, stop and consult its documentation rather than improvising Docker installation.

### 24.1 Confirm Coolify support for this Ubuntu image

**Mandatory gate:** Before installing, open the current official Coolify installation docs and confirm how Ubuntu 26.04 LTS is treated.

- Official Coolify docs have historically listed automatic installer support for Ubuntu LTS **20.04 / 22.04 / 24.04** explicitly.
- Ubuntu 26.04 LTS may work with the installer or may require Coolify’s **manual** installation path (Docker Engine 24+ installed via Docker’s official method — not snap — then Coolify).
- Community reports are not a substitute for the official support statement for your Coolify release.

If automatic install support for 26.04 is not documented for your Coolify version, stop and use the official manual method, or choose a documented OS. Do not invent a custom Docker/Coolify bootstrap.

### 24.2 Install Coolify

Use the current official installation instructions. The official self-hosted installation flow commonly uses this installer; download and inspect the script before executing if your organization requires script review:

```bash
sudo curl -fsSL https://cdn.coollabs.io/coolify/install.sh -o /root/coolify-install.sh
sudo less /root/coolify-install.sh
sudo bash /root/coolify-install.sh
```

The script is maintained upstream and can change. Verify the URL against the official Coolify documentation before execution. Do not include secrets in the command line. Remove snap-packaged Docker first if present (`snap list docker`); Coolify does not support Docker from snap.

For a self-hosted Coolify server, current official firewall guidance lists TCP `8000` (dashboard direct access), `6001` (real-time updates), `6002` (web terminal), `80` (HTTP/proxy/certificate flow), and `443` (HTTPS), plus the selected SSH port (here `2121`). Ports `8000`, `6001`, and `6002` are temporary/direct-IP access ports; restrict them to trusted sources where possible and close public access after the dashboard, real-time updates, and terminal work through the configured domain/proxy. Open `80`/`443` publicly only when the server is intended to receive public web traffic. Do not expose application/database host ports unless required. Apply the same review for IPv6.

Create the Coolify administrator promptly. Anyone who can reach the initial registration endpoint may be able to claim administrative access. Securely back up installation secrets, including `/data/coolify/source/.env` (especially `APP_KEY=`), outside the server.

### 24.3 Validate Coolify deployment before Docker hardening

1. Open the dashboard at `http://SERVER_IP:8000` if direct access is enabled, or use its configured domain.
2. Confirm the administrator account is created.
3. Verify dashboard updates and web terminal access.
4. Configure the Coolify proxy and a test application deployment.
5. Verify the test application over its intended domain/protocol and confirm only intended ports are externally reachable.
6. Confirm Docker Engine and containerd are running, then proceed to Sections 24.4 and 25.

Do not apply broad firewall, daemon, or socket-permission changes before the test deployment works. Keep provider-console recovery available.

### 24.4 Coolify backup and restoration (required)

An instance backup saves Coolify’s own database (projects, resources, settings, deployment history). It does **not** back up application data inside containers/volumes. Both are required for recoverability. Follow current official docs: [Back up Coolify](https://coolify.io/docs/core/backup-and-recovery/instance-backup) and [Restore Coolify](https://coolify.io/docs/core/backup-and-recovery/instance-restore).

**A. Save the encryption key off-server (mandatory)**

```bash
sudo grep '^APP_KEY=' /data/coolify/source/.env
```

Store the full `APP_KEY=...` line in an offline secret store. Without it, restored secrets cannot be decrypted.

**B. Create a Coolify instance (database) backup**

Prefer the dashboard: Settings → Backup → configure schedule → Back up now → confirm Executions show Success → Download a copy off-server.

Terminal alternative (verify container/user names against the running install):

```bash
sudo mkdir -p /data/backups
sudo docker exec coolify-db \
  pg_dump --format=custom --no-acl --no-owner \
  --username=coolify coolify \
  > /data/backups/coolify-db-manual-backup.dmp
test -s /data/backups/coolify-db-manual-backup.dmp && ls -lh /data/backups/coolify-db-manual-backup.dmp
```

Copy the `.dmp` off the server. Also back up `/data/coolify/source/.env` and, when relevant, `/data/coolify/ssh/keys/` and host `authorized_keys` used by Coolify.

**C. Back up application persistent data**

- Database resources: use the engine’s application-aware backup (for example `pg_dump`), not only a live filesystem copy.
- Docker volumes / storage mounts: use Coolify storage-mount backups where supported, or archive volumes with writes stopped; see Coolify storage backup docs. Dashboard storage backups create archives but may not restore from the UI — plan a manual restore procedure.
- Record environment variables, secrets, deployment configuration, domains, and proxy/TLS settings from the Coolify UI or exported configuration.

**D. Restoration test (mandatory — backup alone is not enough)**

In a maintenance window or on a disposable sibling host:

1. Restore the Coolify instance database per official restore docs (requires matching/compatible Coolify version and the saved `APP_KEY`).
2. Restore at least one application volume or database backup into a test deployment.
3. Confirm the dashboard loads, a known application responds, and secrets decrypt.

Record the restore test evidence in the Section 18 checklist. Do not mark Coolify backup complete until a restore has been tested.

# 25. Docker Engine security hardening and verification — post-Coolify

**This is intentionally the final hardening stage.** Run it only after Coolify has installed Docker and a test deployment is working. These are review and verification controls; apply changes selectively and validate Coolify builds, deployments, and networking afterward.

## 25.1 Docker service verification

```bash
sudo systemctl is-active docker
sudo systemctl is-enabled docker
sudo docker info
sudo systemctl is-active containerd
sudo systemctl is-enabled containerd
```

Expected: Docker and containerd are active and enabled.

**Docker API exposure check (mandatory):** Unauthenticated Docker API on TCP 2375 (and poorly controlled 2376) is a critical host compromise risk. Verify no unintended listeners:

```bash
sudo ss -tulpen | grep -E '(:2375|:2376)\s' || echo 'No Docker API TCP listener on 2375/2376'
sudo docker info 2>/dev/null | grep -i 'swarm\|listening'
grep -RniE 'tcp://|2375|2376|hosts?' /etc/docker/daemon.json /etc/systemd/system/docker.service.d 2>/dev/null
```

Expected: no public/unauthenticated Docker API on `0.0.0.0:2375` / `[::]:2375`. Prefer the Unix socket only unless a deliberately authenticated, firewalled TLS setup (2376) is required and documented. Re-check after any daemon.json or systemd override change.

## 25.2 Docker daemon configuration

```bash
sudo cat /etc/docker/daemon.json
```

If `/etc/docker/daemon.json` does not exist, Docker may be using its defaults or a configuration supplied by its service arguments; inspect `systemctl cat docker` and `docker info` before concluding. Never overwrite an existing daemon configuration without reviewing and backing it up.

Security requirements:

- Never expose Docker API over an unauthenticated TCP socket or unrestricted remote listener.
- Keep the Docker Unix socket restricted to authorized users and processes.
- Avoid mounting `/var/run/docker.sock` into ordinary application containers.
- Do not enable privileged mode unless explicitly required and risk-assessed.
- Keep Docker Engine and containerd updated using a method compatible with Coolify.
- Do not blindly enable user-namespace remapping, change seccomp defaults, or replace Docker firewall rules; such changes can disrupt Coolify/workloads.

If the daemon configuration needs log rotation, inspect and back up the complete file and merge—not replace—its settings. If `/etc/docker/daemon.json` exists, back it up; if it does not, create it only after confirming no alternative daemon configuration is supplied by the service:

```bash
if sudo test -f /etc/docker/daemon.json; then sudo cp -a /etc/docker/daemon.json "/root/daemon.json.bkp.$(date +%Y%m%d-%H%M%S)"; fi
sudo vim /etc/docker/daemon.json
```

A compatible `json-file` rotation example is:

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

Use only after confirming Coolify and deployed workloads support the selected driver/options. Docker daemon configuration changes require a planned Docker restart and may interrupt all containers. Validate JSON before applying (for example, `sudo python3 -m json.tool /etc/docker/daemon.json`), then restart during the maintenance window:

```bash
sudo systemctl restart docker
sudo systemctl status docker --no-pager
sudo docker info
```

Recheck Coolify, proxy, test deployment, and log behavior afterward. If a change causes a failure, restore the backup (or remove the newly created file if no prior configuration existed) and restart Docker.

## 25.3 Docker socket permissions and group

```bash
sudo stat -c '%a %U:%G %n' /var/run/docker.sock
getent group docker
```

The `docker` group effectively grants root-equivalent host control. Do not add ordinary application users or unrelated administrators to it. Do not blindly change socket permissions; Coolify may rely on the access arrangement found during inspection.

## 25.4 Container inventory, ports, and security settings

```bash
sudo docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
sudo docker ps --format '{{.Names}} {{.Ports}}'
```

Inspect security-relevant fields only when containers exist (`docker inspect` with an empty ID list fails):

```bash
ids=$(sudo docker ps -q)
if [ -n "$ids" ]; then
  sudo docker inspect $ids --format '{{.Name}} Privileged={{.HostConfig.Privileged}} ReadOnlyRootfs={{.HostConfig.ReadonlyRootfs}} User={{.Config.User}}'
  sudo docker inspect $ids --format '{{.Name}} CapAdd={{.HostConfig.CapAdd}} CapDrop={{.HostConfig.CapDrop}}'
  sudo docker inspect $ids --format '{{.Name}} Memory={{.HostConfig.Memory}} NanoCPUs={{.HostConfig.NanoCpus}}'
else
  echo 'No running containers — skip inspect (unexpected after Coolify test deploy)'
fi
```

Review containers individually where needed. Investigate unexpected published ports, privileged containers, unnecessary host filesystem/socket mounts, and root execution where an unprivileged user is supported. Do not blindly disable root execution for Coolify-managed infrastructure or application containers. Apply least privilege, capability drops, read-only root filesystems, and CPU/memory limits only where compatible and tested.

## 25.5 Docker networking and firewall inspection

```bash
sudo docker network ls
sudo docker network inspect bridge
sudo iptables -S
sudo iptables -t nat -S
sudo nft list ruleset
```

These are inspection commands. **Do not flush or replace Docker-managed firewall rules.** The provider firewall remains the primary inbound boundary because published Docker ports can interact with host-firewall filtering differently from ordinary host listeners. Preserve Coolify-created networks and proxy routes; do not rename, delete, or replace them without a migration plan. After deployments, externally verify only intended ports are reachable.

## 25.6 Docker storage and logging

```bash
sudo docker system df
sudo du -sh /var/lib/docker
sudo docker info | grep -i "Logging Driver"
sudo find /var/lib/docker/containers -name '*-json.log' -type f -exec du -h {} \;
```

Review container log sizes, filesystem free space, and the Docker data root before making storage changes:

```bash
sudo docker info | grep -E 'Docker Root Dir|Storage Driver|Logging Driver'
sudo findmnt /var/lib/docker
sudo df -h /var/lib/docker
```

Do not move Docker’s data root, prune volumes, or delete application data as a hardening shortcut. Configure log rotation only after inspecting the full daemon configuration and confirming Coolify requirements.

## 25.7 Fail2ban nftables and Docker compatibility verification

This is the **Docker compatibility check**, not a repeat of the Fail2ban email or host firewall tests. Complete the notification and firewall tests in Sections 13.11–13.12, then inspect the firewall after Coolify has deployed workloads:

```bash
sudo fail2ban-client get sshd actions
sudo fail2ban-client status sshd
sudo docker ps
sudo docker network ls
sudo iptables -S
sudo iptables -t nat -S
sudo nft list ruleset
```

Use a controlled ban of `198.51.100.25` only if needed to inspect the interaction between the active Fail2ban action and Docker-managed rules; then unban it and verify that application traffic remains reachable. This is a separate compatibility check from the email test (Section 13.11.B) and the host firewall behavior check (Section 13.12). Never flush nftables or replace Docker chains.

## 25.8 Ongoing Docker operational checks

- Review published container ports after deployments (IPv4 and IPv6).
- Review privileged mode, host mounts, Docker socket mounts, and container capabilities.
- Monitor Docker storage and container log growth.
- Keep Docker Engine and containerd updated using a method compatible with Coolify.
- After any Docker daemon or firewall-related change: retest Coolify dashboard, proxy (80/443), web terminal/realtime if used, and at least one application deployment before closing the maintenance window.
- Recheck Docker API listeners on 2375/2376, the external port scan, and `ss -tulpen` after deployments.
- Do not flush nftables/iptables to “fix” Docker networking.



---

# 26. References and version-sensitive guidance

Consult current documentation before applying settings that depend on package version, provider behavior, or Coolify release. This runbook does not assume that Ubuntu 26.04 compatibility is implied by compatibility with earlier LTS releases.

- Ubuntu 26.04 LTS summary (OpenSSH 10.2p1, Chrony default, sudo-rs): https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/
- Ubuntu Server — sudo-rs / sudo.ws: https://ubuntu.com/server/docs/reference/other-tools/sudo-rs/
- Ubuntu Server — Automatic updates: https://ubuntu.com/server/docs/how-to/software/automatic-updates/
- Ubuntu Discourse — SSH socket activation: https://discourse.ubuntu.com/t/sshd-now-uses-socket-based-activation-ubuntu-22-10-and-later/30189
- OpenSSH manuals — `sshd_config(5)`, `sshd(8)` (see `sshd -T` / `-C`)
- Fail2ban — jail action aliases (`action_`, `action_mw`, `action_mwl`) in the installed `/etc/fail2ban/jail.conf`
- Coolify — Installation: https://coolify.io/docs/get-started/installation
- Coolify — Self-hosted start: https://coolify.io/docs/start-with-self-hosted
- Coolify — Firewall: https://coolify.io/docs/core/infrastructure/servers/firewall
- Coolify — Instance backup: https://coolify.io/docs/core/backup-and-recovery/instance-backup
- Coolify — Instance restore: https://coolify.io/docs/core/backup-and-recovery/instance-restore
- Coolify — Storage mount backups: https://coolify.io/docs/core/persistent-storage/storage-mounts/backups
- Docker Engine — Daemon socket / security: https://docs.docker.com/engine/security/
- Linux Audit — `auditctl(8)` / `audit.rules(7)`: https://man7.org/linux/man-pages/man8/auditctl.8.html

Check package-local manuals (`man sshd_config`, `man sshd`, `man ssh.socket`, `man auditctl`, `man audit.rules`, `man auditd.conf`, `man unattended-upgrade`, `man chrony`) for the installed versions.
