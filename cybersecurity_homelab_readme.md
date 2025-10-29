# cybersecurity-homelab

> A self-hosted cybersecurity training lab using Wazuh SIEM and Sysmon telemetry

&#x20; &#x20;

---

## 📖 Overview

This project is a hands-on, realistic home SOC (Security Operations Center) lab. It simulates what a junior SOC analyst / detection engineer would work with:

- **Ubuntu Server (22.04 LTS)** running a SIEM stack based on Wazuh (All-in-One)
- **Windows endpoint(s)** sending telemetry to that SIEM using:
  - Wazuh agent (log forwarding / FIM / security events)
  - Sysmon (detailed process and network visibility)
- A real workflow for:
  - log collection
  - alerting
  - investigation
  - tuning

The goals of this lab:

- Build real SIEM skills (not just “I watched a YouTube video”)
- Practice SOC workflows like triaging alerts, investigating suspicious PowerShell, and spotting brute-force logins
- Capture all of that in a public, employer-friendly portfolio

⚠️ Everything in this repo uses **safe placeholders**:

- `<MANAGER_IP>` instead of the real server IP
- `<AGENT_NAME>` for an enrolled Windows endpoint name
- `<ADMIN_USER>` for your SSH/admin user
- No SSH keys, no Wazuh enrollment keys, no passwords are included

You can safely share this repo publicly.

---

## 🧩 Lab Components

### 1. SIEM / Core Server

- OS: **Ubuntu Server 22.04 LTS** (or 20.04 upgraded to 22.04)
- Installed stack: **Wazuh All-in-One** (manager, indexer, dashboard)
- Static IP on the LAN, referenced here generically as `<MANAGER_IP>`
- Accessible via:
  - SSH: `ssh <ADMIN_USER>@<MANAGER_IP>`
  - Web dashboard: `https://<MANAGER_IP>` (self-signed cert warning is normal)

### 2. Windows Endpoint(s)

- Runs the **Wazuh Agent** and **Sysmon**
- Forwards:
  - Windows Event Logs
  - Sysmon telemetry (process creation, network connections, registry tampering, encoded PowerShell execution, etc.)
- Appears in the Wazuh dashboard as `<AGENT_NAME>`

### 3. Workflow

1. Endpoint generates events (logons, PowerShell, suspicious behavior)
2. Agent + Sysmon forward those events to Wazuh
3. Wazuh correlates / applies rules
4. Dashboard shows alerts you can investigate like a SOC analyst

This is meant to replicate a mini enterprise SOC pipeline inside your house.

---

## 🖥️ Example Architecture

**Core Security Host**

- Ubuntu Server `22.04`
- Static IP `<MANAGER_IP>` (e.g. 192.168.X.X)
- Services:
  - Wazuh Manager (SIEM brain)
  - Elasticsearch / indexer
  - Wazuh Dashboard (Kibana-like UI)

**Windows Endpoint (**``**)**

- Has Wazuh Agent installed and enrolled
- Has Sysmon installed and logging
- Sends telemetry back to `<MANAGER_IP>`

**Data Flow**

```text
[Windows Host w/ Sysmon + Wazuh Agent]
           ↓
    Enriched Security Events
           ↓
 [Wazuh Manager + Elasticsearch on Ubuntu]
           ↓
     Analyst reviews alerts
          in Dashboard
```

For more detail, see sections below on deployment and troubleshooting.

---

## 🚀 Quick Start / How To Rebuild This Lab

### 0. Hardware & Network Prereqs

- A spare machine / old laptop to act as the SIEM server
  - Install Ubuntu Server 22.04 LTS
  - Give it a static IP on your LAN (`<MANAGER_IP>`)
- A Windows PC or VM to act as the monitored endpoint
- Both must be able to reach each other on the network

> ⚠️ Do **not** expose this lab directly to the public internet.

---

### 1. Prepare the Ubuntu Server

After installing Ubuntu Server, update packages, install basics, and configure SSH.

You can automate your baseline prep with a script like:

```bash
#!/usr/bin/env bash
# scripts/ubuntu-bootstrap.sh
set -euo pipefail

apt update && apt upgrade -y
apt install -y curl wget git vim htop unzip ca-certificates gnupg lsb-release net-tools

systemctl enable ssh
systemctl start ssh

SSHD_CONF="/etc/ssh/sshd_config"
cp "${SSHD_CONF}" "${SSHD_CONF}.bak"

# Lab posture:
# - Disable direct root SSH login
# - Allow password auth (can tighten later)
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/g' "${SSHD_CONF}"
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/g' "${SSHD_CONF}"

systemctl restart ssh
```

Run it:

```bash
sudo bash scripts/ubuntu-bootstrap.sh
```

This gets you:

- System patched
- Useful admin tools installed
- SSH running and locked down so `root` can’t login directly

> Hardening step for later: once you set up SSH keys, you can change `PasswordAuthentication yes` → `no`.

---

### 2. Configure a Static IP (Netplan)

On Ubuntu Server, you generally want a static IP so your SIEM is always reachable at the same address.

Example Netplan file (do NOT commit real IPs):

```yaml
# configs/netplan-example.yaml
network:
  version: 2
  ethernets:
    eno1:
      dhcp4: no
      addresses:
        - <MANAGER_IP>/24        # e.g. 192.168.4.10/24
      gateway4: <GATEWAY_IP>     # e.g. 192.168.4.1
      nameservers:
        addresses:
          - 1.1.1.1
          - 8.8.8.8
```

Apply with:

```bash
sudo cp configs/netplan-example.yaml /etc/netplan/00-installer-config.yaml
sudo netplan apply
```

Now your server should sit on a predictable IP `<MANAGER_IP>`.

---

### 3. Install Wazuh All-in-One on the Ubuntu Server

Wazuh offers an all-in-one installer that sets up:

- Wazuh Manager (SIEM engine)
- Elasticsearch / indexer
- Wazuh Dashboard (web UI)

Example install script:

```bash
#!/usr/bin/env bash
# scripts/install-wazuh-aio.sh
set -euo pipefail

WAZUH_INSTALLER_URL="https://packages.wazuh.com/4.8/wazuh-install.sh"
TMP="/tmp/wazuh-install.sh"

curl -sSo "${TMP}" "${WAZUH_INSTALLER_URL}"
chmod +x "${TMP}"

bash "${TMP}" -a

cat <<'EOF'
[+] Wazuh installation complete.
- Check services:
    sudo systemctl status wazuh-manager
    sudo systemctl status elasticsearch
    sudo systemctl status kibana

- Access dashboard in a browser:
    https://<MANAGER_IP>
  (Self-signed cert warning is expected in a homelab.)

- Log in with the admin credentials printed by the installer.
  DO NOT commit those credentials to source control.
EOF
```

Run it:

```bash
sudo bash scripts/install-wazuh-aio.sh
```

When it's done, open a browser on your normal workstation and hit:

```text
https://<MANAGER_IP>
```

Accept the certificate warning. Log in using the credentials the script printed.

Now you have a working SIEM dashboard.

---

### 4. Add a Windows Endpoint with Wazuh Agent

#### On the Wazuh server (Ubuntu):

Generate or extract an enrollment key for an agent.

```bash
sudo /var/ossec/bin/manage_agents
# A) Add agent
#    - Agent name: <AGENT_NAME>
#    - IP: any
#    - Confirm: y
# E) Extract key for that agent
# Copy that key
```

You’ll paste that key on the Windows side.

#### On the Windows endpoint:

Open **PowerShell as Administrator** and run a helper script similar to:

```powershell
param(
    [Parameter(Mandatory=$true)][string]$ManagerIP,
    [Parameter(Mandatory=$true)][string]$AgentName
)

Write-Host "[+] Downloading Wazuh agent MSI to $env:TEMP ..."
$msi = "$env:TEMP\wazuh-agent-latest.msi"
Invoke-WebRequest -UseBasicParsing -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.2-1.msi" -OutFile $msi

Write-Host "[+] Launching installer (GUI)..."
Write-Host "When prompted:"
Write-Host "  - Manager / Server IP   = $ManagerIP"
Write-Host "  - Agent Name            = $AgentName"
Write-Host "  - Enrollment Key        = (paste from manage_agents)"

Start-Process msiexec.exe -Verb RunAs -Wait -ArgumentList "/i `"$msi`""

Write-Host "[+] Checking Wazuh service..."
Get-Service | Where-Object { $_.Name -like 'Wazuh*' } | Format-Table -AutoSize
```

After install:

```powershell
Start-Service WazuhSvc
Get-Service WazuhSvc
```

It should show `Running`.

Back in the Wazuh dashboard → Agents: you should now see `<AGENT_NAME>`. If status is `pending`, approve it. If status is `active`, congratulations — that endpoint is now feeding logs into your SIEM.

---

### 5. Install Sysmon on Windows for Deep Telemetry

**Why Sysmon?** Sysmon gives high-signal telemetry:

- Process creation (Event ID 1)
- Network connections (Event ID 3)
- Registry modifications
- Command-line arguments (including encoded PowerShell)

**How to install Sysmon:**

1. Download Sysmon from Microsoft Sysinternals.
2. Download / create a Sysmon config. An example is below.
3. In Admin PowerShell:
   ```powershell
   cd C:\Path\To\Sysmon\
   .\Sysmon64.exe -accepteula -i C:\Path\To\sysmonconfig-export.xml
   ```
4. Confirm it's running:
   ```powershell
   Get-Service Sysmon64
   ```

Example minimal Sysmon config (`configs/sysmonconfig-export.xml`):

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">powershell</CommandLine>
      <CommandLine condition="contains">-enc</CommandLine>
      <CommandLine condition="contains">-nop</CommandLine>
      <CommandLine condition="contains">-w hidden</CommandLine>
    </ProcessCreate>

    <NetworkConnect onmatch="include">
      <Image condition="end with">powershell.exe</Image>
      <Image condition="end with">cmd.exe</Image>
    </NetworkConnect>

    <ImageLoad onmatch="exclude">
      <Image condition="contains">\\Windows\\System32\\</Image>
    </ImageLoad>
  </EventFiltering>
</Sysmon>
```

Once Sysmon is running, its events (like suspicious PowerShell) will flow into Wazuh via the agent.

---

## 🕵️ Test Your Detection Pipeline (Blue Team Rep)

Now that:

- Wazuh SIEM is up,
- Windows Agent is enrolled,
- Sysmon is logging,

…you can simulate attacker-like behavior and watch it surface as alerts.

### Suspicious PowerShell test

Run on the Windows endpoint (Admin PowerShell):

```powershell
powershell -nop -w hidden -enc SQBFAFgA
```

This mimics common attacker flags:

- `-nop` (no profile)
- `-w hidden` (run hidden)
- `-enc` (base64-encoded command)

What should happen:

1. Sysmon logs a ProcessCreate (Event ID 1) showing PowerShell and that weird command line.
2. The Wazuh agent forwards that log to `<MANAGER_IP>`.
3. Wazuh applies detection rules about suspicious PowerShell usage.
4. In the Wazuh dashboard: go to **Security Events**, filter by `<AGENT_NAME>`, and you should see the alert.

You’ve just simulated malicious behavior and observed it like a SOC analyst would.

---

## 🔄 Daily Operations / Runbook

Typical daily SOC-ish tasks for this lab:

### Check SIEM services:

```bash
sudo systemctl status wazuh-manager
sudo systemctl status elasticsearch
sudo systemctl status kibana
```

### Check disk / memory health:

```bash
df -h
free -h
```

### Reboot the SIEM box:

```bash
ssh <ADMIN_USER>@<MANAGER_IP>
sudo reboot
```

### Reconnect and confirm uptime:

```bash
ssh <ADMIN_USER>@<MANAGER_IP>
uptime
```

### Onboard a new Windows host:

1. On Ubuntu: `manage_agents` to create and extract key.
2. On Windows: install agent MSI using that key.
3. Approve the agent in the Wazuh dashboard.
4. (Optional) Install Sysmon on that host.

### Investigate brute force / failed logins:

- Look in Wazuh dashboard for events related to multiple login failures.
- Ask:
  - Which account was targeted?
  - Was there eventually a successful login after failures?
  - Was it local or remote?

### Investigate suspicious PowerShell:

- Was `powershell.exe` launched with `-enc`, `-nop`, `-w hidden`?
- Who launched it (which user)?
- What process was the parent?
- Would you escalate this if you saw it in a corporate SOC?

---

## 🛠 Troubleshooting (Real-World Things That Broke)

These are common problems you will absolutely hit in a home lab.

### “Password is wrong” on SSH even though it's right

- You might be using the wrong username.
  - On the server console, run `whoami`. Use that exact username in SSH.
- Check `/var/log/auth.log` for lines like `Failed password for <user>` or `User does not exist`:
  ```bash
  sudo tail -n 20 /var/log/auth.log
  ```
- Make sure SSH allows password auth in `/etc/ssh/sshd_config`:
  ```text
  PasswordAuthentication yes
  PermitRootLogin no
  ```
  Then:
  ```bash
  sudo systemctl restart ssh
  ```

### Can ping the SIEM server but SSH times out

- SSH might not be installed or running:
  ```bash
  sudo systemctl status ssh
  sudo apt install -y openssh-server
  sudo systemctl enable ssh
  sudo systemctl start ssh
  ```
- Firewall (`ufw`) might be blocking inbound 22:
  ```bash
  sudo ufw status  # 'inactive' means not blocking
  sudo ufw allow ssh
  ```
- Your workstation and server might not actually be on the same reachable subnet/VLAN.

### Windows agent installed but doesn't show in Wazuh

1. Check service:
   ```powershell
   Get-Service WazuhSvc
   Start-Service WazuhSvc
   ```
2. Confirm you used the correct `<MANAGER_IP>`.
3. Make sure you pasted the correct agent enrollment key from `manage_agents`.
4. In the Wazuh dashboard → Agents, approve the agent if it's pending.

### Sysmon install error: "Failed to open xml configuration"

- Usually the XML file path/ extension is wrong.
- Make sure the file is actually named: `sysmonconfig-export.xml`
- Then:
  ```powershell
  .\Sysmon64.exe -accepteula -i C:\Path\To\sysmonconfig-export.xml
  ```

### Wazuh dashboard won't load in browser

- Check services on Ubuntu:
  ```bash
  sudo systemctl status wazuh-manager
  sudo systemctl status elasticsearch
  sudo systemctl status kibana
  ```
- Browse to `https://<MANAGER_IP>`
- Click through the self-signed cert warning.

---

## 🔐 Security / Redaction Policy

This repo is intentionally safe for public viewing:

- All IPs, usernames, hostnames, and agent names are placeholders like `<MANAGER_IP>`, `<ADMIN_USER>`, `<AGENT_NAME>`.
- No enrollment keys or API keys are included.
- No passwords are stored here.
- No logs from `/var/ossec/etc/`, `/var/log/auth.log`, or the Wazuh dashboard are committed.
- `.gitignore` blocks secrets, certs, and local configs from ever being committed.

If you accidentally commit something sensitive (ex: real LAN IPs, screenshots with creds, agent keys):

1. Rotate or revoke the exposed credential ASAP.
2. Remove it from git history (rewrite or force-push a cleaned branch).
3. Update this README to note that you rotated the secret.

> Never expose your live Wazuh dashboard to the open internet unless you know exactly what you're doing (reverse proxy, auth, firewalling, etc.). Lab stays on LAN.

---

## 🔎 How This Helps in Interviews

This lab demonstrates:

- Linux server administration (Ubuntu Server install, static IP, SSH setup)
- SIEM deployment and tuning (Wazuh All-in-One)
- Windows telemetry onboarding (Wazuh Agent + Sysmon)
- Network / access troubleshooting (subnet mismatches, SSH auth, routing)
- Detection validation (PowerShell abuse, brute force login simulation)
- Incident response mindset (collecting evidence, asking “is this normal?”)

You can literally walk a hiring manager through:

1. How an alert was generated
2. Where you saw it in Wazuh
3. What it meant / how you'd escalate it
4. What you'd recommend next (lockout, reset credentials, isolate host, etc.)

This is exactly what a SOC Tier 1 / Tier 2 analyst gets asked to do.

---

## 📜 License

This project is released under the MIT License.\
See `LICENSE` for the full text.

---

## 🤝 Contributing

Contributions, suggestions, and tuning ideas are welcome.\
If you open a PR:

- Don't include real IPs, usernames, or keys.
- Use placeholders like `<MANAGER_IP>` (never your actual LAN IP).
- Update docs where relevant.

See `CONTRIBUTING.md` for more.

---

## ⚠ Disclaimer

This homelab is intentionally noisy, intentionally hackable, and intentionally *not hardened for production*.\
It is designed for education, practice, and to show operational familiarity with SIEM / SOC workflows.

Do not expose it directly to the public internet. Do not consider it a replacement for a production security monitoring program.

Happy hunting 🛡️

