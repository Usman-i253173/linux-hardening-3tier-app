# linux-hardening-3tier-app
Hardened 3-tier web app (Nginx + Node.js) on bare-metal Ubuntu with SSH, UFW, fail2ban, auditd, AIDE, AppArmor, PAM, and a custom alerting layer — 2026 Linux security best practices.



## Hardening Applied

- **SSH** — Root login disabled, max auth tries limited, login banner, verbose logging
- **UFW Firewall** — Default deny policy, only ports 22 and 80 open, port 3000 blocked externally
- **fail2ban** — Auto-bans IPs after repeated failed SSH attempts
- **Kernel Hardening** — sysctl parameters for anti-spoofing, SYN flood protection, ASLR
- **auditd** — Kernel-level audit rules watching sensitive files (passwd, sudoers, sshd_config)
- **AIDE** — File integrity monitoring with baseline database
- **AppArmor** — 91 profiles in enforce mode
- **PAM** — Password quality enforcement via pam_pwquality, account lockout via pam_faillock
- **Auto Updates** — Unattended security updates configured
- **Alerting** — Custom alerting layer monitoring auth failures, ban events, file changes, and port scans

## Before You Run These Scripts

These scripts were written for a specific machine setup. Before running them on your own system, you need to make a few changes:

### 1. Username
The scripts use `administrator` as the username in several places. Search for it and replace it with your own username:

- In `02_advanced_harden.sh` — the auditd rule watches `/home/administrator/app/`
- In `/etc/systemd/system/nodeapp.service` — the `User=` and `WorkingDirectory=` fields

To find your username run:
```bash
whoami
```

Then replace every occurrence of `administrator` in the scripts with your username.

### 2. App Directory
The Node.js backend is expected to be at `~/app/backend/server.js`. If you put it somewhere else, update the path in:
- `nodeapp.service` — the `WorkingDirectory=` line
- `02_advanced_harden.sh` — the auditd watch rule for `app_changes`

### 3. SSH Port
The scripts keep SSH on the default port 22. If you want to change it (recommended), edit `01_core_harden.sh` and add port 2222
to the SSH settings block, and update the UFW rule from `ufw allow OpenSSH` to `ufw allow 2222/tcp`.

### 4. Apache vs Nginx conflict
If Apache2 is already installed on your machine it will occupy port 80 and Nginx won't start. Fix it with:
```bash
sudo systemctl stop apache2
sudo systemctl disable apache2
```

### 5. PAM Script Safety Warning
`03_pam_harden.sh` touches PAM configuration. A mistake here locks you out of your entire system. Before running it:
- Open a second terminal and keep it logged in
- Test `sudo whoami` in that second terminal
- Only proceed once you have confirmed it works
- The script has a safety gate built in — it will ask you to type `I UNDERSTAND` before making any changes

## Scripts

| Script | Purpose |
|---|---|
| `01_core_harden.sh` | SSH, UFW, fail2ban |
| `02_advanced_harden.sh` | sysctl, auditd, AIDE, AppArmor, auto-updates |
| `03_pam_harden.sh` | PAM password quality and account lockout |
| `04_alerting.sh` | Alerting system across all hardening layers |

Commands to run:
```bash
sudo chmod +x ------.sh
sudo ./------.sh
```


### Running Order
```bash
sudo chmod +x 01_core_harden.sh && sudo ./01_core_harden.sh
sudo chmod +x 02_advanced_harden.sh && sudo ./02_advanced_harden.sh
sudo chmod +x 03_pam_harden.sh && sudo ./03_pam_harden.sh   # read safety warning above first
sudo chmod +x 04_alerting.sh && sudo ./04_alerting.sh
```

## nmap Verification

After deployment, nmap confirms the hardening:
- Port 80 visible — Nginx and Node.js Express detected
- Port 22 visible — SSH detected
- Port 3000 not visible — Node.js bound to localhost only, firewall blocking external access

```bash
nmap -sV -p 80,22 <YOUR_IP>
nmap --script http-title -p 80 <YOUR_IP>
nmap -A <YOUR_IP>
```

## Alerting

Once the alerting script runs, use these to monitor:
```bash
tail -f /var/log/hardening/alerts.log    # live feed
alert_dashboard                           # summary of last 24 hours
alert_dashboard 1                         # last 1 hour
```

## Stack

- Ubuntu 24.04 (bare metal)
- Nginx
- Node.js + Express
- UFW + fail2ban + auditd + AIDE + AppArmor

## Author

Usman Laghari

