#!/bin/bash
# =============================================================================
# 01_core_harden.sh — Core Hardening: SSH, UFW, fail2ban
# Run: sudo ./01_core_harden.sh
# =============================================================================

set -euo pipefail

BACKUP_DIR="/root/hardening_backups/$(date +%Y%m%d_%H%M%S)"
LOG="/var/log/hardening/01_core.log"
mkdir -p "$(dirname "$LOG")" "$BACKUP_DIR"

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG"; }
backup() { [[ -f "$1" ]] && cp -a "$1" "$BACKUP_DIR/" && log "Backed up $1"; }
section() { echo "" | tee -a "$LOG"; log ">>> $1"; }

[[ $EUID -ne 0 ]] && { echo "Run as root (sudo)."; exit 1; }

# =============================================================================
# 1. SSH HARDENING
# =============================================================================
section "SSH Hardening"

SSHD="/etc/ssh/sshd_config"
backup "$SSHD"

declare -A SSH_SETTINGS=(
    ["PermitRootLogin"]="no"
    ["MaxAuthTries"]="3"
    ["MaxSessions"]="3"
    ["PasswordAuthentication"]="yes"     # keep yes until key auth is verified
    ["PermitEmptyPasswords"]="no"
    ["X11Forwarding"]="no"
    ["AllowTcpForwarding"]="no"
    ["ClientAliveInterval"]="300"
    ["ClientAliveCountMax"]="2"
    ["LoginGraceTime"]="30"
    ["Banner"]="/etc/ssh/banner"
    ["LogLevel"]="VERBOSE"
)

for key in "${!SSH_SETTINGS[@]}"; do
    val="${SSH_SETTINGS[$key]}"
    if grep -qE "^\s*#?\s*${key}\s+" "$SSHD"; then
        sed -i "s|^\s*#\?\s*${key}\s\+.*|${key} ${val}|" "$SSHD"
    else
        echo "${key} ${val}" >> "$SSHD"
    fi
    log "  Set ${key} = ${val}"
done

# SSH login banner
cat > /etc/ssh/banner << 'EOF'
*******************************************************************************
  AUTHORIZED ACCESS ONLY. All activity is monitored and logged.
  Unauthorized access is prohibited and will be prosecuted.
*******************************************************************************
EOF

# Validate BEFORE restart — this is the lockout prevention check
if sshd -t 2>>"$LOG"; then
    systemctl restart sshd
    log "SSH service restarted successfully."
else
    log "ERROR: sshd_config validation failed. Restoring backup."
    cp -a "$BACKUP_DIR/sshd_config" "$SSHD"
    log "Backup restored. SSH config unchanged."
    exit 1
fi

# =============================================================================
# 2. UFW FIREWALL
# =============================================================================
section "UFW Configuration"

apt-get install -y ufw >> "$LOG" 2>&1

ufw --force reset >> "$LOG" 2>&1   # start clean
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward

# Allow services
ufw allow OpenSSH
ufw allow 80/tcp     comment 'Nginx HTTP'
# ufw allow 443/tcp  comment 'Nginx HTTPS — enable when cert is set up'
# Port 3000 is intentionally NOT opened — Node binds to 127.0.0.1 only

# Rate-limit SSH to slow brute force (before fail2ban even triggers)
ufw limit ssh/tcp

ufw --force enable
log "UFW enabled. Port 3000 blocked externally — Node on localhost only."
ufw status verbose | tee -a "$LOG"

# =============================================================================
# 3. FAIL2BAN
# =============================================================================
section "fail2ban Setup"

apt-get install -y fail2ban >> "$LOG" 2>&1
backup "/etc/fail2ban/jail.local"

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime       = 1h
findtime      = 10m
maxretry      = 4
banaction     = ufw
backend       = systemd

[sshd]
enabled       = true
port          = ssh
logpath       = %(sshd_log)s
maxretry      = 3
bantime       = 2h

[nginx-http-auth]
enabled       = true
port          = http,https
logpath       = /var/log/nginx/error.log

[nginx-limit-req]
enabled       = true
port          = http,https
logpath       = /var/log/nginx/error.log
EOF

systemctl enable fail2ban
systemctl restart fail2ban
log "fail2ban configured and running."
fail2ban-client status | tee -a "$LOG"

section "Phase 1 Complete"
log "Backups stored in: $BACKUP_DIR"
log "Full log: $LOG"
