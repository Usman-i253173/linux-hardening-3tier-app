#!/bin/bash
# =============================================================================
# 04_alerting.sh — Alerting Setup
# Sets up a structured alerting layer across all hardening components:
#   - Auth failure alerts (from /var/log/auth.log)
#   - fail2ban ban events
#   - auditd critical rule triggers
#   - AIDE integrity alerts
#   - App-level (Nginx 4xx/5xx spikes)
#
# Alerts write to /var/log/hardening/alerts.log (structured, grep-friendly)
# Optional: email alerts via local mail (configure SMTP separately if needed)
#
# Run: sudo ./04_alerting.sh
# =============================================================================

set -euo pipefail

LOG="/var/log/hardening/04_alerting.log"
ALERT_LOG="/var/log/hardening/alerts.log"
ALERT_SCRIPT="/usr/local/bin/check_alerts.sh"
ALERT_DASHBOARD="/usr/local/bin/alert_dashboard.sh"
mkdir -p "$(dirname "$LOG")"

log()     { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG"; }
section() { echo "" | tee -a "$LOG"; log ">>> $1"; }

[[ $EUID -ne 0 ]] && { echo "Run as root (sudo)."; exit 1; }

# =============================================================================
# 1. ALERT LOG STRUCTURE
# =============================================================================
section "Setting up alert log"

touch "$ALERT_LOG"
chmod 640 "$ALERT_LOG"

# Alert format: TIMESTAMP|SEVERITY|SOURCE|MESSAGE
# SEVERITY: INFO, WARN, CRIT
log "Alert log initialized at $ALERT_LOG"
echo "$(date '+%Y-%m-%d %H:%M:%S')|INFO|SYSTEM|Alerting system initialized" >> "$ALERT_LOG"

# =============================================================================
# 2. MAIN ALERT CHECKER SCRIPT
# =============================================================================
section "Writing alert checker script"

cat > "$ALERT_SCRIPT" << 'ALERTSCRIPT'
#!/bin/bash
# check_alerts.sh — runs every 5 minutes via cron, checks all sources
# Structured output: TIMESTAMP|SEVERITY|SOURCE|MESSAGE

ALERT_LOG="/var/log/hardening/alerts.log"
STATE_DIR="/var/lib/hardening_alerts"
mkdir -p "$STATE_DIR"

alert() {
    local severity="$1"
    local source="$2"
    local message="$3"
    echo "$(date '+%Y-%m-%d %H:%M:%S')|${severity}|${source}|${message}" >> "$ALERT_LOG"
    logger -t "SECURITY_ALERT" "[${severity}] ${source}: ${message}"
}

# -----------------------------------------------------------------------
# 1. SSH brute force: more than 5 failures in the last 10 minutes
# -----------------------------------------------------------------------
SSH_FAILS=$(journalctl -u sshd --since "10 minutes ago" 2>/dev/null | \
    grep -c "Failed password\|Invalid user\|Connection closed by invalid" 2>/dev/null || echo 0)

if [[ "$SSH_FAILS" -gt 5 ]]; then
    alert "CRIT" "SSH" "${SSH_FAILS} failed login attempts in the last 10 minutes"
fi

# -----------------------------------------------------------------------
# 2. New root login or su to root
# -----------------------------------------------------------------------
ROOT_LOGINS=$(journalctl --since "5 minutes ago" 2>/dev/null | \
    grep -c "session opened for user root" 2>/dev/null || echo 0)

if [[ "$ROOT_LOGINS" -gt 0 ]]; then
    alert "WARN" "AUTH" "Root session opened — ${ROOT_LOGINS} occurrence(s)"
fi

# -----------------------------------------------------------------------
# 3. fail2ban ban events in the last 5 minutes
# -----------------------------------------------------------------------
if command -v fail2ban-client &>/dev/null; then
    BANNED=$(journalctl -u fail2ban --since "5 minutes ago" 2>/dev/null | \
        grep -c "Ban " 2>/dev/null || echo 0)
    if [[ "$BANNED" -gt 0 ]]; then
        # Get the actual IPs that were banned
        BANNED_IPS=$(journalctl -u fail2ban --since "5 minutes ago" 2>/dev/null | \
            grep "Ban " | awk '{print $NF}' | tr '\n' ',' 2>/dev/null || echo "unknown")
        alert "CRIT" "FAIL2BAN" "${BANNED} IP(s) banned: ${BANNED_IPS}"
    fi
fi

# -----------------------------------------------------------------------
# 4. auditd: sensitive file changes (sudoers, passwd, sshd_config)
# -----------------------------------------------------------------------
if command -v ausearch &>/dev/null; then
    AUDIT_HITS=$(ausearch -k identity -k sudoers -k sshd_config \
        --start "$(date -d '5 minutes ago' '+%H:%M:%S')" \
        --end "$(date '+%H:%M:%S')" 2>/dev/null | \
        grep -c "type=SYSCALL" 2>/dev/null || echo 0)
    if [[ "$AUDIT_HITS" -gt 0 ]]; then
        alert "CRIT" "AUDITD" "Sensitive file access detected: ${AUDIT_HITS} event(s) — check /var/log/audit/audit.log"
    fi
fi

# -----------------------------------------------------------------------
# 5. AIDE: check for alert flag set by daily cron job
# -----------------------------------------------------------------------
if grep -q "AIDE_ALERT" /var/log/hardening/alerts.log 2>/dev/null; then
    LAST_AIDE=$(grep "AIDE_ALERT" /var/log/hardening/alerts.log | tail -1)
    STATE_FILE="$STATE_DIR/last_aide_alert"
    if [[ ! -f "$STATE_FILE" ]] || [[ "$LAST_AIDE" != "$(cat "$STATE_FILE" 2>/dev/null)" ]]; then
        alert "CRIT" "AIDE" "File integrity change detected — check /var/log/aide/"
        echo "$LAST_AIDE" > "$STATE_FILE"
    fi
fi

# -----------------------------------------------------------------------
# 6. Nginx: spike in 4xx or 5xx errors (possible scanning/attack)
# -----------------------------------------------------------------------
if [[ -f /var/log/nginx/error.log ]]; then
    NGINX_ERRORS=$(tail -100 /var/log/nginx/error.log | \
        grep -c "$(date '+%Y/%m/%d')" 2>/dev/null || echo 0)
    if [[ "$NGINX_ERRORS" -gt 20 ]]; then
        alert "WARN" "NGINX" "${NGINX_ERRORS} Nginx errors today — possible scanning activity"
    fi
fi

# -----------------------------------------------------------------------
# 7. UFW blocked connections spike (possible port scan)
# -----------------------------------------------------------------------
UFW_BLOCKS=$(journalctl -u ufw --since "5 minutes ago" 2>/dev/null | \
    grep -c "UFW BLOCK\|UFW AUDIT" 2>/dev/null || echo 0)
if [[ "$UFW_BLOCKS" -gt 15 ]]; then
    alert "WARN" "UFW" "${UFW_BLOCKS} blocked connections in 5 minutes — possible port scan"
fi

# -----------------------------------------------------------------------
# 8. Disk space alert (full disk can disable logging — attacker trick)
# -----------------------------------------------------------------------
DISK_USE=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
if [[ "$DISK_USE" -gt 85 ]]; then
    alert "WARN" "SYSTEM" "Root partition ${DISK_USE}% full — logging may be affected"
fi

ALERTSCRIPT

chmod +x "$ALERT_SCRIPT"
log "Alert checker script written to $ALERT_SCRIPT"

# =============================================================================
# 3. ALERT DASHBOARD SCRIPT
# =============================================================================
section "Writing alert dashboard script"

cat > "$ALERT_DASHBOARD" << 'DASHBOARD'
#!/bin/bash
# alert_dashboard.sh — quick human-readable summary of recent alerts
# Usage: alert_dashboard [hours_back]   (default: 24)

ALERT_LOG="/var/log/hardening/alerts.log"
HOURS="${1:-24}"

echo ""
echo "============================================================"
echo "  SECURITY ALERT DASHBOARD — Last ${HOURS}h"
echo "  Generated: $(date)"
echo "============================================================"
echo ""

if [[ ! -f "$ALERT_LOG" ]]; then
    echo "  No alert log found at $ALERT_LOG"
    exit 0
fi

CUTOFF=$(date -d "${HOURS} hours ago" '+%Y-%m-%d %H:%M:%S')

# Filter recent alerts
RECENT=$(awk -F'|' -v cutoff="$CUTOFF" '$1 >= cutoff' "$ALERT_LOG")

if [[ -z "$RECENT" ]]; then
    echo "  No alerts in the last ${HOURS} hours."
else
    # Count by severity
    CRIT=$(echo "$RECENT" | grep -c "|CRIT|" || echo 0)
    WARN=$(echo "$RECENT" | grep -c "|WARN|" || echo 0)
    INFO=$(echo "$RECENT" | grep -c "|INFO|" || echo 0)

    echo "  CRITICAL: $CRIT  |  WARNING: $WARN  |  INFO: $INFO"
    echo ""

    if [[ "$CRIT" -gt 0 ]]; then
        echo "--- CRITICAL ---"
        echo "$RECENT" | grep "|CRIT|" | awk -F'|' '{printf "  [%s] %s: %s\n", $1, $3, $4}'
        echo ""
    fi

    if [[ "$WARN" -gt 0 ]]; then
        echo "--- WARNING ---"
        echo "$RECENT" | grep "|WARN|" | awk -F'|' '{printf "  [%s] %s: %s\n", $1, $3, $4}'
        echo ""
    fi
fi

echo "--- SERVICE STATUS ---"
for svc in sshd ufw fail2ban auditd apparmor nginx nodeapp; do
    status=$(systemctl is-active "$svc" 2>/dev/null || echo "not-found")
    printf "  %-15s %s\n" "$svc" "$status"
done

echo ""
echo "  fail2ban bans:"
fail2ban-client status sshd 2>/dev/null | grep "Banned IP" || echo "  (none or fail2ban not running)"

echo ""
echo "============================================================"
DASHBOARD

chmod +x "$ALERT_DASHBOARD"
log "Alert dashboard written to $ALERT_DASHBOARD"

# =============================================================================
# 4. SCHEDULE ALERTS VIA CRON
# =============================================================================
section "Scheduling alert checks"

# Run check_alerts.sh every 5 minutes
CRON_LINE="*/5 * * * * root $ALERT_SCRIPT >> /var/log/hardening/cron_alerts.log 2>&1"
CRON_FILE="/etc/cron.d/security-alerts"

echo "$CRON_LINE" > "$CRON_FILE"
chmod 644 "$CRON_FILE"
log "Alert check scheduled every 5 minutes via $CRON_FILE"

# =============================================================================
# 5. WIRE AUDITD ALERTS INTO THE SYSTEM
# =============================================================================
section "Configuring auditd dispatcher"

# Point auditd to run our alert script when critical keys trigger
AUDIT_DISPATCHER="/etc/audit/plugins.d/hardening-alert.conf"
cat > "$AUDIT_DISPATCHER" << 'EOF'
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
args = LOG_INFO
format = string
EOF

systemctl restart auditd 2>/dev/null || true
log "auditd dispatcher configured."

# =============================================================================
# 6. QUICK TEST
# =============================================================================
section "Running alert checker now (initial test)"

bash "$ALERT_SCRIPT"
log "Initial alert check complete."

echo ""
echo "========================================================"
echo "  ALERTING SETUP COMPLETE"
echo "========================================================"
echo ""
echo "  View live alerts:    tail -f $ALERT_LOG"
echo "  Dashboard (24h):     $ALERT_DASHBOARD"
echo "  Dashboard (1h):      $ALERT_DASHBOARD 1"
echo "  Run check manually:  $ALERT_SCRIPT"
echo ""
echo "  All hardening phases complete."
echo "  Run nmap against this machine to verify what's visible."
echo "========================================================"
log "Alerting setup complete. Log: $LOG"
