#!/bin/bash
# =============================================================================
# 02_advanced_harden.sh — Advanced Hardening
# Covers: sysctl, auto-updates, SUID/SGID audit, auditd, AIDE, AppArmor
# Run: sudo ./02_advanced_harden.sh
# =============================================================================

set -euo pipefail

BACKUP_DIR="/root/hardening_backups/$(date +%Y%m%d_%H%M%S)"
LOG="/var/log/hardening/02_advanced.log"
REPORT="/root/hardening_backups/suid_report_$(date +%Y%m%d).txt"
mkdir -p "$(dirname "$LOG")" "$BACKUP_DIR"

log()     { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG"; }
backup()  { [[ -f "$1" ]] && cp -a "$1" "$BACKUP_DIR/" && log "Backed up $1"; }
section() { echo "" | tee -a "$LOG"; log ">>> $1"; }

[[ $EUID -ne 0 ]] && { echo "Run as root (sudo)."; exit 1; }

# =============================================================================
# 1. KERNEL HARDENING via sysctl
# =============================================================================
section "Kernel Hardening (sysctl)"

SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"
backup "$SYSCTL_CONF"

cat > "$SYSCTL_CONF" << 'EOF'
# --- Network: Anti-spoofing ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# --- Network: SYN flood protection ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# --- Network: Misc ---
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Kernel: Restrict information exposure ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3

# --- Kernel: Restrict ptrace (stops process injection) ---
kernel.yama.ptrace_scope = 1

# --- Kernel: Restrict core dumps ---
fs.suid_dumpable = 0

# --- Kernel: Address Space Layout Randomization ---
kernel.randomize_va_space = 2

# --- Filesystem ---
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

sysctl -p "$SYSCTL_CONF" | tee -a "$LOG"
log "sysctl hardening applied."

# =============================================================================
# 2. AUTOMATIC SECURITY UPDATES
# =============================================================================
section "Automatic Security Updates"

apt-get install -y unattended-upgrades apt-listchanges >> "$LOG" 2>&1
backup "/etc/apt/apt.conf.d/50unattended-upgrades"

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Configure what gets auto-updated (security only — no risky dist-upgrades)
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";   // never auto-reboot a server
Unattended-Upgrade::Mail "root";
EOF

systemctl enable unattended-upgrades
systemctl restart unattended-upgrades
log "Automatic security updates configured (security patches only, no auto-reboot)."

# =============================================================================
# 3. SUID / SGID AUDIT
# =============================================================================
section "SUID/SGID Audit"

log "Scanning for SUID/SGID binaries — saving to $REPORT"

echo "=== SUID/SGID Audit — $(date) ===" > "$REPORT"
echo "" >> "$REPORT"
echo "--- SUID Binaries ---" >> "$REPORT"
find / -xdev -perm -4000 -type f 2>/dev/null >> "$REPORT"
echo "" >> "$REPORT"
echo "--- SGID Binaries ---" >> "$REPORT"
find / -xdev -perm -2000 -type f 2>/dev/null >> "$REPORT"

log "SUID/SGID report written to $REPORT"
log "Review this list — any unexpected entries are potential privilege escalation vectors."

# Known-safe SUID binaries to whitelist — remove SUID from anything NOT in this list
# (we list but do not auto-remove — you review first)
KNOWN_SUID=(
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/passwd"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/newgrp"
    "/usr/bin/gpasswd"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/sbin/pppd"
    "/bin/ping"
    "/bin/mount"
    "/bin/umount"
    "/usr/bin/pkexec"
)

echo "" >> "$REPORT"
echo "--- Potentially Unexpected SUID (review manually) ---" >> "$REPORT"
while IFS= read -r bin; do
    found=false
    for known in "${KNOWN_SUID[@]}"; do
        [[ "$bin" == "$known" ]] && found=true && break
    done
    [[ "$found" == false ]] && echo "REVIEW: $bin" >> "$REPORT"
done < <(find / -xdev -perm -4000 -type f 2>/dev/null)

log "Review $REPORT for any REVIEW: entries before removing SUID bits."

# =============================================================================
# 4. AUDITD — KERNEL AUDIT SYSTEM
# =============================================================================
section "auditd Setup"

apt-get install -y auditd audispd-plugins >> "$LOG" 2>&1
backup "/etc/audit/rules.d/audit.rules"

cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Delete existing rules
-D

# Buffer size
-b 8192

# Failure mode: 1=print, 2=panic
-f 1

# --- Authentication events ---
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# --- SSH configuration changes ---
-w /etc/ssh/sshd_config -p wa -k sshd_config

# --- Login/logout events ---
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# --- Privileged command execution ---
-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged
-w /usr/bin/sudo -p x -k sudo_use
-w /bin/su -p x -k su_use

# --- Network configuration changes ---
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/hosts -p wa -k hosts_file

# --- Kernel module loading ---
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# --- File deletion by users ---
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k file_deletion

# --- Suspicious file access ---
-a always,exit -F arch=b64 -S open -F dir=/etc -F success=0 -k etc_access_fail

# --- App-specific: watch Node app and Nginx configs ---
-w /home/usman/app/ -p wa -k app_changes
-w /etc/nginx/ -p wa -k nginx_config

# Immutable (must reboot to change rules after this)
# -e 2   # uncomment to lock rules — only enable once everything is confirmed working
EOF

augenrules --load >> "$LOG" 2>&1
systemctl enable auditd
systemctl restart auditd
log "auditd configured with hardening ruleset."
auditctl -l | tee -a "$LOG"

# =============================================================================
# 5. AIDE — FILE INTEGRITY MONITORING
# =============================================================================
section "AIDE File Integrity Monitor"

apt-get install -y aide aide-common >> "$LOG" 2>&1
backup "/etc/aide/aide.conf"

# Initialize the baseline database (takes 2-5 minutes — normal)
log "Initializing AIDE baseline database — this takes a few minutes..."
aideinit >> "$LOG" 2>&1
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
log "AIDE baseline created at /var/lib/aide/aide.db"

# Schedule daily AIDE checks via cron
cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
# Daily AIDE integrity check — results go to syslog and /var/log/aide/aide.log
LOGDIR="/var/log/aide"
mkdir -p "$LOGDIR"
REPORT="$LOGDIR/aide-$(date +%Y%m%d).log"
aide --check > "$REPORT" 2>&1
if [[ $? -ne 0 ]]; then
    logger -t AIDE "INTEGRITY ALERT: Changes detected — see $REPORT"
    # Hook for alerting script (Phase 4 will flesh this out)
    echo "AIDE_ALERT|$(date)|Changes detected" >> /var/log/hardening/alerts.log
fi
EOF

chmod +x /etc/cron.daily/aide-check
log "AIDE baseline initialized and daily check scheduled."

# =============================================================================
# 6. APPARMOR VERIFICATION
# =============================================================================
section "AppArmor Verification"

apt-get install -y apparmor apparmor-utils >> "$LOG" 2>&1
systemctl enable apparmor
systemctl start apparmor

aa-status | tee -a "$LOG"

# Enable any profiles still in complain mode — move to enforce
aa-enforce /etc/apparmor.d/usr.sbin.nginx 2>/dev/null || true
aa-enforce /etc/apparmor.d/usr.bin.node  2>/dev/null || true

log "AppArmor verified. Any profiles in complain mode are logged above."

section "Phase 2 Complete"
log "Backups: $BACKUP_DIR | SUID Report: $REPORT | Log: $LOG"
