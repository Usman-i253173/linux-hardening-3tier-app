#!/bin/bash
# =============================================================================
# 03_pam_harden.sh — PAM Hardening: pwquality + faillock
#
# CRITICAL SAFETY NOTICE:
# This script touches PAM — a misconfiguration locks you out of your system
# completely (we learned this the hard way). Before running this:
#   1. Open a SECOND terminal and keep it logged in as root
#   2. Test sudo works in that second terminal before closing anything
#   3. Do NOT close your current session until you have verified login works
#
# Run: sudo ./03_pam_harden.sh
# =============================================================================

set -euo pipefail

BACKUP_DIR="/root/hardening_backups/pam_$(date +%Y%m%d_%H%M%S)"
LOG="/var/log/hardening/03_pam.log"
mkdir -p "$(dirname "$LOG")" "$BACKUP_DIR"

log()     { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG"; }
backup()  { [[ -f "$1" ]] && cp -a "$1" "$BACKUP_DIR/" && log "Backed up $1"; }
section() { echo "" | tee -a "$LOG"; log ">>> $1"; }

[[ $EUID -ne 0 ]] && { echo "Run as root (sudo)."; exit 1; }

# =============================================================================
# SAFETY CHECK — refuse to run without confirmed second session
# =============================================================================
echo ""
echo "=========================================================="
echo "  PAM HARDENING — SAFETY GATE"
echo "=========================================================="
echo ""
echo "  Before proceeding, verify ALL of the following:"
echo "  1. You have a SECOND terminal open and logged in as root"
echo "  2. You have tested 'sudo whoami' in that second terminal"
echo "  3. You know your GRUB recovery procedure if needed"
echo ""
read -rp "  Type 'I UNDERSTAND' to continue: " CONFIRM

if [[ "$CONFIRM" != "I UNDERSTAND" ]]; then
    log "Safety gate not confirmed. Exiting."
    echo "Aborted. Run again when ready."
    exit 0
fi

log "Safety gate confirmed. Proceeding with PAM hardening."

# =============================================================================
# BACKUP ALL PAM FILES FIRST
# =============================================================================
section "Backing up PAM configuration"

PAM_FILES=(
    "/etc/pam.d/common-auth"
    "/etc/pam.d/common-password"
    "/etc/pam.d/common-account"
    "/etc/pam.d/common-session"
    "/etc/pam.d/login"
    "/etc/pam.d/sshd"
    "/etc/security/pwquality.conf"
    "/etc/security/faillock.conf"
)

for f in "${PAM_FILES[@]}"; do
    backup "$f"
done

log "All PAM files backed up to $BACKUP_DIR"

# =============================================================================
# 1. PASSWORD QUALITY — pam_pwquality
# =============================================================================
section "pam_pwquality — Password Quality"

apt-get install -y libpam-pwquality >> "$LOG" 2>&1
backup "/etc/security/pwquality.conf"

cat > /etc/security/pwquality.conf << 'EOF'
# Minimum password length
minlen = 12

# Require at least 1 digit
dcredit = -1

# Require at least 1 uppercase
ucredit = -1

# Require at least 1 lowercase
lcredit = -1

# Require at least 1 special character
ocredit = -1

# Reject passwords with more than 3 consecutive identical characters
maxrepeat = 3

# Reject passwords that contain the username
reject_username = 1

# Number of recent passwords to remember (prevent reuse)
remember = 5
EOF

log "pwquality.conf configured."

# Ensure pam_pwquality is in common-password — add it if not present
# We use pam-auth-update for safety (the Debian-recommended way)
PWQUALITY_MODULE="/usr/share/pam-configs/pwquality"
if [[ ! -f "$PWQUALITY_MODULE" ]]; then
    cat > "$PWQUALITY_MODULE" << 'EOF'
Name: pwquality password strength checking
Default: yes
Priority: 1024
Password-Type: Primary
Password:
    requisite                       pam_pwquality.so retry=3 authtok_type=
EOF
    pam-auth-update --package 2>>"$LOG"
    log "pam_pwquality module installed via pam-auth-update."
else
    log "pam_pwquality already registered. Skipping pam-auth-update."
fi

# =============================================================================
# 2. ACCOUNT LOCKOUT — pam_faillock
# =============================================================================
section "pam_faillock — Account Lockout"

# Configure faillock behaviour
cat > /etc/security/faillock.conf << 'EOF'
# Lock account after 5 failed attempts
deny = 5

# Lockout duration: 15 minutes
unlock_time = 900

# Also count failures for root (careful — can lock root out)
# even_deny_root = true        # uncomment if you want root lockout too
root_unlock_time = 60

# Reset failure count after 10 minutes of no failures
fail_interval = 600

# Audit lockout events
audit = true

# Log to syslog
silent = false
EOF

log "faillock.conf configured: 5 attempts → 15 min lockout."

# =============================================================================
# VERIFY PAM SYNTAX
# =============================================================================
section "PAM Syntax Verification"

# Check that pam files are parseable — pam itself has no --test flag,
# but we can at least verify they exist and are non-empty
for f in /etc/pam.d/common-auth /etc/pam.d/common-password; do
    if [[ -s "$f" ]]; then
        log "  $f — OK (non-empty)"
    else
        log "  ERROR: $f is empty! Restoring backup."
        cp -a "$BACKUP_DIR/$(basename $f)" "$f"
        exit 1
    fi
done

# =============================================================================
# VERIFY WITH A TEST (non-destructive)
# =============================================================================
section "Post-Install Verification"

log "Testing password quality module is loaded:"
grep -r "pam_pwquality" /etc/pam.d/ | tee -a "$LOG" || log "WARNING: pam_pwquality not found in pam.d — check manually"

log "Testing faillock module is active:"
grep -r "pam_faillock" /etc/pam.d/ | tee -a "$LOG" || log "WARNING: pam_faillock not found in pam.d"

log "Faillock status for current users:"
faillock | tee -a "$LOG"

section "Phase 3 Complete"
echo ""
echo "=========================================================="
echo "  NEXT STEPS — DO THIS BEFORE CLOSING ANY TERMINAL"
echo "=========================================================="
echo "  1. Open a NEW terminal and try: su - $(logname)"
echo "  2. Try: sudo whoami"
echo "  3. If both work — you're safe."
echo "  4. If login fails — use your still-open root session to"
echo "     restore backups from: $BACKUP_DIR"
echo "=========================================================="
log "Backups at $BACKUP_DIR | Log at $LOG"
