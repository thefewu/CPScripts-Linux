#!/bin/bash

# CyberPatriot Advanced Hardening Script
# Additional security measures beyond main.sh
# Includes GRUB protection, IPv6 hardening, and advanced file checks

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOGFILE="advanced_hardening_$(date +%Y%m%d_%H%M%S).log"
POINTS=0

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOGFILE"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOGFILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOGFILE"
}

score() {
    POINTS=$((POINTS + $1))
    log "${GREEN}+$1 points${NC} - $2 (Total: ${PURPLE}$POINTS${NC})"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

banner() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║            CyberPatriot Advanced Hardening               ║
║   GRUB | IPv6 | File Integrity | Additional Hardening    ║
╚══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

secure_grub() {
    log "Securing GRUB bootloader..."
    
    # Check if GRUB is installed
    if [ ! -f /etc/default/grub ]; then
        warn "GRUB not found, skipping GRUB hardening"
        return
    fi
    
    # Backup
    cp /etc/default/grub /etc/default/grub.bak
    
    # Password protect GRUB (use grub-mkpasswd-pbkdf2)
    read -p "Set GRUB password? (prevents unauthorized boot parameter changes) (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "IMPORTANT: Remember this password!"
        grub-mkpasswd-pbkdf2 | tee /root/grub_password.txt
        
        cat >> /etc/grub.d/40_custom <<EOF

# GRUB Password Protection
set superusers="root"
password_pbkdf2 root PASTE_HASH_HERE
EOF
        
        warn "Edit /etc/grub.d/40_custom and replace PASTE_HASH_HERE with the hash from /root/grub_password.txt"
        warn "Then run: update-grub"
        
        score 3 "GRUB password protection configured (manual step required)"
    fi
    
    # Disable recovery mode
    if ! grep -q "GRUB_DISABLE_RECOVERY" /etc/default/grub; then
        echo 'GRUB_DISABLE_RECOVERY="true"' >> /etc/default/grub
        update-grub >> "$LOGFILE" 2>&1
        score 2 "GRUB recovery mode disabled"
    fi
    
    # Set permissions
    chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
    chmod 600 /etc/default/grub
}

harden_ipv6() {
    log "Hardening IPv6 configuration..."
    
    read -p "Disable IPv6? (only if not required - check README first!) (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cat >> /etc/sysctl.d/99-ipv6.conf <<EOF
# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
        sysctl -p /etc/sysctl.d/99-ipv6.conf >> "$LOGFILE" 2>&1
        score 3 "IPv6 disabled"
    else
        # If keeping IPv6, harden it
        cat >> /etc/sysctl.d/99-ipv6-hardening.conf <<EOF
# IPv6 Hardening
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
        sysctl -p /etc/sysctl.d/99-ipv6-hardening.conf >> "$LOGFILE" 2>&1
        score 2 "IPv6 hardened (kept enabled)"
    fi
}

secure_tmp() {
    log "Securing /tmp partition..."
    
    # Check if /tmp is on separate partition
    if mount | grep -q "on /tmp "; then
        log "/tmp is on separate partition"
        
        # Add noexec, nodev, nosuid to /tmp in fstab
        if ! grep "on /tmp " /etc/fstab | grep -q "noexec"; then
            cp /etc/fstab /etc/fstab.bak
            sed -i '/\/tmp/ s/defaults/defaults,noexec,nodev,nosuid/' /etc/fstab
            mount -o remount /tmp
            score 3 "/tmp hardened with noexec,nodev,nosuid"
        fi
    else
        warn "/tmp is not on separate partition - consider mounting with tmpfs"
        read -p "Mount /tmp as tmpfs with security options? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if ! grep -q "tmpfs /tmp tmpfs" /etc/fstab; then
                echo "tmpfs /tmp tmpfs defaults,noexec,nodev,nosuid,size=2G 0 0" >> /etc/fstab
                mount -o remount /tmp 2>/dev/null || mount /tmp
                score 3 "/tmp mounted as tmpfs with security options"
            fi
        fi
    fi
    
    # Ensure sticky bit on /tmp
    chmod +t /tmp
}

secure_var_tmp() {
    log "Securing /var/tmp..."
    
    # /var/tmp should also be secured
    if ! mount | grep -q "on /var/tmp "; then
        # Bind mount /var/tmp to /tmp for same protections
        if ! grep -q "/var/tmp" /etc/fstab; then
            echo "/tmp /var/tmp none bind 0 0" >> /etc/fstab
            mount --bind /tmp /var/tmp
            score 2 "/var/tmp bind-mounted to /tmp"
        fi
    fi
    
    # Ensure sticky bit
    chmod +t /var/tmp
}

configure_aide() {
    log "Configuring AIDE file integrity monitoring..."
    
    if ! command -v aide &> /dev/null; then
        apt-get install -y aide aide-common >> "$LOGFILE" 2>&1
    fi
    
    # Configure AIDE
    cat >> /etc/aide/aide.conf <<EOF

# CyberPatriot Custom Rules
# Monitor critical system files
/etc/passwd$ R
/etc/shadow$ R
/etc/group$ R
/etc/gshadow$ R
/etc/sudoers$ R
/etc/ssh/sshd_config$ R
/boot/ R
/sbin/ R
/bin/ R
/usr/bin/ R
/usr/sbin/ R
EOF
    
    # Check if database exists
    if [ ! -f /var/lib/aide/aide.db ]; then
        log "Initializing AIDE database (this will take time)..."
        aideinit >> "$LOGFILE" 2>&1 &
        warn "AIDE initialization running in background"
        score 3 "AIDE configured (database initializing)"
    else
        score 2 "AIDE already configured"
    fi
}

check_core_dumps() {
    log "Disabling core dumps..."
    
    # Disable core dumps in limits.conf
    if ! grep -q "hard core" /etc/security/limits.conf; then
        echo "* hard core 0" >> /etc/security/limits.conf
        score 1 "Core dumps disabled in limits.conf"
    fi
    
    # Disable core dumps in sysctl (already done in main.sh but verify)
    if ! grep -q "fs.suid_dumpable" /etc/sysctl.d/99-cyberpatriot.conf 2>/dev/null; then
        echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-cyberpatriot.conf
        sysctl -p /etc/sysctl.d/99-cyberpatriot.conf >> "$LOGFILE" 2>&1
    fi
    
    # Disable apport (crash reporting)
    systemctl stop apport 2>/dev/null || true
    systemctl disable apport 2>/dev/null || true
    systemctl mask apport 2>/dev/null || true
    
    if [ -f /etc/default/apport ]; then
        sed -i 's/enabled=1/enabled=0/' /etc/default/apport
        score 1 "Apport crash reporting disabled"
    fi
}

secure_nfs() {
    log "Securing NFS if present..."
    
    if [ -f /etc/exports ]; then
        cp /etc/exports /etc/exports.bak
        
        # Check for insecure NFS exports
        if grep -q "no_root_squash" /etc/exports; then
            warn "Found no_root_squash in NFS exports (security risk)"
        fi
        
        if grep -q "rw" /etc/exports; then
            warn "Found read-write NFS exports - verify these are necessary"
        fi
        
        # Ensure NFS exports are restricted
        chmod 644 /etc/exports
    fi
}

configure_banners() {
    log "Configuring login banners..."
    
    BANNER_TEXT="Authorized access only. All activity may be monitored and reported."
    
    # /etc/issue (console login)
    echo "$BANNER_TEXT" > /etc/issue
    
    # /etc/issue.net (network login)
    echo "$BANNER_TEXT" > /etc/issue.net
    
    # Remove OS information from banners
    echo "" > /etc/motd
    
    score 1 "Login banners configured"
}

disable_unnecessary_protocols() {
    log "Disabling unnecessary network protocols..."
    
    # Disable uncommon protocols
    PROTOCOLS=("dccp" "sctp" "rds" "tipc")
    
    for proto in "${PROTOCOLS[@]}"; do
        echo "install $proto /bin/true" >> /etc/modprobe.d/disable-protocols.conf
    done
    
    # Disable firewire (DMA attack vector)
    echo "blacklist firewire-core" >> /etc/modprobe.d/blacklist-firewire.conf
    
    # Disable thunderbolt (DMA attack vector)
    echo "blacklist thunderbolt" >> /etc/modprobe.d/blacklist-thunderbolt.conf
    
    score 2 "Unnecessary protocols disabled"
}

configure_ctrl_alt_del() {
    log "Disabling Ctrl-Alt-Delete reboot..."
    
    systemctl mask ctrl-alt-del.target >> "$LOGFILE" 2>&1 || true
    score 1 "Ctrl-Alt-Delete reboot disabled"
}

check_default_accounts() {
    log "Checking for default/unnecessary accounts..."
    
    # List of accounts that should typically be locked or removed
    SUSPICIOUS_ACCOUNTS=("games" "news" "gopher" "ftp")
    
    for account in "${SUSPICIOUS_ACCOUNTS[@]}"; do
        if grep -q "^${account}:" /etc/passwd; then
            warn "Found account: $account - consider removing or locking"
            read -p "Lock account $account? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                passwd -l "$account" 2>/dev/null && score 1 "Locked account: $account"
            fi
        fi
    done
}

configure_auditd_advanced() {
    log "Adding advanced audit rules..."
    
    if ! command -v auditctl &> /dev/null; then
        warn "auditd not installed, skipping advanced audit rules"
        return
    fi
    
    cat >> /etc/audit/rules.d/advanced.rules <<EOF
# Advanced Audit Rules

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change

# Monitor user/group tools
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupdel -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification

# Monitor privileged commands
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor mounts
-a always,exit -F arch=b64 -S mount -S umount2 -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -S umount -S umount2 -F auid>=1000 -F auid!=4294967295 -k mounts
EOF
    
    service auditd restart >> "$LOGFILE" 2>&1
    score 2 "Advanced audit rules configured"
}

check_setuid_setgid() {
    log "Auditing SUID/SGID binaries..."
    
    # Find all SUID/SGID files
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -la {} \; > /root/suid_sgid_files.txt 2>/dev/null &
    
    # Known safe SUID binaries
    SAFE_SUID=(
        "/usr/bin/passwd"
        "/usr/bin/sudo"
        "/usr/bin/gpasswd"
        "/usr/bin/newgrp"
        "/usr/bin/chsh"
        "/usr/bin/chfn"
        "/bin/su"
        "/bin/mount"
        "/bin/umount"
        "/usr/bin/pkexec"
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
        "/usr/lib/openssh/ssh-keysign"
    )
    
    warn "SUID/SGID audit running in background - review /root/suid_sgid_files.txt"
    log "Compare against known safe SUID binaries"
}

configure_tcp_wrappers() {
    log "Configuring TCP Wrappers..."
    
    # Install if not present
    if ! dpkg -l | grep -q tcpd; then
        apt-get install -y tcpd >> "$LOGFILE" 2>&1
    fi
    
    # Default deny in hosts.deny
    if [ ! -f /etc/hosts.deny ] || ! grep -q "ALL: ALL" /etc/hosts.deny; then
        echo "ALL: ALL" >> /etc/hosts.deny
        score 1 "TCP Wrappers default deny configured"
    fi
    
    # Allow SSH in hosts.allow
    if [ ! -f /etc/hosts.allow ] || ! grep -q "sshd:" /etc/hosts.allow; then
        echo "sshd: ALL" >> /etc/hosts.allow
        log "SSH allowed in TCP Wrappers"
    fi
}

secure_at_cron() {
    log "Additional cron/at security..."
    
    # Ensure cron daemon is running but secure
    if systemctl is-active --quiet cron; then
        # Already secured in main.sh, just verify
        if [ -f /etc/cron.allow ]; then
            chmod 600 /etc/cron.allow
            chmod 600 /etc/at.allow 2>/dev/null || true
        fi
        
        # Check for suspicious cron jobs
        log "Checking for suspicious cron jobs..."
        grep -r "nc\|netcat\|/dev/tcp\|bash -i" /etc/cron* /var/spool/cron* 2>/dev/null > /root/suspicious_cron.txt || true
        if [ -s /root/suspicious_cron.txt ]; then
            error "Suspicious cron jobs found - review /root/suspicious_cron.txt"
        fi
    fi
}

check_null_passwords() {
    log "Checking for NULL passwords..."
    
    # Check /etc/shadow for null passwords
    awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null > /root/null_passwords.txt
    
    if [ -s /root/null_passwords.txt ]; then
        error "Accounts with null/locked passwords found:"
        cat /root/null_passwords.txt
        
        while read account; do
            # Skip system accounts
            if id -u "$account" &>/dev/null; then
                uid=$(id -u "$account")
                if [ $uid -ge 1000 ]; then
                    warn "User account with null password: $account"
                fi
            fi
        done < /root/null_passwords.txt
    fi
}

optimize_kernel_parameters() {
    log "Optimizing additional kernel parameters..."
    
    cat >> /etc/sysctl.d/99-cyberpatriot-extra.conf <<EOF
# Additional Kernel Hardening

# Increase inotify watchers
fs.inotify.max_user_watches = 524288

# Kernel panic timeout (reboot after panic)
kernel.panic = 10

# Restrict kernel logs to root only
kernel.dmesg_restrict = 1

# Protect against certain classes of attacks
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

# Disable magic SysRq keys
kernel.sysrq = 0

# Restrict access to kernel logs
kernel.dmesg_restrict = 1
EOF
    
    sysctl -p /etc/sysctl.d/99-cyberpatriot-extra.conf >> "$LOGFILE" 2>&1
    score 2 "Additional kernel parameters optimized"
}

main() {
    banner
    check_root
    
    log "Starting advanced hardening..."
    echo
    
    secure_grub
    harden_ipv6
    secure_tmp
    secure_var_tmp
    configure_aide
    check_core_dumps
    secure_nfs
    configure_banners
    disable_unnecessary_protocols
    configure_ctrl_alt_del
    check_default_accounts
    configure_auditd_advanced
    check_setuid_setgid
    configure_tcp_wrappers
    secure_at_cron
    check_null_passwords
    optimize_kernel_parameters
    
    echo
    log "════════════════════════════════════════════════════════"
    log "Advanced hardening complete!"
    log "Total Estimated Points: ${PURPLE}$POINTS${NC}"
    log "Log file: $LOGFILE"
    log "════════════════════════════════════════════════════════"
    echo
    warn "Review the following files:"
    echo "  - /root/suid_sgid_files.txt"
    echo "  - /root/suspicious_cron.txt (if exists)"
    echo "  - /root/null_passwords.txt (if exists)"
    echo
}

main
