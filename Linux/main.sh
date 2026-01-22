#!/bin/bash

#CyberPatriot Ubuntu Hardening Script
# Fixes regex bugs, /tmp check, sudoers edits, file perms, package/service checks
# Compatible with Ubuntu 18.04, 20.04, 22.04, 24.04 and likely others

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

LOG_DIR="/root/cyberpatriot_logs"
mkdir -p "$LOG_DIR"
LOGFILE="$LOG_DIR/hardening_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/root/cyberpatriot_backup_$(date +%Y%m%d_%H%M%S)"

APPLY=false
if [[ "${1:-}" == "--apply" ]]; then
    APPLY=true
    shift || true
fi

POINTS=0
DISABLE_DESKTOP_SERVICES=false
HAS_SYSTEMD=false
HAS_SS=false
SNAP_PRESENT=false

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
    log "+$1 points - $2 (Total: ${PURPLE}$POINTS${NC})"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
        exit 1
    fi
}

capability_check() {
    log "Performing capability checks..."
    if pidof systemd &>/dev/null; then
        log "systemd: present"
        HAS_SYSTEMD=true
    else
        warn "systemd: NOT detected - service management will be limited"
        HAS_SYSTEMD=false
    fi
    if command -v ss &>/dev/null; then
        log "ss: present"
        HAS_SS=true
    else
        warn "ss: NOT found - network port checks will fall back to netstat if available"
        HAS_SS=false
    fi
    if command -v snap &>/dev/null; then
        log "snap: present"
        SNAP_PRESENT=true
    fi
    log "Destructive changes require --apply or interactive OK."
    if [ "$APPLY" = false ]; then
        warn "Destructive fixes are NOT enabled. Rerun with --apply to automatically apply them."
    else
        log "Destructive fixes ARE enabled (--apply)"
    fi
}

require_apply_or_confirm() {
    local message="$1"
    if [ "$APPLY" = true ]; then
        return 0
    fi
    echo
    warn "PROPOSED CHANGE: $message"
    echo "To perform automatically, re-run this script with --apply."
    read -p "Perform this change now interactively? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        return 0
    fi
    return 1
}

banner() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════╗
║     CyberPatriot Ubuntu Hardening Suite v4.0               ║
╚════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

create_backup() {
    log "Creating comprehensive backup at: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"

    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh; do
        if [ -e "$f" ]; then
            cp -a "$f" "$BACKUP_DIR/" 2>/dev/null || true
        fi
    done

    # Tar selected dirs to preserve permissions/metadata. Non-fatal if paths don't exist.
    tar -C / -czpf "$BACKUP_DIR/etc_selected_$(date +%Y%m%d_%H%M%S).tar.gz" \
        etc/ssh etc/pam.d etc/apt etc/systemd etc/ufw 2>/dev/null || true

    if command -v systemctl &>/dev/null; then
        systemctl list-unit-files > "$BACKUP_DIR/services.list" 2>/dev/null || true
    fi
    if command -v ufw &>/dev/null; then
        ufw status verbose > "$BACKUP_DIR/ufw_rules.txt" 2>/dev/null || true
    fi

    log "Backup created at: $BACKUP_DIR"
}

update_system() {
    log "Updating package lists and upgrading system..."
    DEBIAN_FRONTEND=noninteractive apt-get update -y >> "$LOGFILE" 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get -f install -y >> "$LOGFILE" 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" >> "$LOGFILE" 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" >> "$LOGFILE" 2>&1 || true
    apt-get autoremove -y >> "$LOGFILE" 2>&1 || true
    apt-get autoclean -y >> "$LOGFILE" 2>&1 || true
    score 5 "System updated and upgraded"
}

configure_automatic_updates() {
    log "Configuring automatic security updates..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades apt-listchanges >> "$LOGFILE" 2>&1 || true

    tmpfile=$(mktemp)
    cat > "$tmpfile" <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    mv "$tmpfile" /etc/apt/apt.conf.d/50unattended-upgrades

    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    score 3 "Automatic security updates configured"
}

secure_users() {
    log "Implementing user account security..."
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs 2>/dev/null || echo "PASS_MIN_DAYS   7" >> /etc/login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs 2>/dev/null || echo "PASS_MAX_DAYS   90" >> /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs 2>/dev/null || echo "PASS_WARN_AGE   14" >> /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN   12/' /etc/login.defs 2>/dev/null || echo "PASS_MIN_LEN   12" >> /etc/login.defs
    score 3 "Password aging & minimum length policies configured"

    mkdir -p /etc/lightdm/lightdm.conf.d
    cat > /etc/lightdm/lightdm.conf.d/50-no-guest.conf <<'EOF'
[Seat:*]
allow-guest=false
EOF
    if [ -f /etc/gdm3/custom.conf ]; then
        if ! grep -q "TimedLoginEnable" /etc/gdm3/custom.conf; then
            sed -i '/\[daemon\]/a TimedLoginEnable=false' /etc/gdm3/custom.conf || true
        fi
    fi
    score 2 "Guest login disabled where detected"

    awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null > /tmp/empty_pass.txt || true
    if [ -s /tmp/empty_pass.txt ]; then
        warn "Users with empty password found. They will be locked only if --apply is used or you confirm interactively."
        if [ "$APPLY" = true ]; then
            while read -r user; do
                passwd -l "$user" 2>/dev/null && warn "Locked user with empty password: $user" || warn "Failed locking $user"
            done < /tmp/empty_pass.txt
            score 5 "Locked users with empty passwords"
        else
            # leave file for admin review
            log "Empty-password users listed in /tmp/empty_pass.txt"
        fi
    fi

    # Lock root account
    if require_apply_or_confirm "Lock root account (passwd -l root)"; then
        passwd -l root 2>/dev/null && score 2 "Root account locked" || warn "Failed to lock root or already locked"
    else
        warn "Root locking skipped"
    fi

    # Set umask
    sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs 2>/dev/null || echo "UMASK           027" >> /etc/login.defs
    for file in /etc/profile /etc/bash.bashrc; do
        if [ -f "$file" ] && ! grep -q "umask 027" "$file"; then
            echo "umask 027" >> "$file"
        fi
    done
    score 1 "Secure umask configured"
}

configure_pam() {
    log "Configuring PAM for enhanced security..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-pwquality libpam-cracklib >> "$LOGFILE" 2>&1 || true

    # Write pwquality (modifies system auth policy)
    if require_apply_or_confirm "Enforce /etc/security/pwquality.conf (minlen, credit, etc)"; then
        cat > /etc/security/pwquality.conf <<'EOF'
# Password Quality Requirements - CyberPatriot
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 3
maxrepeat = 3
maxsequence = 3
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
EOF
        score 5 "Strong password complexity requirements configured"
    else
        warn "PAM pwquality changes skipped"
    fi

    # Account lockout (faillock or pam_tally2)
    if [ -f /usr/sbin/faillock ]; then
        if ! grep -q "pam_faillock" /etc/pam.d/common-auth 2>/dev/null; then
            if require_apply_or_confirm "Insert pam_faillock rules into /etc/pam.d/common-auth (account lockout)"; then
                sed -i '1i auth required pam_faillock.so preauth silent audit deny=5 unlock_time=1800' /etc/pam.d/common-auth || true
                sed -i '/pam_unix.so/ a auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=1800' /etc/pam.d/common-auth || true
                sed -i '/pam_permit.so/ i auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=1800' /etc/pam.d/common-auth || true
                score 3 "Account lockout configured (faillock)"
            else
                warn "PAM faillock insertion skipped"
            fi
        fi
    else
        if ! grep -q "pam_tally2" /etc/pam.d/common-auth 2>/dev/null; then
            if require_apply_or_confirm "Insert pam_tally2 rules into /etc/pam.d/common-auth (account lockout)"; then
                sed -i '1i auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=1800' /etc/pam.d/common-auth || true
                score 3 "Account lockout configured (pam_tally2)"
            else
                warn "PAM pam_tally2 insertion skipped"
            fi
        fi
    fi

    # Password history & sha512
    if ! grep -q "remember=" /etc/pam.d/common-password 2>/dev/null || ! grep -q "sha512" /etc/pam.d/common-password 2>/dev/null; then
        if require_apply_or_confirm "Add password history and sha512 to /etc/pam.d/common-password"; then
            sed -i '/pam_unix.so/ s/$/ remember=5 minlen=12 sha512/' /etc/pam.d/common-password || true
            score 3 "Password history & hashing configured"
        else
            warn "Password-history/sha512 changes skipped"
        fi
    fi
}

secure_ssh() {
    log "Hardening SSH configuration..."
    if [ ! -f /etc/ssh/sshd_config ]; then
        warn "SSH not installed, skipping SSH hardening"
        return
    fi

    cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null || true

    # Use safe regex (POSIX) for matching option lines in sshd_config
    set_ssh_config() {
        local param="$1"; local value="$2"
        if grep -qE "^[#[:space:]]*${param}[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null; then
            sed -i "s|^[#[:space:]]*${param}[[:space:]]\+.*|${param} ${value}|" /etc/ssh/sshd_config || true
        else
            echo "${param} ${value}" >> /etc/ssh/sshd_config
        fi
    }

    set_ssh_config "PermitRootLogin" "no"; score 3 "SSH root login disabled"
    set_ssh_config "PermitEmptyPasswords" "no"; score 2 "SSH empty passwords disabled"
    set_ssh_config "Protocol" "2"; score 2 "SSH Protocol 2 enforced"
    set_ssh_config "X11Forwarding" "no"; score 1 "X11 forwarding disabled"
    set_ssh_config "MaxAuthTries" "3"; score 1 "SSH max auth tries set to 3"
    set_ssh_config "LoginGraceTime" "60"
    set_ssh_config "HostbasedAuthentication" "no"
    set_ssh_config "IgnoreRhosts" "yes"
    set_ssh_config "PermitUserEnvironment" "no"
    set_ssh_config "AllowTcpForwarding" "no"
    set_ssh_config "AllowStreamLocalForwarding" "no"
    set_ssh_config "GatewayPorts" "no"
    set_ssh_config "PermitTunnel" "no"
    set_ssh_config "ClientAliveInterval" "300"
    set_ssh_config "ClientAliveCountMax" "0"; score 1 "SSH idle timeout configured (5 min)"
    set_ssh_config "MaxStartups" "10:30:60"
    set_ssh_config "MaxSessions" "10"

    sed -i '/^Ciphers /d' /etc/ssh/sshd_config 2>/dev/null || true
    sed -i '/^MACs /d' /etc/ssh/sshd_config 2>/dev/null || true
    sed -i '/^KexAlgorithms /d' /etc/ssh/sshd_config 2>/dev/null || true

    {
      echo "# Strong crypto settings"
      echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
      echo "MACs hmac-sha2-256,hmac-sha2-512,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"
      echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
    } >> /etc/ssh/sshd_config

    score 2 "Weak SSH ciphers disabled (strong crypto appended)"

    # Banner
    echo "Authorized access only. All activity may be monitored and reported." > /etc/issue.net
    set_ssh_config "Banner" "/etc/issue.net"

    # Validate config and restart
    if sshd -t 2>/dev/null; then
        if require_apply_or_confirm "Restart sshd to apply SSH hardening?"; then
            if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
                log "SSH restarted after config change"
            else
                warn "Failed to restart sshd with systemctl; try manually"
            fi
        else
            warn "SSH restart skipped; new settings will not take effect until restart"
        fi
    else
        error "sshd -t failed; restoring previous config"
        cp -a /etc/ssh/sshd_config.bak /etc/ssh/sshd_config 2>/dev/null || true
    fi
}

configure_firewall() {
    log "Configuring UFW firewall with advanced rules..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y ufw >> "$LOGFILE" 2>&1 || true

    if require_apply_or_confirm "Reset UFW to default, set deny incoming, allow outgoing, allow/limit SSH, and enable UFW"; then
        ufw --force reset >> "$LOGFILE" 2>&1 || true
        ufw default deny incoming >> "$LOGFILE" 2>&1 || true
        ufw default allow outgoing >> "$LOGFILE" 2>&1 || true
        ufw default deny routed >> "$LOGFILE" 2>&1 || true
        ufw allow 22/tcp comment 'SSH' >> "$LOGFILE" 2>&1 || true
        ufw limit 22/tcp >> "$LOGFILE" 2>&1 || true
        ufw logging medium >> "$LOGFILE" 2>&1 || true
        ufw --force enable >> "$LOGFILE" 2>&1 || true
        score 6 "Firewall configured with rate limiting"
    else
        warn "Firewall configuration skipped"
    fi

    cat > /root/add_firewall_rules.sh <<'EOF'
#!/bin/bash
# Add firewall rules for specific services
# Example: ufw allow 80/tcp comment 'HTTP'
echo "Edit this script to add service-specific firewall rules"
EOF
    chmod +x /root/add_firewall_rules.sh
}

secure_network() {
    log "Applying comprehensive network security settings (sysctl)..."
    cp -a /etc/sysctl.conf /etc/sysctl.conf.bak 2>/dev/null || true

    cat > /etc/sysctl.d/99-cyberpatriot.conf <<'EOF'
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_rfc1337 = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
EOF

    if require_apply_or_confirm "Apply kernel/network sysctl hardening (write /etc/sysctl.d/99-cyberpatriot.conf and run sysctl -p)"; then
        sysctl -p /etc/sysctl.d/99-cyberpatriot.conf >> "$LOGFILE" 2>&1 || true
        score 8 "Comprehensive network security configured"
    else
        warn "Sysctl changes skipped"
    fi
}

# Helper: check for systemd services
systemd_has_unit() {
    local svc="$1"
    if ! $HAS_SYSTEMD &>/dev/null; then
        return 1
    fi
    # get list of service unit names
    if systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -xqE "^${svc}(\.service)?$"; then
        return 0
    fi
    return 1
}

disable_unnecessary_services() {
    log "Analyzing and disabling unnecessary services..."
    CRITICAL_DISABLE=( "telnet" "rsh-server" "rlogin" "rexec" "talk" "ntalk" "tftp" )
    USUALLY_DISABLE=( "isc-dhcp-server" "isc-dhcp-server6" "slapd" "nfs-server" "rpcbind" "snmpd" )
    SITUATIONAL=( "apache2" "nginx" "mysql" "mariadb" "postgresql" "bind9" "vsftpd" "proftpd" "dovecot" "postfix" "smbd" "nmbd" )
    DESKTOP_OPTIONAL=( "avahi-daemon" "cups" "cups-browsed" "bluetooth" )

    if [ "$HAS_SYSTEMD" = false ]; then
        warn "Skipping automated service stops/enables; systemd not detected"
        return
    fi

    for service in "${CRITICAL_DISABLE[@]}"; do
        if systemd_has_unit "$service"; then
            if require_apply_or_confirm "Stop/disable/mask $service"; then
                systemctl stop "${service}.service" 2>/dev/null || systemctl stop "$service" 2>/dev/null || true
                systemctl disable "${service}.service" 2>/dev/null || systemctl disable "$service" 2>/dev/null || true
                systemctl mask "${service}.service" 2>/dev/null || systemctl mask "$service" 2>/dev/null || true
                score 3 "Disabled critical risk service: $service"
            fi
        fi
    done

    for service in "${USUALLY_DISABLE[@]}"; do
        if systemctl is-active --quiet "${service}.service" 2>/dev/null || systemctl is-enabled --quiet "${service}.service" 2>/dev/null || systemctl is-active --quiet "$service" 2>/dev/null || systemctl is-enabled --quiet "$service" 2>/dev/null; then
            if require_apply_or_confirm "Stop/disable $service"; then
                systemctl stop "${service}.service" 2>/dev/null || systemctl stop "$service" 2>/dev/null || true
                systemctl disable "${service}.service" 2>/dev/null || systemctl disable "$service" 2>/dev/null || true
                systemctl mask "${service}.service" 2>/dev/null || systemctl mask "$service" 2>/dev/null || true
                score 2 "Disabled unnecessary service: $service"
            fi
        fi
    done

    log "Services requiring manual review (situational):"
    for service in "${SITUATIONAL[@]}"; do
        if systemctl is-active --quiet "${service}.service" 2>/dev/null || systemctl is-active --quiet "$service" 2>/dev/null; then
            warn "  - $service is RUNNING - verify if required"
        fi
    done

    if [ "$DISABLE_DESKTOP_SERVICES" = "true" ]; then
        for service in "${DESKTOP_OPTIONAL[@]}"; do
            if systemctl is-active --quiet "${service}.service" 2>/dev/null || systemctl is-active --quiet "$service" 2>/dev/null; then
                if require_apply_or_confirm "Stop/disable desktop service $service"; then
                    systemctl stop "${service}.service" 2>/dev/null || systemctl stop "$service" 2>/dev/null || true
                    systemctl disable "${service}.service" 2>/dev/null || systemctl disable "$service" 2>/dev/null || true
                    systemctl mask "${service}.service" 2>/dev/null || systemctl mask "$service" 2>/dev/null || true
                    score 2 "Disabled desktop service: $service"
                fi
            fi
        done
    fi
}

configure_audit() {
    log "Installing and configuring comprehensive auditing..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y auditd audispd-plugins >> "$LOGFILE" 2>&1 || true

    tmpfile=$(mktemp)
    cat > "$tmpfile" <<'EOF'
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /var/log/auth.log -p wa -k authentication
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/netplan/ -p wa -k network
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete
-e 2
EOF
    mv "$tmpfile" /etc/audit/rules.d/cyberpatriot.rules

    systemctl restart auditd >> "$LOGFILE" 2>&1 || service auditd restart >> "$LOGFILE" 2>&1 || true
    systemctl enable auditd >> "$LOGFILE" 2>&1 || true
    score 4 "Comprehensive audit logging configured"
}

secure_cron() {
    log "Securing cron and at..."
    touch /etc/cron.allow /etc/at.allow
    chmod 600 /etc/cron.allow /etc/at.allow || true
    rm -f /etc/cron.deny /etc/at.deny || true
    echo "root" > /etc/cron.allow
    echo "root" > /etc/at.allow
    chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly 2>/dev/null || true
    score 2 "Cron and at access restricted"
}

install_security_tools() {
    log "Installing comprehensive security toolkit..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        rkhunter chkrootkit lynis fail2ban aide \
        apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra \
        libpam-tmpdir libpam-umask debsums acct sysstat \
        arpwatch net-tools >> "$LOGFILE" 2>&1 || true

    score 5 "Security tools installed"

    cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
EOF

    systemctl enable fail2ban >> "$LOGFILE" 2>&1 || true
    systemctl restart fail2ban >> "$LOGFILE" 2>&1 || true
    score 3 "Fail2ban configured and enabled"

    systemctl enable apparmor >> "$LOGFILE" 2>&1 || true
    systemctl start apparmor >> "$LOGFILE" 2>&1 || true
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true
    score 2 "AppArmor enabled and enforcing"

    log "Initializing AIDE database (background - can take long)"
    (aideinit >> "$LOGFILE" 2>&1 && log "AIDE database initialized" || warn "AIDE initialization failed") &
}

remove_prohibited_software() {
    log "Scanning for prohibited software..."
    PROHIBITED=( "john" "hydra" "nmap" "netcat" "nc" "ncat" "crack" "ophcrack" "aircrack-ng" "wireshark" "tshark" "metasploit-framework" "nikto" "kismet" )
    to_remove=()
    for pkg in "${PROHIBITED[@]}"; do
        if dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | grep -xq "$pkg"; then
            to_remove+=("$pkg")
        fi
    done

    if [ ${#to_remove[@]} -eq 0 ]; then
        log "No prohibited packages found"
    else
        log "Prohibited packages found: ${to_remove[*]}"
        if [ "$APPLY" = true ]; then
            log "Removing prohibited packages..."
            apt-get purge -y "${to_remove[@]}" >> "$LOGFILE" 2>&1 || true
            score 3 "Removed prohibited software: ${to_remove[*]}"
        else
            warn "Run with --apply to remove these packages automatically"
            rec="$LOG_DIR/recommended_remove_$(date +%Y%m%d_%H%M%S).sh"
            echo "#!/bin/bash" > "$rec"
            echo "apt-get purge -y ${to_remove[*]}" >> "$rec"
            chmod +x "$rec" || true
            log "Recommended removal script written to $rec"
        fi
    fi

    # Check for prohibited snaps
    if command -v snap &> /dev/null && [ "$SNAP_PRESENT" = true ]; then
        snap list 2>/dev/null | awk 'NR>1{print $1}' | grep -iE "(game|crack|hack|hydra|john|metasploit|wireshark)" | while read -r snapname; do
            if [ "$APPLY" = true ]; then
                snap remove "$snapname" >> "$LOGFILE" 2>&1 && score 2 "Removed prohibited snap: $snapname" || warn "Failed to remove snap: $snapname"
            else
                warn "Prohibited snap found: $snapname (run with --apply to remove)"
            fi
        done
    fi
}

secure_file_permissions() {
    log "Securing critical file permissions..."
    if require_apply_or_confirm "Change permissions on /etc/passwd, /etc/shadow, /etc/gshadow, etc (chmod/chown)"; then
        chmod 644 /etc/passwd || true
        chmod 640 /etc/shadow || true
        chmod 644 /etc/group || true
        chmod 640 /etc/gshadow || true
        chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
        chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
        chmod 644 /etc/fstab || true
        chmod 644 /etc/hosts || true
        chmod 644 /etc/host.conf || true
        chmod 644 /etc/hostname || true
        chown root:root /etc/passwd /etc/group || true
        chown root:shadow /etc/shadow /etc/gshadow || true
        chmod 600 /etc/crontab 2>/dev/null || true
        chown root:root /etc/crontab 2>/dev/null || true
        score 4 "Critical file permissions secured"
    else
        warn "File permission hardening skipped"
    fi
}

check_sudoers() {
    log "Auditing sudoers configuration..."
    cp -a /etc/sudoers /etc/sudoers.bak 2>/dev/null || true

    grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null > /root/sudoers_nopasswd.txt || true
    if [ -s /root/sudoers_nopasswd.txt ]; then
        warn "NOPASSWD entries found - review /root/sudoers_nopasswd.txt"
    fi

    # FIX - Hey Josh, Instead of appending to /etc/sudoers, create a drop-in in /etc/sudoers.d and validate with visudo
    tmp_sudo="$(mktemp)"
    cat > "$tmp_sudo" <<'EOF'
# Defaults added by cyberpatriot hardening - drop-in
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
# Note: requiretty is not reliable on Debian/Ubuntu; include only if supported
EOF
    # validate file
    if visudo -c -f "$tmp_sudo" >/dev/null 2>&1; then
        mv "$tmp_sudo" /etc/sudoers.d/99-cyberpatriot-defaults
        chmod 440 /etc/sudoers.d/99-cyberpatriot-defaults
        log "Wrote /etc/sudoers.d/99-cyberpatriot-defaults"
    else
        warn "Generated sudoers drop-in failed visudo validation; not installed"
        rm -f "$tmp_sudo"
    fi

    score 2 "Sudoers configuration audited"
}

disable_usb_storage() {
    log "Disabling USB storage (modprobe rule)..."
    if require_apply_or_confirm "Add modprobe rule to disable usb-storage and remove module"; then
        echo "install usb-storage /bin/true" > /etc/modprobe.d/disable-usb-storage.conf
        rmmod usb-storage 2>/dev/null || true
        score 2 "USB storage disabled"
    else
        warn "USB storage disabling skipped"
    fi
}

secure_shared_memory() {
    log "Securing shared memory (/run/shm)..."
    if ! grep -q "/run/shm" /etc/fstab 2>/dev/null; then
        if require_apply_or_confirm "Mount /run/shm as tmpfs with noexec,nodev,nosuid"; then
            echo "tmpfs /run/shm tmpfs defaults,noexec,nodev,nosuid,size=1G 0 0" >> /etc/fstab
            mount -o remount,noexec,nodev,nosuid /run/shm 2>/dev/null || true
            score 2 "Shared memory secured"
        else
            warn "Shared memory hardening skipped"
        fi
    fi

    # Test for a matching noexec entry specifically for /tmp
    if ! grep -qE '/tmp[^[:space:]]*.*noexec' /etc/fstab 2>/dev/null; then
        warn "Consider securing /tmp with noexec,nodev,nosuid"
    fi
}

configure_process_accounting() {
    log "Enabling process accounting if available..."
    if command -v accton &>/dev/null; then
        mkdir -p /var/log/account 2>/dev/null || true
        touch /var/log/account/pacct 2>/dev/null || true
        if require_apply_or_confirm "Enable process accounting (accton)"; then
            accton /var/log/account/pacct 2>/dev/null && score 1 "Process accounting enabled" || warn "accton failed"
        else
            warn "Process accounting skipped"
        fi
    else
        warn "acct (process accounting) not installed"
    fi
}

harden_compilers() {
    log "Restricting compiler access..."
    if require_apply_or_confirm "Restrict compiler binaries (/usr/bin/gcc*, g++, cc, as) to root/devs"; then
        chmod 750 /usr/bin/gcc* 2>/dev/null || true
        chmod 750 /usr/bin/g++* 2>/dev/null || true
        chmod 750 /usr/bin/cc 2>/dev/null || true
        chmod 750 /usr/bin/c++ 2>/dev/null || true
        chmod 750 /usr/bin/as 2>/dev/null || true
        score 1 "Compiler access restricted"
    else
        warn "Compiler restriction skipped"
    fi
}

remove_unnecessary_packages() {
    log "Removing unnecessary packages..."
    UNNECESSARY=( "xinetd" "nis" "yp-tools" "tftpd" "atftpd" "finger" "whoopsie" )
    for pkg in "${UNNECESSARY[@]}"; do
        if dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | grep -xq "$pkg"; then
            if require_apply_or_confirm "Purge $pkg"; then
                apt-get purge -y "$pkg" >> "$LOGFILE" 2>&1 || true
                score 1 "Removed unnecessary package: $pkg"
            fi
        fi
    done
}

check_worldwritable() {
    log "Scanning for world-writable files (background)..."
    (find / -xdev -type f -perm -0002 -ls 2>/dev/null > /root/world_writable_files.txt && log "World-writable files scan complete") &
    (find / -xdev -type d -perm -0002 ! -perm -1000 -ls 2>/dev/null > /root/world_writable_dirs_no_sticky.txt && log "World-writable directories scan complete") &
    warn "World-writable scans started in background"
}

configure_login_defs() {
    log "Hardening login.defs..."
    sed -i 's/^LOG_OK_LOGINS.*/LOG_OK_LOGINS   yes/' /etc/login.defs 2>/dev/null || echo "LOG_OK_LOGINS   yes" >> /etc/login.defs
    sed -i 's/^FAILLOG_ENAB.*/FAILLOG_ENAB    yes/' /etc/login.defs 2>/dev/null || echo "FAILLOG_ENAB    yes" >> /etc/login.defs
    sed -i 's/^LOG_UNKFAIL_ENAB.*/LOG_UNKFAIL_ENAB  yes/' /etc/login.defs 2>/dev/null || echo "LOG_UNKFAIL_ENAB  yes" >> /etc/login.defs
    sed -i 's/^SYSLOG_SU_ENAB.*/SYSLOG_SU_ENAB   yes/' /etc/login.defs 2>/dev/null || echo "SYSLOG_SU_ENAB   yes" >> /etc/login.defs
    sed -i 's/^SYSLOG_SG_ENAB.*/SYSLOG_SG_ENAB   yes/' /etc/login.defs 2>/dev/null || echo "SYSLOG_SG_ENAB   yes" >> /etc/login.defs
    score 1 "Enhanced login logging configured"
}

check_suspicious_files() {
    log "Checking for suspicious configuration files..."
    find /home -name ".rhosts" 2>/dev/null > /root/rhosts_files.txt || true
    if [ -s /root/rhosts_files.txt ]; then
        warn "Found .rhosts files - will remove them if you confirm or use --apply"
        while read -r file; do
            if require_apply_or_confirm "Remove $file (found .rhosts)"; then
                rm -f "$file" && score 2 "Removed .rhosts file: $file" || warn "Failed to remove $file"
            else
                warn "Skipped removal of $file"
            fi
        done < /root/rhosts_files.txt
    fi

    find /home -name ".netrc" 2>/dev/null > /root/netrc_files.txt || true
    if [ -s /root/netrc_files.txt ]; then
        warn "Found .netrc files: /root/netrc_files.txt"
    fi
}

report_security_findings() {
    log "Generating advanced security report in /root/ ..."
    find / -perm /6000 -type f -exec ls -ld {} \; 2>/dev/null > /root/suid_sgid_files.txt || true
    awk -F: '$7 !~ /(nologin|false)/ {print $1 " " $7}' /etc/passwd | grep -vE 'root|sys|daemon' > /root/login_shell_users.txt || true
    if [ "$HAS_SS" = true ]; then
        ss -tulnp | grep -v "127.0.0.1" > /root/listening_ports.txt 2>/dev/null || true
    else
        netstat -tulnp | grep -v "127.0.0.1" > /root/listening_ports.txt 2>/dev/null || true
    fi
    find /home -name "authorized_keys" -exec cat {} \; > /root/ssh_auth_keys.txt 2>/dev/null || true
    find /etc/systemd/system /lib/systemd/system -type f -exec grep -Ei 'ExecStart=' {} \; > /root/systemd_services.txt 2>/dev/null || true
    [ -f /etc/rc.local ] && cat /etc/rc.local > /root/rc.local.txt 2>/dev/null || true
    for user in $(cut -f1 -d: /etc/passwd); do crontab -u "$user" -l 2>/dev/null; done > /root/all_user_crontabs.txt 2>/dev/null || true
    getent group shadow > /root/shadow_group.txt 2>/dev/null || true
    cat /etc/shells > /root/valid_shells.txt 2>/dev/null || true
    ls -ld /home/* 2>/dev/null | grep -v "drwx------" > /root/insecure_home_dirs.txt 2>/dev/null || true
    visudo -c > /root/sudoers_lint.txt 2>&1 || true
    rkhunter --update && rkhunter --check --rwo > /root/rkhunter_report.txt 2>/dev/null || true
    chkrootkit > /root/chkrootkit_report.txt 2>/dev/null || true
    log "Advanced security report files generated in /root/"
}

ask_and_run() {
    read -p "$1 (y/n): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] && $2
}

main_menu() {
    banner
    echo -e "${BLUE}Select hardening mode:${NC}"
    echo "1. Full Automatic (Fastest - use for standard workstations)"
    echo "2. Interactive (Recommended - review each step)"
    echo "3. Quick Essential (Critical items only)"
    echo "4. Exit"
    echo
    read -p "Enter choice [1-4]: " choice
    case $choice in
        1) DISABLE_DESKTOP_SERVICES=true; full_automatic ;;
        2) interactive_mode ;;
        3) quick_essential ;;
        4) exit 0 ;;
        *) error "Invalid choice"; main_menu ;;
    esac
}

full_automatic() {
    log "Starting FULL AUTOMATIC hardening..."
    create_backup
    update_system
    configure_automatic_updates
    secure_users
    configure_pam
    configure_login_defs
    secure_ssh
    configure_firewall
    secure_network
    disable_unnecessary_services
    configure_audit
    secure_cron
    install_security_tools
    remove_prohibited_software
    remove_unnecessary_packages
    secure_file_permissions
    check_sudoers
    disable_usb_storage
    secure_shared_memory
    configure_process_accounting
    harden_compilers
    check_suspicious_files
    check_worldwritable
    report_security_findings
    finish
}

interactive_mode() {
    log "Starting INTERACTIVE hardening..."
    create_backup
    ask_and_run "Update system?" update_system
    ask_and_run "Configure automatic updates?" configure_automatic_updates
    ask_and_run "Secure user accounts?" secure_users
    ask_and_run "Configure PAM (password policies)?" configure_pam
    ask_and_run "Harden login.defs?" configure_login_defs
    ask_and_run "Secure SSH?" secure_ssh
    ask_and_run "Configure firewall?" configure_firewall
    ask_and_run "Apply network security (sysctl)?" secure_network

    echo
    warn "Service management requires careful review of README!"
    read -p "Disable desktop services (cups, avahi, bluetooth)? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        DISABLE_DESKTOP_SERVICES=true
    fi

    ask_and_run "Disable unnecessary services?" disable_unnecessary_services
    ask_and_run "Configure comprehensive auditing?" configure_audit
    ask_and_run "Secure cron/at?" secure_cron
    ask_and_run "Install security tools (fail2ban, aide, etc.)?" install_security_tools
    ask_and_run "Remove prohibited software?" remove_prohibited_software
    ask_and_run "Remove unnecessary packages?" remove_unnecessary_packages
    ask_and_run "Secure file permissions?" secure_file_permissions
    ask_and_run "Audit sudoers?" check_sudoers
    ask_and_run "Disable USB storage?" disable_usb_storage
    ask_and_run "Secure shared memory?" secure_shared_memory
    ask_and_run "Restrict compiler access?" harden_compilers
    ask_and_run "Check for suspicious files (.rhosts, .netrc)?" check_suspicious_files
    ask_and_run "Scan for world-writable files?" check_worldwritable

    report_security_findings
    finish
}

quick_essential() {
    log "Running QUICK ESSENTIAL hardening..."
    create_backup
    update_system
    secure_users
    configure_pam
    secure_ssh
    configure_firewall
    remove_prohibited_software
    secure_file_permissions
    report_security_findings
    finish
}

finish() {
    echo
    log "════════════════════════════════════════════════════════"
    log "Hardening Complete!"
    log "Total Estimated Points: ${PURPLE}$POINTS${NC}"
    log "Log file: $LOGFILE"
    log "Backup location: $BACKUP_DIR"
    log "════════════════════════════════════════════════════════"
    echo
    warn "IMPORTANT NEXT STEPS:"
    echo "1. Check README for required services and verify they work"
    echo "2. Review all generated reports in /root/"
    echo
    echo -e "${GREEN}Files to review:${NC}"
    echo "  - $LOGFILE (hardening log)"
    echo "  - /root/sudoers_nopasswd.txt (sudo without password)"
    echo "  - /root/world_writable_files.txt (security risk)"
    echo "  - /root/rhosts_files.txt (if exists)"
    read -p "Press Enter to continue..." -r
}

# Main execution
check_root
capability_check
banner
main_menu
