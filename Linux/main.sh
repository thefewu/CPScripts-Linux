#!/bin/bash

# CyberPatriot Ubuntu Hardening Script - Enhanced Main Module
# Version: 4.0 - Comprehensive hardening with intelligent service management
# Compatible with Ubuntu 18.04, 20.04, 22.04, 24.04

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

LOGFILE="hardening_$(date +%Y%m%d_%H%M%S).log"
POINTS=0
BACKUP_DIR="/root/cyberpatriot_backup_$(date +%Y%m%d_%H%M%S)"

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
        error "This script must be run as root (use sudo)"
        exit 1
    fi
}

banner() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════╗
║     CyberPatriot Ubuntu Hardening Suite v4.0               ║
║           Enhanced Competition Edition                     ║
║                                                            ║
║  Features: Intelligent Service Management                 ║
║           Kernel Hardening | Advanced Detection           ║
╚════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

create_backup() {
    log "Creating comprehensive backup..."
    mkdir -p "$BACKUP_DIR"
    
    # Critical system files
    cp /etc/passwd "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/shadow "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/group "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/gshadow "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/sudoers "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /etc/sudoers.d "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /etc/ssh "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/login.defs "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /etc/pam.d "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/fstab "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/hosts "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/host.conf "$BACKUP_DIR/" 2>/dev/null || true
    
    # Service configurations
    systemctl list-unit-files > "$BACKUP_DIR/services.txt"
    
    # Firewall rules
    ufw status verbose > "$BACKUP_DIR/ufw_rules.txt" 2>/dev/null || true
    
    log "Backup created at: $BACKUP_DIR"
}

update_system() {
    log "Updating package lists and upgrading system..."
    
    # Update package lists
    apt-get update -y >> "$LOGFILE" 2>&1
    
    # Fix any broken packages first
    DEBIAN_FRONTEND=noninteractive apt-get -f install -y >> "$LOGFILE" 2>&1
    
    # Upgrade packages non-interactively
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" >> "$LOGFILE" 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" >> "$LOGFILE" 2>&1
    
    # Clean up
    apt-get autoremove -y >> "$LOGFILE" 2>&1
    apt-get autoclean -y >> "$LOGFILE" 2>&1
    
    score 5 "System updated and upgraded"
}

configure_automatic_updates() {
    log "Configuring automatic security updates..."
    
    apt-get install -y unattended-upgrades apt-listchanges >> "$LOGFILE" 2>&1
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
    
    score 3 "Automatic security updates configured"
}

secure_users() {
    log "Implementing user account security..."
    
    # Password aging in /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    score 3 "Password aging policies configured"
    
    # Minimum password length
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN   12/' /etc/login.defs 2>/dev/null || echo "PASS_MIN_LEN   12" >> /etc/login.defs
    
    # Disable guest account (multiple methods for compatibility)
    if [ -f /etc/lightdm/lightdm.conf ]; then
        if ! grep -q "allow-guest=false" /etc/lightdm/lightdm.conf; then
            echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
            score 2 "Guest account disabled"
        fi
    fi
    
    mkdir -p /etc/lightdm/lightdm.conf.d
    cat > /etc/lightdm/lightdm.conf.d/50-no-guest.conf <<EOF
[Seat:*]
allow-guest=false
EOF
    
    # GDM guest disable
    if [ -f /etc/gdm3/custom.conf ]; then
        if ! grep -q "TimedLoginEnable" /etc/gdm3/custom.conf; then
            sed -i '/\[daemon\]/a TimedLoginEnable=false' /etc/gdm3/custom.conf
        fi
    fi
    
    # Lock root account (but don't break sudo)
    passwd -l root 2>/dev/null && score 2 "Root account locked" || true
    
    # Find users with UID 0 (besides root) - CRITICAL SECURITY ISSUE
    awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v "^root$" > /tmp/uid0_users.txt || true
    if [ -s /tmp/uid0_users.txt ]; then
        error "CRITICAL: Users with UID 0 found (other than root):"
        cat /tmp/uid0_users.txt | tee -a "$LOGFILE"
        warn "These users have root privileges! Review immediately!"
    fi
    
    # Lock users with empty passwords - CRITICAL
    awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null > /tmp/empty_pass.txt || true
    if [ -s /tmp/empty_pass.txt ]; then
        while read user; do
            passwd -l "$user" 2>/dev/null && warn "CRITICAL: Locked user with empty password: $user"
        done < /tmp/empty_pass.txt
        score 5 "Locked all users with empty passwords"
    fi
    
    # Set secure umask
    sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
    
    # Set umask in profile files
    for file in /etc/profile /etc/bash.bashrc; do
        if [ -f "$file" ]; then
            if ! grep -q "umask 027" "$file"; then
                echo "umask 027" >> "$file"
            fi
        fi
    done
    score 1 "Secure umask configured"
}

configure_pam() {
    log "Configuring PAM for enhanced security..."
    
    # Install PAM modules
    apt-get install -y libpam-pwquality libpam-cracklib >> "$LOGFILE" 2>&1
    
    # Password quality requirements
    cat > /etc/security/pwquality.conf <<EOF
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
    
    # Account lockout - try faillock first (newer), fall back to tally2
    if [ -f /usr/sbin/faillock ]; then
        # Modern Ubuntu (20.04+)
        if ! grep -q "pam_faillock" /etc/pam.d/common-auth; then
            sed -i '1i auth required pam_faillock.so preauth silent audit deny=5 unlock_time=1800' /etc/pam.d/common-auth
            sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=1800' /etc/pam.d/common-auth
            sed -i '/pam_permit.so/i auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=1800' /etc/pam.d/common-auth
            score 3 "Account lockout configured (faillock: 5 attempts, 30 min)"
        fi
    else
        # Older Ubuntu (18.04)
        if ! grep -q "pam_tally2" /etc/pam.d/common-auth; then
            sed -i '1i auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=1800' /etc/pam.d/common-auth
            score 3 "Account lockout configured (tally2: 5 attempts, 30 min)"
        fi
    fi
    
    # Password history
    if ! grep -q "remember=5" /etc/pam.d/common-password; then
        sed -i '/pam_unix.so/ s/$/ remember=5 minlen=12/' /etc/pam.d/common-password
        score 2 "Password history configured (5 passwords)"
    fi
    
    # Ensure SHA512 is used for password hashing
    if ! grep -q "sha512" /etc/pam.d/common-password; then
        sed -i '/pam_unix.so/ s/$/ sha512/' /etc/pam.d/common-password
        score 1 "SHA512 password hashing enforced"
    fi
}

secure_ssh() {
    log "Hardening SSH configuration..."
    
    if [ ! -f /etc/ssh/sshd_config ]; then
        warn "SSH not installed, skipping SSH hardening"
        return
    fi
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Function to set SSH config value
    set_ssh_config() {
        local param=$1
        local value=$2
        if grep -q "^#*${param}" /etc/ssh/sshd_config; then
            sed -i "s/^#*${param}.*/${param} ${value}/" /etc/ssh/sshd_config
        else
            echo "${param} ${value}" >> /etc/ssh/sshd_config
        fi
    }
    
    # Critical settings
    set_ssh_config "PermitRootLogin" "no"
    score 3 "SSH root login disabled"
    
    set_ssh_config "PermitEmptyPasswords" "no"
    score 2 "SSH empty passwords disabled"
    
    set_ssh_config "Protocol" "2"
    score 2 "SSH Protocol 2 enforced"
    
    set_ssh_config "X11Forwarding" "no"
    score 1 "X11 forwarding disabled"
    
    set_ssh_config "MaxAuthTries" "3"
    score 1 "SSH max auth tries set to 3"
    
    set_ssh_config "LoginGraceTime" "60"
    set_ssh_config "HostbasedAuthentication" "no"
    set_ssh_config "IgnoreRhosts" "yes"
    set_ssh_config "PermitUserEnvironment" "no"
    set_ssh_config "AllowTcpForwarding" "no"
    set_ssh_config "AllowStreamLocalForwarding" "no"
    set_ssh_config "GatewayPorts" "no"
    set_ssh_config "PermitTunnel" "no"
    
    # Idle timeout
    set_ssh_config "ClientAliveInterval" "300"
    set_ssh_config "ClientAliveCountMax" "0"
    score 1 "SSH idle timeout configured (5 min)"
    
    set_ssh_config "MaxStartups" "10:30:60"
    set_ssh_config "MaxSessions" "10"
    
    # Disable weak ciphers and MACs
    echo "# Strong crypto settings" >> /etc/ssh/sshd_config
    echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com" >> /etc/ssh/sshd_config
    echo "MACs hmac-sha2-256,hmac-sha2-512,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com" >> /etc/ssh/sshd_config
    echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config
    score 2 "Weak SSH ciphers disabled"
    
    # Banner
    echo "Authorized access only. All activity may be monitored and reported." > /etc/issue.net
    set_ssh_config "Banner" "/etc/issue.net"
    
    # Test configuration
    if sshd -t 2>/dev/null; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
        log "SSH configuration validated and restarted"
    else
        error "SSH configuration test failed, restoring backup"
        cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    fi
}

configure_firewall() {
    log "Configuring UFW firewall with advanced rules..."
    
    apt-get install -y ufw >> "$LOGFILE" 2>&1
    
    # Reset to clean state
    ufw --force reset >> "$LOGFILE" 2>&1
    
    # Default policies
    ufw default deny incoming >> "$LOGFILE" 2>&1
    ufw default allow outgoing >> "$LOGFILE" 2>&1
    ufw default deny routed >> "$LOGFILE" 2>&1
    
    # Allow SSH (critical - don't lock yourself out!)
    ufw allow 22/tcp comment 'SSH' >> "$LOGFILE" 2>&1
    
    # Rate limit SSH to prevent brute force
    ufw limit 22/tcp >> "$LOGFILE" 2>&1
    
    # Log level
    ufw logging medium >> "$LOGFILE" 2>&1
    
    # Enable firewall
    ufw --force enable >> "$LOGFILE" 2>&1
    
    score 6 "Firewall configured with rate limiting"
    
    # Create script to add service-specific rules later
    cat > /root/add_firewall_rules.sh <<'EOF'
#!/bin/bash
# Add firewall rules for specific services
# Run this after determining which services should be accessible

# Example: Web server
# ufw allow 80/tcp comment 'HTTP'
# ufw allow 443/tcp comment 'HTTPS'

# Example: Database (only from specific IP)
# ufw allow from 192.168.1.0/24 to any port 3306 comment 'MySQL'

# Example: FTP
# ufw allow 21/tcp comment 'FTP'

echo "Edit this script to add service-specific firewall rules"
EOF
    chmod +x /root/add_firewall_rules.sh
}

secure_network() {
    log "Applying comprehensive network security settings..."
    
    cp /etc/sysctl.conf /etc/sysctl.conf.bak 2>/dev/null || true
    
    cat > /etc/sysctl.d/99-cyberpatriot.conf <<EOF
# CyberPatriot Network Security - Enhanced

# IP Forwarding (disable unless this is a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# ICMP redirects (prevent MITM attacks)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Source routing (disable)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log suspicious packets (martians)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reverse path filtering (prevent IP spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# TCP/IP stack hardening
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_rfc1337 = 1

# Kernel pointers (hide from unprivileged users)
kernel.kptr_restrict = 2

# Dmesg restrictions
kernel.dmesg_restrict = 1

# Core dump restrictions
fs.suid_dumpable = 0
kernel.core_uses_pid = 1

# Address space layout randomization
kernel.randomize_va_space = 2

# Restrict ptrace
kernel.yama.ptrace_scope = 1

# Protect against symlink attacks
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
EOF
    
    # Apply settings
    sysctl -p /etc/sysctl.d/99-cyberpatriot.conf >> "$LOGFILE" 2>&1
    score 8 "Comprehensive network security configured"
}

disable_unnecessary_services() {
    log "Analyzing and disabling unnecessary services..."
    
    # HIGH RISK - Almost always disable these
    CRITICAL_DISABLE=(
        "telnet"
        "rsh-server"
        "rlogin"
        "rexec"
        "talk"
        "ntalk"
        "tftp"
    )
    
    # USUALLY DISABLE - Check README first
    USUALLY_DISABLE=(
        "isc-dhcp-server"
        "isc-dhcp-server6"
        "slapd"
        "nfs-server"
        "rpcbind"
        "snmpd"
    )
    
    # SITUATIONAL - Depends on server role
    SITUATIONAL=(
        "apache2"
        "nginx"
        "mysql"
        "mariadb"
        "postgresql"
        "bind9"
        "vsftpd"
        "proftpd"
        "dovecot"
        "postfix"
        "smbd"
        "nmbd"
    )
    
    # USUALLY SAFE TO DISABLE - Desktop services
    DESKTOP_OPTIONAL=(
        "avahi-daemon"
        "cups"
        "cups-browsed"
        "bluetooth"
    )
    
    # EDGE CASES - Verify need
    VERIFY_FIRST=(
        "rsync"
        "iscsid"
    )
    
    # Disable critical risk services
    for service in "${CRITICAL_DISABLE[@]}"; do
        if systemctl list-unit-files | grep -q "^${service}"; then
            systemctl stop "$service" >> "$LOGFILE" 2>&1 || true
            systemctl disable "$service" >> "$LOGFILE" 2>&1 || true
            systemctl mask "$service" >> "$LOGFILE" 2>&1 || true
            score 3 "Disabled critical risk service: $service"
        fi
    done
    
    # Disable usually unnecessary services
    for service in "${USUALLY_DISABLE[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null || systemctl is-enabled --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" >> "$LOGFILE" 2>&1 || true
            systemctl disable "$service" >> "$LOGFILE" 2>&1 || true
            systemctl mask "$service" >> "$LOGFILE" 2>&1 || true
            score 2 "Disabled unnecessary service: $service"
        fi
    done
    
    # Log situational services for manual review
    log "Services requiring manual review based on README:"
    for service in "${SITUATIONAL[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            warn "  - $service is RUNNING - verify if required"
        fi
    done
    
    # Optionally disable desktop services (interactive mode will ask)
    if [ "${DISABLE_DESKTOP_SERVICES}" == "true" ]; then
        for service in "${DESKTOP_OPTIONAL[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                systemctl stop "$service" >> "$LOGFILE" 2>&1 || true
                systemctl disable "$service" >> "$LOGFILE" 2>&1 || true
                systemctl mask "$service" >> "$LOGFILE" 2>&1 || true
                score 2 "Disabled desktop service: $service"
            fi
        done
    fi
}

configure_audit() {
    log "Installing and configuring comprehensive auditing..."
    
    apt-get install -y auditd audispd-plugins >> "$LOGFILE" 2>&1
    
    # Enhanced audit rules
    cat > /etc/audit/rules.d/cyberpatriot.rules <<EOF
# CyberPatriot Audit Rules

# Delete all existing rules
-D

# Buffer size (increase for busy systems)
-b 8192

# Failure mode (1 = print, 2 = panic)
-f 1

# Monitor user/group modifications
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor authentication
-w /var/log/auth.log -p wa -k authentication
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Monitor network configuration changes
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/sysconfig/network -p wa -k network
-w /etc/netplan/ -p wa -k network

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# Monitor cron
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Monitor file deletions
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete

# Make configuration immutable
-e 2
EOF
    
    # Restart auditd
    service auditd restart >> "$LOGFILE" 2>&1 || systemctl restart auditd >> "$LOGFILE" 2>&1
    systemctl enable auditd >> "$LOGFILE" 2>&1
    score 4 "Comprehensive audit logging configured"
}

secure_cron() {
    log "Securing cron and at..."
    
    # Create allow files (whitelist approach)
    touch /etc/cron.allow /etc/at.allow
    chmod 600 /etc/cron.allow /etc/at.allow
    
    # Remove deny files (they override allow files)
    rm -f /etc/cron.deny /etc/at.deny
    
    # Add root to allowed users
    echo "root" > /etc/cron.allow
    echo "root" > /etc/at.allow
    
    # Secure cron directories
    chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly 2>/dev/null || true
    
    score 2 "Cron and at access restricted"
}

install_security_tools() {
    log "Installing comprehensive security toolkit..."
    
    # Install tools
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        rkhunter chkrootkit lynis fail2ban aide \
        apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra \
        libpam-tmpdir libpam-umask debsums acct sysstat \
        arpwatch net-tools >> "$LOGFILE" 2>&1
    
    score 5 "Security tools installed"
    
    # Configure fail2ban
    cat > /etc/fail2ban/jail.local <<EOF
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
    
    systemctl enable fail2ban >> "$LOGFILE" 2>&1
    systemctl restart fail2ban >> "$LOGFILE" 2>&1
    score 3 "Fail2ban configured and enabled"
    
    # Enable AppArmor
    systemctl enable apparmor >> "$LOGFILE" 2>&1
    systemctl start apparmor >> "$LOGFILE" 2>&1
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true
    score 2 "AppArmor enabled and enforcing"
    
    # Initialize AIDE (background process - takes time)
    log "Initializing AIDE database (running in background)..."
    (aideinit >> "$LOGFILE" 2>&1 && log "AIDE database initialized" || warn "AIDE initialization failed") &
}

remove_prohibited_software() {
    log "Scanning for and removing prohibited software..."
    
    PROHIBITED=(
        "john" "hydra" "nmap" "netcat" "nc" "ncat" "crack" "ophcrack"
        "aircrack-ng" "wireshark" "tshark" "nessus" "nikto" "kismet"
        "metasploit-framework" "mitmproxy" "mitmf" "ettercap" "dsniff" "hashcat"
        "medusa" "patator" "thc-hydra" "sqlmap" "wpscan" "dirb" "dirbuster"
        "burpsuite" "zaproxy" "freeciv" "minetest" "supertux" "frozen-bubble"
        "aisleriot" "gnome-mahjongg" "gnome-mines" "gnome-sudoku" "quadrapassel"
    )
    
    for pkg in "${PROHIBITED[@]}"; do
        if dpkg -l 2>/dev/null | grep -qw "^ii.*$pkg"; then
            apt-get purge -y "$pkg" >> "$LOGFILE" 2>&1 || true
            score 3 "Removed prohibited software: $pkg"
        fi
    done
    
    # Check for prohibited snaps
    if command -v snap &> /dev/null; then
        snap list 2>/dev/null | grep -iE "(game|crack|hack|hydra|john)" | awk '{print $1}' | while read snapname; do
            snap remove "$snapname" >> "$LOGFILE" 2>&1 && score 2 "Removed prohibited snap: $snapname"
        done
    fi
}

secure_file_permissions() {
    log "Securing critical file permissions..."
    
    # Critical system files
    chmod 644 /etc/passwd
    chmod 000 /etc/shadow
    chmod 644 /etc/group
    chmod 000 /etc/gshadow
    chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
    chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
    chmod 644 /etc/fstab
    chmod 644 /etc/hosts
    chmod 644 /etc/host.conf
    chmod 644 /etc/hostname
    
    # Ownership
    chown root:root /etc/passwd /etc/group
    chown root:shadow /etc/shadow /etc/gshadow
    
    # Secure cron
    chmod 600 /etc/crontab 2>/dev/null || true
    chown root:root /etc/crontab 2>/dev/null || true
    
    score 4 "Critical file permissions secured"
}

check_sudoers() {
    log "Auditing sudoers configuration..."
    
    cp /etc/sudoers /etc/sudoers.bak 2>/dev/null || true
    
    # Find NOPASSWD entries (security risk)
    grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null > /root/sudoers_nopasswd.txt || true
    if [ -s /root/sudoers_nopasswd.txt ]; then
        warn "NOPASSWD entries found - review /root/sudoers_nopasswd.txt"
    fi
    
    # Ensure sudo uses secure defaults
    if ! grep -q "^Defaults.*use_pty" /etc/sudoers; then
        echo "Defaults use_pty" >> /etc/sudoers
    fi
    if ! grep -q "^Defaults.*logfile" /etc/sudoers; then
        echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers
    fi
    if ! grep -q "^Defaults.*requiretty" /etc/sudoers; then
        echo "Defaults requiretty" >> /etc/sudoers 2>/dev/null || true
    fi
    
    score 2 "Sudoers configuration audited"
}

disable_usb_storage() {
    log "Disabling USB storage..."
    
    echo "install usb-storage /bin/true" > /etc/modprobe.d/disable-usb-storage.conf
    rmmod usb-storage 2>/dev/null || true
    score 2 "USB storage disabled"
}

secure_shared_memory() {
    log "Securing shared memory..."
    
    if ! grep -q "/run/shm" /etc/fstab; then
        echo "tmpfs /run/shm tmpfs defaults,noexec,nodev,nosuid,size=1G 0 0" >> /etc/fstab
        mount -o remount,noexec,nodev,nosuid /run/shm 2>/dev/null || true
        score 2 "Shared memory secured"
    fi
    
    # Secure /tmp
    if ! grep -q "/tmp" /etc/fstab | grep -q "noexec"; then
        warn "Consider securing /tmp with noexec,nodev,nosuid"
    fi
}

configure_process_accounting() {
    log "Enabling process accounting..."
    
    if command -v accton &> /dev/null; then
        touch /var/log/account/pacct 2>/dev/null || true
        accton /var/log/account/pacct 2>/dev/null && score 1 "Process accounting enabled"
    fi
}

harden_compilers() {
    log "Restricting compiler access..."
    
    # Restrict to root and authorized developers
    chmod 750 /usr/bin/gcc* 2>/dev/null || true
    chmod 750 /usr/bin/g++* 2>/dev/null || true
    chmod 750 /usr/bin/cc 2>/dev/null || true
    chmod 750 /usr/bin/c++ 2>/dev/null || true
    chmod 750 /usr/bin/as 2>/dev/null || true
    
    score 1 "Compiler access restricted"
}

remove_unnecessary_packages() {
    log "Removing unnecessary packages..."
    
    UNNECESSARY=(
        "xinetd"
        "nis"
        "yp-tools"
        "tftpd"
        "atftpd"
        "finger"
        "whoopsie"
    )
    
    for pkg in "${UNNECESSARY[@]}"; do
        if dpkg -l 2>/dev/null | grep -qw "^ii.*$pkg"; then
            apt-get purge -y "$pkg" >> "$LOGFILE" 2>&1 || true
            score 1 "Removed unnecessary package: $pkg"
        fi
    done
}

check_worldwritable() {
    log "Scanning for world-writable files (background)..."
    
    # Find world-writable files (excluding /proc, /sys)
    (find / -xdev -type f -perm -0002 -ls 2>/dev/null > /root/world_writable_files.txt && \
     log "World-writable files scan complete") &
    
    (find / -xdev -type d -perm -0002 ! -perm -1000 -ls 2>/dev/null > /root/world_writable_dirs_no_sticky.txt && \
     log "World-writable directories scan complete") &
    
    warn "World-writable scans started in background"
}

configure_login_defs() {
    log "Hardening login.defs..."
    
    # Additional login.defs hardening
    sed -i 's/^LOG_OK_LOGINS.*/LOG_OK_LOGINS   yes/' /etc/login.defs 2>/dev/null || echo "LOG_OK_LOGINS   yes" >> /etc/login.defs
    sed -i 's/^FAILLOG_ENAB.*/FAILLOG_ENAB    yes/' /etc/login.defs 2>/dev/null || echo "FAILLOG_ENAB    yes" >> /etc/login.defs
    sed -i 's/^LOG_UNKFAIL_ENAB.*/LOG_UNKFAIL_ENAB  yes/' /etc/login.defs 2>/dev/null || echo "LOG_UNKFAIL_ENAB  yes" >> /etc/login.defs
    sed -i 's/^SYSLOG_SU_ENAB.*/SYSLOG_SU_ENAB   yes/' /etc/login.defs 2>/dev/null || echo "SYSLOG_SU_ENAB   yes" >> /etc/login.defs
    sed -i 's/^SYSLOG_SG_ENAB.*/SYSLOG_SG_ENAB   yes/' /etc/login.defs 2>/dev/null || echo "SYSLOG_SG_ENAB   yes" >> /etc/login.defs
    
    score 1 "Enhanced login logging configured"
}

check_suspicious_files() {
    log "Checking for suspicious configuration files..."
    
    # Check for .rhosts files (security risk)
    find /home -name ".rhosts" 2>/dev/null > /root/rhosts_files.txt
    if [ -s /root/rhosts_files.txt ]; then
        warn "Found .rhosts files (security risk): /root/rhosts_files.txt"
        cat /root/rhosts_files.txt | while read file; do
            rm -f "$file" && score 2 "Removed .rhosts file: $file"
        done
    fi
    
    # Check for .netrc files (may contain passwords)
    find /home -name ".netrc" 2>/dev/null > /root/netrc_files.txt
    if [ -s /root/netrc_files.txt ]; then
        warn "Found .netrc files: /root/netrc_files.txt"
    fi
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
        1) 
            DISABLE_DESKTOP_SERVICES=true
            full_automatic
            ;;
        2) 
            interactive_mode
            ;;
        3) 
            quick_essential
            ;;
        4) 
            exit 0
            ;;
        *) 
            error "Invalid choice"
            main_menu
            ;;
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
    
    finish
}

ask_and_run() {
    read -p "$1 (y/n): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] && $2
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
    echo "1. Run forensics.sh to check for malware/backdoors"
    echo "2. Run user_audit.sh to verify user accounts"
    echo "3. Run service_analyzer.sh to review services"
    echo "4. Run media_scanner.sh to find prohibited files"
    echo "5. Check README for required services and verify they work"
    echo "6. Review all generated reports in /root/"
    echo
    echo -e "${GREEN}Files to review:${NC}"
    echo "  - $LOGFILE (hardening log)"
    echo "  - /root/sudoers_nopasswd.txt (sudo without password)"
    echo "  - /root/world_writable_files.txt (security risk)"
    echo "  - /root/rhosts_files.txt (if exists)"
    echo
    echo -e "${YELLOW}Next commands to run:${NC}"
    echo "  sudo ./forensics.sh"
    echo "  sudo ./user_audit.sh"
    echo "  sudo ./service_analyzer.sh"
    echo "  sudo ./media_scanner.sh"
    echo
    read -p "Press Enter to continue..."
}

# Main execution
check_root
main_menu
