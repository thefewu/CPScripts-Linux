#!/bin/bash

# CyberPatriot Forensics and Malware Detection Script
# Finds suspicious files, backdoors, and malicious scripts
# Make sure to review findings carefully - not everything flagged is actually bad!

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOGFILE="forensics_$(date +%Y%m%d_%H%M%S).log"
FINDINGS="/root/forensics_findings.txt"

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOGFILE"
}

warn() {
    echo -e "${YELLOW}[SUSPICIOUS]${NC} $1" | tee -a "$LOGFILE" | tee -a "$FINDINGS"
}

error() {
    echo -e "${RED}[CRITICAL]${NC} $1" | tee -a "$LOGFILE" | tee -a "$FINDINGS"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

banner() {
    clear
    echo -e "${YELLOW}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║     CyberPatriot Forensics & Malware Scanner          ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

scan_suspicious_files() {
    log "Scanning for suspicious files in user directories..."
    
    # Common hacking tool filenames - these are bad if we find them
    SUSPICIOUS_NAMES=(
        "*crack*"
        "*hack*"
        "*exploit*"
        "*payload*"
        "*backdoor*"
        "*rootkit*"
        "*keylog*"
        "*password*"
        "*.pcap"           # Packet capture files
        "*netcat*"
        "*nc.exe"
        "*meterpreter*"
        "*reverse_shell*"
        "*bind_shell*"
    )
    
    for pattern in "${SUSPICIOUS_NAMES[@]}"; do
        find /home -iname "$pattern" -type f 2>/dev/null | while read file; do
            warn "Suspicious filename: $file"
        done
    done
}

scan_hidden_files() {
    log "Scanning for hidden files in user directories..."
    
    # Hidden files start with a dot - some are normal, some aren't
    find /home -name ".*" -type f 2>/dev/null | while read file; do
        # Skip the common legitimate ones
        if [[ ! "$file" =~ \.(bashrc|profile|bash_history|vimrc|ssh|gnupg|cache|mozilla|config|local)$ ]]; then
            warn "Hidden file: $file"
        fi
    done
}

scan_setuid_files() {
    log "Scanning for unusual SUID/SGID files..."
    
    # SUID files run with owner's permissions - can be dangerous
    # These are the normal ones we expect to see
    LEGITIMATE_SUID=(
        "/usr/bin/passwd"
        "/usr/bin/sudo"
        "/usr/bin/gpasswd"
        "/usr/bin/chsh"
        "/usr/bin/chfn"
        "/usr/bin/newgrp"
        "/bin/su"
        "/bin/mount"
        "/bin/umount"
        "/usr/bin/pkexec"
    )
    
    find / -perm -4000 -type f 2>/dev/null | while read file; do
        is_legit=0
        
        # Check if it's in our legitimate list
        for legit in "${LEGITIMATE_SUID[@]}"; do
            if [ "$file" == "$legit" ]; then
                is_legit=1
                break
            fi
        done
        
        if [ $is_legit -eq 0 ]; then
            error "Unusual SUID file: $file ($(ls -lh $file))"
        fi
    done
}

scan_cron_jobs() {
    log "Scanning cron jobs for suspicious entries..."
    
    # Check system cron files
    for cronfile in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
        if [ -f "$cronfile" ]; then
            while IFS= read -r line; do
                # Look for suspicious commands in cron entries
                if [[ "$line" =~ (nc|netcat|/dev/tcp|bash.*-i|sh.*-i|python.*socket|perl.*socket|wget|curl.*sh) ]]; then
                    error "Suspicious cron entry in $cronfile: $line"
                fi
            done < "$cronfile"
        fi
    done
    
    # Check each user's crontab
    for user in $(cut -d: -f1 /etc/passwd); do
        crontab -u "$user" -l 2>/dev/null | while IFS= read -r line; do
            if [[ "$line" =~ (nc|netcat|/dev/tcp|bash.*-i|sh.*-i|python.*socket|perl.*socket) ]]; then
                error "Suspicious cron entry for user $user: $line"
            fi
        done
    done
}

scan_startup_scripts() {
    log "Scanning startup scripts and systemd services..."
    
    # Check rc.local (runs at boot)
    if [ -f /etc/rc.local ]; then
        while IFS= read -r line; do
            if [[ "$line" =~ (nc|netcat|/dev/tcp|bash.*-i|sh.*-i) ]]; then
                error "Suspicious entry in /etc/rc.local: $line"
            fi
        done < /etc/rc.local
    fi
    
    # Check systemd service files for backdoors
    find /etc/systemd/system /lib/systemd/system -name "*.service" 2>/dev/null | while read service; do
        if grep -qE "(nc|netcat|/dev/tcp|bash -i|sh -i)" "$service" 2>/dev/null; then
            error "Suspicious systemd service: $service"
            grep -E "(nc|netcat|/dev/tcp|bash -i|sh -i)" "$service" | head -5
        fi
    done
}

scan_bashrc_profiles() {
    log "Scanning bash profiles and rc files..."
    
    # Check shell initialization files for malicious code
    for rcfile in /home/*/.bashrc /home/*/.bash_profile /home/*/.profile /root/.bashrc /root/.bash_profile; do
        if [ -f "$rcfile" ]; then
            while IFS= read -r line; do
                if [[ "$line" =~ (nc|netcat|/dev/tcp|bash.*-i.*bash|python.*socket|perl.*socket) ]]; then
                    error "Suspicious entry in $rcfile: $line"
                fi
            done < "$rcfile"
        fi
    done
}

scan_listening_ports() {
    log "Scanning for suspicious listening ports..."
    
    # Check what ports are listening
    netstat -tulpn 2>/dev/null | grep LISTEN | while read line; do
        port=$(echo "$line" | awk '{print $4}' | cut -d: -f2)
        process=$(echo "$line" | awk '{print $7}')
        
        # High numbered ports can be suspicious
        if [ "$port" -gt 10000 ] 2>/dev/null; then
            warn "High port listening: $port - $process"
        fi
        
        # Check for known backdoor ports
        case $port in
            31337|12345|6666|1337|8080|4444|5555)
                error "Known backdoor port listening: $port - $process"
                ;;
        esac
    done
}

scan_network_connections() {
    log "Scanning active network connections..."
    
    # Log all established connections for review
    netstat -tunap 2>/dev/null | grep ESTABLISHED | while read line; do
        remote=$(echo "$line" | awk '{print $5}')
        process=$(echo "$line" | awk '{print $7}')
        
        echo "Connection: $remote - $process" >> "$FINDINGS"
    done
}

scan_unauthorized_ssh_keys() {
    log "Scanning for unauthorized SSH keys..."
    
    # Check authorized_keys files - these allow passwordless login
    for authkeys in /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; do
        if [ -f "$authkeys" ]; then
            while IFS= read -r key; do
                # Show first 80 chars of each key
                warn "SSH key in $authkeys: ${key:0:80}..."
            done < "$authkeys"
        fi
    done
}

scan_hosts_file() {
    log "Checking /etc/hosts for suspicious entries..."
    
    if [ -f /etc/hosts ]; then
        while IFS= read -r line; do
            # Skip comments, localhost entries, and empty lines
            if [[ ! "$line" =~ ^# ]] && [[ ! "$line" =~ ^127\.0\.0\.1.*localhost ]] && [[ ! "$line" =~ ^::1 ]] && [ ! -z "$line" ]; then
                warn "Hosts file entry: $line"
            fi
        done < /etc/hosts
    fi
}

scan_web_shells() {
    log "Scanning for web shells..."
    
    # Directories where web shells might be placed
    WEB_DIRS=(
        "/var/www"
        "/usr/share/nginx"
        "/opt/lampp/htdocs"
    )
    
    for dir in "${WEB_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            # Look for common web shell code patterns in web files
            find "$dir" -type f \( -name "*.php" -o -name "*.asp" -o -name "*.jsp" \) 2>/dev/null | while read file; do
                if grep -qE "(eval\(|base64_decode|system\(|exec\(|passthru\(|shell_exec)" "$file" 2>/dev/null; then
                    error "Potential web shell: $file"
                fi
            done
        fi
    done
}

scan_unusual_processes() {
    log "Scanning for unusual processes..."
    
    # Look for suspicious processes in the process list
    ps aux | grep -vE "^\[" | while read line; do
        if echo "$line" | grep -qE "(nc|netcat|/dev/tcp|ncat|socat|reverse)"; then
            warn "Suspicious process: $line"
        fi
    done
}

scan_modified_binaries() {
    log "Checking for recently modified system binaries..."
    
    # System binaries shouldn't change often - if they do, could be rootkit
    find /bin /sbin /usr/bin /usr/sbin -type f -mtime -7 2>/dev/null | while read binary; do
        warn "Recently modified binary: $binary ($(stat -c %y $binary))"
    done
}

scan_ld_preload() {
    log "Checking for LD_PRELOAD rootkits..."
    
    # LD_PRELOAD can be used to inject malicious code
    if [ -f /etc/ld.so.preload ]; then
        error "LD_PRELOAD file exists: /etc/ld.so.preload"
        cat /etc/ld.so.preload >> "$FINDINGS"
    fi
}

run_rkhunter() {
    log "Running rkhunter (rootkit scanner)..."
    
    if command -v rkhunter &> /dev/null; then
        # Update rkhunter database first
        rkhunter --update >> "$LOGFILE" 2>&1
        # Run the scan
        rkhunter --check --skip-keypress --report-warnings-only | tee -a "$FINDINGS"
    else
        warn "rkhunter not installed. Install with: apt-get install rkhunter"
    fi
}

run_chkrootkit() {
    log "Running chkrootkit..."
    
    if command -v chkrootkit &> /dev/null; then
        # Filter out normal "not found" messages
        chkrootkit | grep -v "not found" | grep -v "nothing found" | tee -a "$FINDINGS"
    else
        warn "chkrootkit not installed. Install with: apt-get install chkrootkit"
    fi
}

check_suspicious_users() {
    log "Checking for suspicious user accounts..."
    
    # Check for users with low UIDs that aren't system users
    awk -F: '$3 < 1000 && $3 != 0 && $1 != "nobody" {print $1}' /etc/passwd | while read user; do
        warn "Low UID user (potential backdoor): $user"
    done
    
    # Check for users with no password required (very bad!)
    awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | while read user; do
        error "User with no password: $user"
    done
}

generate_report() {
    log "Generating forensics report..."
    
    # Create an HTML report for easy viewing
    cat > /root/forensics_report.html <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>CyberPatriot Forensics Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .critical { color: red; font-weight: bold; }
        .warning { color: orange; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>CyberPatriot Forensics Report</h1>
    <p>Generated: $(date)</p>
    <h2>Findings</h2>
    <pre>
$(cat "$FINDINGS")
    </pre>
</body>
</html>
EOF
    
    log "Report generated: /root/forensics_report.html"
}

# Main execution
main() {
    banner
    check_root
    
    # Clear findings file
    > "$FINDINGS"
    
    log "Starting comprehensive forensics scan..."
    echo
    
    # Run all the scans
    scan_suspicious_files
    scan_hidden_files
    scan_setuid_files
    scan_cron_jobs
    scan_startup_scripts
    scan_bashrc_profiles
    scan_listening_ports
    scan_network_connections
    scan_unauthorized_ssh_keys
    scan_hosts_file
    scan_web_shells
    scan_unusual_processes
    scan_modified_binaries
    scan_ld_preload
    check_suspicious_users
    run_rkhunter
    run_chkrootkit
    
    generate_report
    
    echo
    log "════════════════════════════════════════════════════════"
    log "Forensics scan complete!"
    log "Findings saved to: $FINDINGS"
    log "HTML report: /root/forensics_report.html"
    log "Log file: $LOGFILE"
    log "════════════════════════════════════════════════════════"
    echo
    warn "REVIEW ALL FINDINGS CAREFULLY!"
    echo "Many items flagged may be legitimate - use your judgment."
    echo
}

main
