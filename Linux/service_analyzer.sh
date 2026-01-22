#!/bin/bash

# CyberPatriot Service Analyzer
# Analyzes all services and helps determine which should be running
# Generates detailed reports about each service

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOGFILE="service_analysis_$(date +%Y%m%d_%H%M%S).log"
REPORT="/root/service_analysis_report.txt"

log() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOGFILE"
}

warn() {
    echo -e "${YELLOW}[CHECK]${NC} $1" | tee -a "$LOGFILE"
}

error() {
    echo -e "${RED}[RISK]${NC} $1" | tee -a "$LOGFILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
}

banner() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║          CyberPatriot Service Analyzer v1.0              ║
║     Comprehensive Service Review & Risk Assessment       ║
╚══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

analyze_service() {
    local service=$1
    local status=$(systemctl is-active "$service" 2>/dev/null)
    local enabled=$(systemctl is-enabled "$service" 2>/dev/null)
    local description=$(systemctl show -p Description "$service" 2>/dev/null | cut -d= -f2)
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$REPORT"
    echo "Service: $service" | tee -a "$REPORT"
    echo "Description: $description" | tee -a "$REPORT"
    echo "Status: $status" | tee -a "$REPORT"
    echo "Enabled: $enabled" | tee -a "$REPORT"
    
    # Check if service is listening on network ports
    local pids=$(systemctl show -p MainPID "$service" 2>/dev/null | cut -d= -f2)
    if [ "$pids" != "0" ] && [ ! -z "$pids" ]; then
        local ports=$(ss -tulpn 2>/dev/null | grep "pid=$pids" | awk '{print $5}')
        if [ ! -z "$ports" ]; then
            echo "Listening Ports: $ports" | tee -a "$REPORT"
        fi
    fi
    
    # Risk assessment
    assess_service_risk "$service" "$status"
    
    echo | tee -a "$REPORT"
}

assess_service_risk() {
    local service=$1
    local status=$2
    
    # High-risk services (should usually be disabled unless explicitly needed)
    case $service in
        telnet*|rsh*|rlogin*|rexec*)
            if [ "$status" == "active" ]; then
                error "HIGH RISK: $service is ACTIVE - Uses unencrypted protocols!" | tee -a "$REPORT"
                echo "RECOMMENDATION: DISABLE immediately unless scenario requires it" | tee -a "$REPORT"
            fi
            ;;
        apache2|nginx|httpd)
            if [ "$status" == "active" ]; then
                warn "Web server running: Check README if web service is required" | tee -a "$REPORT"
                check_web_config "$service"
            fi
            ;;
        vsftpd|proftpd|ftpd)
            if [ "$status" == "active" ]; then
                warn "FTP server running: Check README if FTP is required" | tee -a "$REPORT"
                echo "RECOMMENDATION: Use SFTP instead of FTP if possible" | tee -a "$REPORT"
            fi
            ;;
        smbd|nmbd|samba*)
            if [ "$status" == "active" ]; then
                warn "Samba file sharing active: Verify if required" | tee -a "$REPORT"
            fi
            ;;
        mysql|mariadb|postgresql)
            if [ "$status" == "active" ]; then
                warn "Database server running: Check README if database is required" | tee -a "$REPORT"
                check_database_config "$service"
            fi
            ;;
        bind9|named)
            if [ "$status" == "active" ]; then
                warn "DNS server running: Usually not needed unless specified" | tee -a "$REPORT"
            fi
            ;;
        avahi-daemon)
            if [ "$status" == "active" ]; then
                warn "Avahi (mDNS) running: Usually safe to disable" | tee -a "$REPORT"
                echo "RECOMMENDATION: DISABLE unless local network discovery needed" | tee -a "$REPORT"
            fi
            ;;
        cups*)
            if [ "$status" == "active" ]; then
                warn "Printing service running: Often unnecessary in competition" | tee -a "$REPORT"
                echo "RECOMMENDATION: DISABLE unless scenario requires printing" | tee -a "$REPORT"
            fi
            ;;
    esac
}

check_web_config() {
    local service=$1
    echo "  Web Server Security Checks:" | tee -a "$REPORT"
    
    if [ "$service" == "apache2" ]; then
        # Check Apache configuration
        if [ -d /var/www/html ]; then
            local indexcount=$(find /var/www -name "index.*" | wc -l)
            echo "    - Web files found: $indexcount" | tee -a "$REPORT"
        fi
        
        # Check for directory listing
        if apache2ctl -M 2>/dev/null | grep -q "autoindex"; then
            warn "    - Directory listing may be enabled (check config)" | tee -a "$REPORT"
        fi
    fi
    
    # Check for PHP
    if command -v php &> /dev/null; then
        local phpver=$(php -v | head -1)
        echo "    - PHP installed: $phpver" | tee -a "$REPORT"
    fi
}

check_database_config() {
    local service=$1
    echo "  Database Security Checks:" | tee -a "$REPORT"
    
    if [ "$service" == "mysql" ] || [ "$service" == "mariadb" ]; then
        # Check if root has password
        if mysql -u root -e "SELECT 1" 2>/dev/null; then
            error "    - MySQL root has NO PASSWORD!" | tee -a "$REPORT"
            echo "    - Run: mysql_secure_installation" | tee -a "$REPORT"
        else
            echo "    - MySQL root password is set (good)" | tee -a "$REPORT"
        fi
        
        # Check for anonymous users
        local anon=$(mysql -u root -e "SELECT User,Host FROM mysql.user WHERE User=''" 2>/dev/null | wc -l)
        if [ "$anon" -gt 1 ]; then
            warn "    - Anonymous users found in database" | tee -a "$REPORT"
        fi
    fi
}

list_all_services() {
    log "Listing all active and enabled services..."
    echo
    
    echo "═════════════════════════════════════════════════════" | tee -a "$REPORT"
    echo "ACTIVE SERVICES" | tee -a "$REPORT"
    echo "═════════════════════════════════════════════════════" | tee -a "$REPORT"
    
    systemctl list-units --type=service --state=active --no-pager | grep ".service" | awk '{print $1}' | while read service; do
        analyze_service "$service"
    done
    
    echo | tee -a "$REPORT"
    echo "═════════════════════════════════════════════════════" | tee -a "$REPORT"
    echo "ENABLED BUT INACTIVE SERVICES" | tee -a "$REPORT"
    echo "═════════════════════════════════════════════════════" | tee -a "$REPORT"
    
    systemctl list-unit-files --type=service --state=enabled --no-pager | grep ".service" | awk '{print $1}' | while read service; do
        if ! systemctl is-active --quiet "$service" 2>/dev/null; then
            echo "Service: $service (enabled but not running)" | tee -a "$REPORT"
            echo | tee -a "$REPORT"
        fi
    done
}

check_listening_ports() {
    log "Analyzing listening network ports..."
    echo
    
    echo "═════════════════════════════════════════════════════" | tee -a "$REPORT"
    echo "LISTENING NETWORK PORTS" | tee -a "$REPORT"
    echo "═════════════════════════════════════════════════════" | tee -a "$REPORT"
    
    ss -tulpn 2>/dev/null | grep LISTEN | while read line; do
        local port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
        local process=$(echo "$line" | awk '{print $7}')
        
        echo "Port: $port - Process: $process" | tee -a "$REPORT"
        
        # Flag suspicious ports
        case $port in
            21) warn "  FTP (insecure, use SFTP instead)" | tee -a "$REPORT" ;;
            23) error "  TELNET (HIGHLY INSECURE - DISABLE!)" | tee -a "$REPORT" ;;
            25) warn "  SMTP (mail server - verify if needed)" | tee -a "$REPORT" ;;
            80) warn "  HTTP (web server - check README)" | tee -a "$REPORT" ;;
            110) warn "  POP3 (mail - verify if needed)" | tee -a "$REPORT" ;;
            143) warn "  IMAP (mail - verify if needed)" | tee -a "$REPORT" ;;
            445) warn "  SMB/CIFS (file sharing - verify if needed)" | tee -a "$REPORT" ;;
            3306) warn "  MySQL (database - verify if needed)" | tee -a "$REPORT" ;;
            5432) warn "  PostgreSQL (database - verify if needed)" | tee -a "$REPORT" ;;
            31337|12345|6666) error "  KNOWN BACKDOOR PORT!" | tee -a "$REPORT" ;;
        esac
    done
    
    echo | tee -a "$REPORT"
}

generate_service_recommendations() {
    log "Generating service recommendations..."
    echo
    
    cat >> "$REPORT" <<EOF

═════════════════════════════════════════════════════
SERVICE MANAGEMENT RECOMMENDATIONS
═════════════════════════════════════════════════════

CRITICAL: Always check the scenario README before disabling services!

HIGH PRIORITY - Usually Safe to Disable:
  □ avahi-daemon (network discovery)
  □ cups/cups-browsed (printing)
  □ bluetooth (if not needed)
  
VERIFY BEFORE DISABLING - Check README:
  □ apache2/nginx (web server)
  □ mysql/mariadb/postgresql (database)
  □ vsftpd/proftpd (FTP server)
  □ smbd/nmbd (Samba file sharing)
  □ bind9 (DNS server)
  □ dovecot (mail server)
  
NEVER DISABLE (System Critical):
  ✓ systemd services
  ✓ dbus
  ✓ networking/NetworkManager
  ✓ ssh/sshd (unless told otherwise)
  ✓ ufw (firewall)
  ✓ rsyslog (logging)

QUICK DISABLE COMMANDS:
  sudo systemctl stop SERVICE_NAME
  sudo systemctl disable SERVICE_NAME
  sudo systemctl mask SERVICE_NAME

═════════════════════════════════════════════════════
EOF
}

interactive_service_management() {
    echo
    log "═════════════════════════════════════════════════════"
    log "INTERACTIVE SERVICE MANAGEMENT"
    log "═════════════════════════════════════════════════════"
    echo
    
    warn "This will help you disable unnecessary services"
    echo
    
    # Get list of running services that might be unnecessary
    RISKY_SERVICES=(
        "avahi-daemon"
        "cups"
        "bluetooth"
        "apache2"
        "nginx"
        "mysql"
        "mariadb"
        "postgresql"
        "vsftpd"
        "smbd"
        "nmbd"
        "bind9"
    )
    
    for service in "${RISKY_SERVICES[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo
            warn "Service '$service' is currently RUNNING"
            
            # Get service description
            local desc=$(systemctl show -p Description "$service" 2>/dev/null | cut -d= -f2)
            echo "Description: $desc"
            
            # Check if it's listening on network
            local pid=$(systemctl show -p MainPID "$service" 2>/dev/null | cut -d= -f2)
            if [ "$pid" != "0" ] && [ ! -z "$pid" ]; then
                local ports=$(ss -tulpn 2>/dev/null | grep "pid=$pid" | awk '{print $5}')
                if [ ! -z "$ports" ]; then
                    echo "Listening on: $ports"
                fi
            fi
            
            echo
            read -p "Disable this service? (y/n/s to skip all): " -n 1 -r
            echo
            
            case $REPLY in
                [Yy])
                    systemctl stop "$service" 2>/dev/null
                    systemctl disable "$service" 2>/dev/null
                    systemctl mask "$service" 2>/dev/null
                    log "✓ Disabled: $service"
                    ;;
                [Ss])
                    log "Skipping remaining services"
                    break
                    ;;
                *)
                    log "Kept: $service"
                    ;;
            esac
        fi
    done
}

main() {
    banner
    check_root
    
    > "$REPORT"  # Clear report file
    
    log "Starting comprehensive service analysis..."
    echo
    
    list_all_services
    check_listening_ports
    generate_service_recommendations
    
    echo
    log "════════════════════════════════════════════════════════"
    log "Service analysis complete!"
    log "Report saved to: $REPORT"
    log "Log file: $LOGFILE"
    log "════════════════════════════════════════════════════════"
    echo
    
    read -p "Do you want to interactively manage services? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        interactive_service_management
    fi
    
    echo
    log "Review the report at: $REPORT"
    echo
}

main
