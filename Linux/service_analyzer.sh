#!/bin/bash

# CyberPatriot Service Analyzer
# Analyzes all services and helps determine which should be running
# Generates detailed reports about each service

set -o pipefail

LOG_DIR="/root/cyberpatriot_logs"
mkdir -p "$LOG_DIR"
LOGFILE="$LOG_DIR/service_analysis_$(date +%Y%m%d_%H%M%S).log"
REPORT="/root/service_analysis_report.txt"
APPLY=false
if [[ "$1" == "--apply" ]]; then APPLY=true; shift; fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- logging helpers ---
log()  { echo -e "${GREEN}[INFO]${NC} $1"  | tee -a "$LOGFILE"; }
warn() { echo -e "${YELLOW}[CHECK]${NC} $1" | tee -a "$LOGFILE"; }
error(){ echo -e "${RED}[RISK]${NC} $1"  | tee -a "$LOGFILE"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
}

banner() {
    clear
    echo -e "${BLUE}"
    cat <<'EOF'
╔══════════════════════════════════════════════════════════╗
║          CyberPatriot Service Analyzer                   ║
╚══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

capability_check() {
    log "Performing capability checks..."
    if pidof systemd &>/dev/null; then
        log "systemd: present"
    else
        warn "systemd: not detected - some features will be limited"
    fi

    if command -v ss &>/dev/null; then
        log "ss: present"
        NETTOOL="ss"
    elif command -v netstat &>/dev/null; then
        warn "ss not available - will use netstat"
        NETTOOL="netstat"
    else
        warn "Neither ss nor netstat available - port enumeration may be limited"
        NETTOOL=""
    fi

    if command -v apache2ctl &>/dev/null || command -v httpd &>/dev/null; then
        log "apachectl/httpd: present"
    fi

    if command -v php &>/dev/null; then
        log "php: present"
    fi

    if command -v mysql &>/dev/null || command -v mariadb &>/dev/null; then
        log "mysql/mariadb client: present"
    fi

    if command -v rkhunter &>/dev/null; then
        log "rkhunter: present (optional integrity checks)"
    fi

    if [ "$APPLY" = false ]; then
        warn "Destructive actions (stop/disable/mask) require --apply or interactive confirmation"
    else
        log "--apply passed: destructive actions permitted without second prompt"
    fi
}

# --- service analysis ---
analyze_service() {
    local service="$1"
    local status
    status=$(systemctl is-active "$service" 2>/dev/null || echo "unknown")
    local enabled
    enabled=$(systemctl is-enabled "$service" 2>/dev/null || echo "unknown")
    local description
    description=$(systemctl show -p Description "$service" 2>/dev/null | cut -d= -f2)

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$REPORT"
    echo "Service: $service" | tee -a "$REPORT"
    echo "Description: $description" | tee -a "$REPORT"
    echo "Status: $status" | tee -a "$REPORT"
    echo "Enabled: $enabled" | tee -a "$REPORT"

    # Try to find listening ports for this service via MainPID
    local pids
    pids=$(systemctl show -p MainPID "$service" 2>/dev/null | cut -d= -f2)
    local ports=""
    if [[ -n "$pids" && "$pids" != "0" ]]; then
        if [[ "$NETTOOL" == "ss" ]]; then
            ports=$(ss -tulpn 2>/dev/null | grep "pid=$pids" | awk '{print $5}' | paste -sd "," -)
        elif [[ "$NETTOOL" == "netstat" ]]; then
            ports=$(netstat -tulpn 2>/dev/null | grep "$pids" | awk '{print $4}' | paste -sd "," -)
        fi
    fi
    [[ -n "$ports" ]] && echo "Listening Ports: $ports" | tee -a "$REPORT"

    # Risk assessment
    assess_service_risk "$service" "$status" | tee -a "$REPORT"

    echo | tee -a "$REPORT"
}

assess_service_risk() {
    local service="$1"; local status="$2"
    # Print (and tee to LOGFILE/REPORT when caller pipes)
    case $service in
        telnet*|rsh*|rlogin*|rexec*)
            if [[ "$status" == "active" ]]; then
                echo "[RISK] HIGH: $service is ACTIVE - unencrypted protocol!"
                echo "RECOMMENDATION: DISABLE immediately unless scenario requires it"
            fi
            ;;
        apache2|nginx|httpd)
            if [[ "$status" == "active" ]]; then
                echo "[CHECK] Web server running: verify if required"
                check_web_config "$service"
            fi
            ;;
        vsftpd|proftpd|ftpd)
            if [[ "$status" == "active" ]]; then
                echo "[CHECK] FTP server running: prefer SFTP"
                echo "RECOMMENDATION: Use SFTP instead of FTP if possible"
            fi
            ;;
        smbd|nmbd|samba*)
            if [[ "$status" == "active" ]]; then
                echo "[CHECK] Samba file sharing active: verify scenario"
            fi
            ;;
        mysql|mariadb|postgresql)
            if [[ "$status" == "active" ]]; then
                echo "[CHECK] Database server running: verify scenario and config"
                check_database_config "$service"
            fi
            ;;
        bind9|named)
            if [[ "$status" == "active" ]]; then
                echo "[CHECK] DNS server running: usually not needed for CTF/competitions"
            fi
            ;;
        avahi-daemon)
            if [[ "$status" == "active" ]]; then
                echo "[CHECK] Avahi (mDNS) running: often safe to disable"
                echo "RECOMMENDATION: DISABLE unless local discovery needed"
            fi
            ;;
        cups*)
            if [[ "$status" == "active" ]]; then
                echo "[CHECK] Printing service running: usually unnecessary in competition"
                echo "RECOMMENDATION: DISABLE unless printing required"
            fi
            ;;
        *)
            # NOTE generic checks could be added here
            ;;
    esac
}

check_web_config() {
    local service="$1"
    echo "  Web Server Security Checks:"
    if [[ "$service" == "apache2" || "$service" == "httpd" ]]; then
        if [[ -d /var/www/html || -d /var/www ]]; then
            local indexcount
            indexcount=$(find /var/www -maxdepth 3 -type f -name "index.*" 2>/dev/null | wc -l)
            echo "    - Web files found: $indexcount"
        fi
        if command -v apache2ctl &>/dev/null && apache2ctl -M 2>/dev/null | grep -q "autoindex"; then
            echo "    - Directory listing may be enabled (check config)"
        fi
    fi
    if command -v php &>/dev/null; then
        local phpver
        phpver=$(php -v 2>/dev/null | head -1)
        echo "    - PHP installed: $phpver"
    fi
}

check_database_config() {
    local service="$1"
    echo "  Database Security Checks:"
    if command -v mysql &>/dev/null; then
        if mysql -u root -e "SELECT 1" &>/dev/null; then
            echo "    - MySQL root has NO PASSWORD (accessible without password)"
            echo "    - Run: mysql_secure_installation"
        else
            echo "    - MySQL root appears to require a password (good)"
        fi
        # check for anonymous users
        local anon_count
        anon_count=$(mysql -u root -e "SELECT User,Host FROM mysql.user WHERE User=''" 2>/dev/null | wc -l || echo 0)
        if [[ "$anon_count" -gt 1 ]]; then
            echo "    - Anonymous DB users found (consider removing)"
        fi
    else
        echo "    - MySQL client not installed; skipping DB password checks"
    fi
}

# --- enumerate services ---
list_all_services() {
    log "Listing all active and enabled services..."
    echo "═════════════════════════════════════════════════════" | tee -a "$REPORT"
    echo "ACTIVE SERVICES" | tee -a "$REPORT"
    echo "═════════════════════════════════════════════════════" | tee -a "$REPORT"

    if pidof systemd &>/dev/null; then
        systemctl list-units --type=service --state=active --no-pager 2>/dev/null | grep ".service" | awk '{print $1}' | while read -r service; do
            analyze_service "$service"
        done
    else
        warn "systemd not present - cannot enumerate systemd services"
    fi

    echo | tee -a "$REPORT"
    echo "═════════════════════════════════════════════════════" | tee -a "$REPORT"
    echo "ENABLED BUT INACTIVE SERVICES" | tee -a "$REPORT"
    echo "═════════════════════════════════════════════════════" | tee -a "$REPORT"

    if pidof systemd &>/dev/null; then
        systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | grep ".service" | awk '{print $1}' | while read -r service; do
            if ! systemctl is-active --quiet "$service" 2>/dev/null; then
                echo "Service: $service (enabled but not running)" | tee -a "$REPORT"
                echo | tee -a "$REPORT"
            fi
        done
    fi
}

# --- check listening ports globally ---
check_listening_ports() {
    log "Analyzing listening network ports..."
    echo "═════════════════════════════════════════════════════" | tee -a "$REPORT"
    echo "LISTENING NETWORK PORTS" | tee -a "$REPORT"
    echo "═════════════════════════════════════════════════════" | tee -a "$REPORT"

    if [[ "$NETTOOL" == "ss" ]]; then
        ss -tulpn 2>/dev/null | grep LISTEN | while read -r line; do
            port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
            process=$(echo "$line" | awk '{print $7}')
            echo "Port: $port - Process: $process" | tee -a "$REPORT"
            case $port in
                21) echo "  [CHECK] FTP (insecure, use SFTP instead)" | tee -a "$REPORT" ;;
                23) echo "  [RISK] TELNET (HIGHLY INSECURE - DISABLE!)" | tee -a "$REPORT" ;;
                25) echo "  [CHECK] SMTP (mail server - verify if needed)" | tee -a "$REPORT" ;;
                80) echo "  [CHECK] HTTP (web server - check README)" | tee -a "$REPORT" ;;
                110) echo "  [CHECK] POP3 (mail - verify if needed)" | tee -a "$REPORT" ;;
                143) echo "  [CHECK] IMAP (mail - verify if needed)" | tee -a "$REPORT" ;;
                445) echo "  [CHECK] SMB/CIFS (file sharing - verify if needed)" | tee -a "$REPORT" ;;
                3306) echo "  [CHECK] MySQL (database - verify if needed)" | tee -a "$REPORT" ;;
                5432) echo "  [CHECK] PostgreSQL (database - verify if needed)" | tee -a "$REPORT" ;;
                31337|12345|6666) echo "  [RISK] KNOWN BACKDOOR PORT!" | tee -a "$REPORT" ;;
            esac
        done
    elif [[ "$NETTOOL" == "netstat" ]]; then
        netstat -tulpn 2>/dev/null | grep LISTEN | while read -r line; do
            port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
            process=$(echo "$line" | awk '{print $7}')
            echo "Port: $port - Process: $process" | tee -a "$REPORT"
        done
    else
        warn "Cannot enumerate listening ports (no ss/netstat)"
    fi

    echo | tee -a "$REPORT"
}

# --- generate human recommendations ---
generate_service_recommendations() {
    log "Generating service recommendations..."
    cat >> "$REPORT" <<'EOF'

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
  □ dovecot/postfix (mail server)

NEVER DISABLE (System Critical):
  ✓ systemd
  ✓ dbus
  ✓ networking/NetworkManager
  ✓ ssh/sshd (unless explicitly instructed)
  ✓ ufw (firewall)
  ✓ rsyslog (logging)

QUICK DISABLE COMMANDS:
  sudo systemctl stop SERVICE_NAME
  sudo systemctl disable SERVICE_NAME
  sudo systemctl mask SERVICE_NAME

═════════════════════════════════════════════════════
EOF
}

# --- interactive management ---
interactive_service_management() {
    echo
    log "═════════════════════════════════════════════════════"
    log "INTERACTIVE SERVICE MANAGEMENT"
    log "═════════════════════════════════════════════════════"
    echo

    warn "This section helps you disable unnecessary services."
    echo "  - Press 'y' to disable; 'n' to keep; 's' to skip remaining."
    echo "  - If you provided --apply, actions execute without second confirmation."

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
            local desc
            desc=$(systemctl show -p Description "$service" 2>/dev/null | cut -d= -f2)
            echo "Description: $desc"

            # show listening ports for the service
            local pid ports
            pid=$(systemctl show -p MainPID "$service" 2>/dev/null | cut -d= -f2)
            if [[ -n "$pid" && "$pid" != "0" && -n "$NETTOOL" ]]; then
                if [[ "$NETTOOL" == "ss" ]]; then
                    ports=$(ss -tulpn 2>/dev/null | grep "pid=$pid" | awk '{print $5}' | paste -sd "," -)
                else
                    ports=$(netstat -tulpn 2>/dev/null | grep "$pid" | awk '{print $4}' | paste -sd "," -)
                fi
                [[ -n "$ports" ]] && echo "Listening on: $ports"
            fi

            echo
            read -r -n1 -p "Disable this service? (y/n/s to skip all): " choice
            echo
            # normalize choice
            case "$choice" in
                [Yy])
                    if [ "$APPLY" = true ]; then
                        systemctl stop "$service" 2>/dev/null || true
                        systemctl disable "$service" 2>/dev/null || true
                        systemctl mask "$service" 2>/dev/null || true
                        log "✓ Disabled: $service"
                    else
                        read -r -n1 -p "Confirm disabling $service now? (y/N): " confirm
                        echo
                        if [[ "$confirm" =~ [Yy] ]]; then
                            systemctl stop "$service" 2>/dev/null || true
                            systemctl disable "$service" 2>/dev/null || true
                            systemctl mask "$service" 2>/dev/null || true
                            log "✓ Disabled: $service"
                        else
                            log "Kept: $service"
                        fi
                    fi
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

# --- main ---
main() {
    banner
    check_root
    capability_check

    : > "$REPORT"
    touch "$LOGFILE" 2>/dev/null || true

    log "Starting comprehensive service analysis..."
    list_all_services
    check_listening_ports
    generate_service_recommendations

    log "Service analysis complete! Report saved to: $REPORT"
    log "Log file: $LOGFILE"

    echo
    read -r -n1 -p "Do you want to interactively manage services? (y/n): " manage
    echo
    if [[ "$manage" =~ ^[Yy]$ ]]; then
        interactive_service_management
    fi

    echo
    log "Review the report at: $REPORT"
    echo
}

main "$@"
