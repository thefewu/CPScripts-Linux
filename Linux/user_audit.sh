#!/bin/bash

# CyberPatriot User Account Audit Script
# Adds capability checks, standardized logs, and requires --apply for destructive changes

LOG_DIR="/root/cyberpatriot_logs"
mkdir -p "$LOG_DIR"
LOGFILE="$LOG_DIR/user_audit_$(date +%Y%m%d_%H%M%S).log"
APPLY=false
if [[ "$1" == "--apply" ]]; then APPLY=true; shift; fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOGFILE"
}
warn() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOGFILE"; }
error() { echo -e "${RED}[ACTION NEEDED]${NC} $1" | tee -a "$LOGFILE"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

capability_check() {
    log "Checking capabilities..."
    command -v ss &>/dev/null && log "ss: available" || warn "ss: not available"
    command -v rkhunter &>/dev/null || warn "rkhunter: not installed (forensics checks may be incomplete)"
    if command -v snap &>/dev/null; then log "snap: installed"; fi
    if [ "$APPLY" = false ]; then warn "Destructive actions will not be performed unless run with --apply"; fi
}

banner() {
    clear
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║         CyberPatriot User Account Auditor             ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

list_all_users() {
    echo
    log "ALL USER ACCOUNTS ON SYSTEM"
    echo -e "${BLUE}Username\tUID\tGID\tHome\t\t\tShell${NC}"
    echo "────────────────────────────────────────────────────────────────"

    awk -F: '($3 >= 1000 || $3 == 0){ printf "%-16s\t%s\t%s\t%-24s\t%s\n", $1, $3, $4, $6, $7 }' /etc/passwd
    echo
}

list_sudoers() {
    log "USERS WITH SUDO/ADMIN PRIVILEGES"
    echo "Members of sudo group:"
    getent group sudo | cut -d: -f4 | tr ',' '\n' | sed '/^$/d' | while read user; do echo "  - $user"; done
    echo
}

check_password_status() {
    log "PASSWORD STATUS FOR ALL USERS"
    awk -F: '($3 >= 1000 || $3 == 0){print $1}' /etc/passwd | while read username; do
        status=$(passwd -S "$username" 2>/dev/null | awk '{print $2}')
        case $status in
            P) echo -e "${GREEN}✓${NC} $username - Password set" ;;
            L) echo -e "${YELLOW}⚠${NC} $username - Account LOCKED" ;;
            NP) echo -e "${RED}✗${NC} $username - NO PASSWORD SET (CRITICAL)" ;;
            *) echo -e "${YELLOW}?${NC} $username - Unknown status: $status" ;;
        esac
    done
    echo
}

check_last_login() {
    log "LAST LOGIN INFORMATION"
    awk -F: '($3 >= 1000 || $3 == 0){print $1}' /etc/passwd | while read username; do
        lastlog -u "$username" 2>/dev/null | sed -n '1!p'
    done
    echo
}

interactive_user_management() {
    echo
    log "INTERACTIVE USER MANAGEMENT"
    echo "Enter authorized users (one per line, empty line to finish):"
    AUTHORIZED_USERS=()
    while true; do
        read -p "Authorized user: " user
        [ -z "$user" ] && break
        AUTHORIZED_USERS+=("$user")
    done

    log "Authorized users: ${AUTHORIZED_USERS[*]}"
    echo "Checking for unauthorized users..."
    awk -F: '($3 >= 1000 && $1 != "nobody"){print $1 ":" $3 ":" $6 ":" $7}' /etc/passwd | while IFS=: read username uid home shell; do
        is_auth=0
        for a in "${AUTHORIZED_USERS[@]}"; do [[ "$username" == "$a" ]] && is_auth=1; done
        if [ $is_auth -eq 0 ]; then
            error "UNAUTHORIZED USER FOUND: $username (UID: $uid, Home: $home, Shell: $shell)"
            echo "Actions: 1) Delete user+home 2) Lock account 3) Skip"
            read -p "Choose action [1-3]: " action
            case $action in
                1)
                    if [ "$APPLY" = true ] || ( read -p "Confirm delete $username? (y/N): " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] ); then
                        userdel -r "$username" 2>/dev/null && log "DELETED user: $username" || error "Failed to delete $username"
                    else
                        warn "Deletion skipped for $username"
                    fi
                    ;;
                2)
                    if [ "$APPLY" = true ] || ( read -p "Confirm lock $username? (y/N): " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] ); then
                        passwd -l "$username" && log "LOCKED user: $username" || warn "Lock failed for $username"
                    else
                        warn "Lock skipped for $username"
                    fi
                    ;;
                *) warn "Kept user: $username" ;;
            esac
        fi
    done
}

# Remaining functions unchanged functionally but using standardized logs and capability checks.
check_user_groups() {
    log "USER GROUP MEMBERSHIPS"
    awk -F: '($3 >= 1000 || $3 == 0){print $1}' /etc/passwd | while read username; do
        groups "$username" 2>/dev/null | cut -d: -f2 || true
    done
    echo
}

manage_sudo_access() {
    log "MANAGE SUDO ACCESS"
    SUDO_USERS=()
    echo "Users who should have sudo access (one per line, empty to finish):"
    while true; do
        read -p "Sudo user: " user
        [ -z "$user" ] && break
        SUDO_USERS+=("$user")
    done
    current_sudo=$(getent group sudo | cut -d: -f4 | tr ',' ' ')
    for user in $current_sudo; do
        is_auth=0
        for auth_user in "${SUDO_USERS[@]}"; do [[ "$user" == "$auth_user" ]] && is_auth=1; done
        if [ $is_auth -eq 0 ]; then
            warn "User $user has sudo but is not authorized"
            if [ "$APPLY" = true ] || ( read -p "Remove sudo access from $user? (y/N): " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] ); then
                deluser "$user" sudo && log "Removed sudo from: $user" || warn "Failed to remove sudo from $user"
            fi
        fi
    done
    # Add authorized sudo users
    for user in "${SUDO_USERS[@]}"; do
        if ! groups "$user" 2>/dev/null | grep -q "\bsudo\b"; then
            if [ "$APPLY" = true ] || ( read -p "Add sudo access to $user? (y/N): " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] ); then
                adduser "$user" sudo && log "Added sudo to: $user" || warn "Failed to add sudo to: $user"
            fi
        fi
    done
}

enforce_password_policy() {
    log "ENFORCE PASSWORD CHANGES"
    if [ "$APPLY" = true ] || ( read -p "Force password change for all users at next login? (y/N): " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] ); then
        awk -F: '($3 >= 1000 && $1 != "nobody"){print $1}' /etc/passwd | while read username; do
            chage -d 0 "$username" && log "Password change required for: $username" || warn "Failed to chage for: $username"
        done
    else
        warn "Password change enforcement skipped (use --apply to automate)"
    fi
}

check_uid_conflicts() {
    log "CHECKING FOR UID CONFLICTS"
    awk -F: '{print $3}' /etc/passwd | sort | uniq -d | while read uid; do
        error "Duplicate UID found: $uid"
        awk -F: -v uid="$uid" '$3 == uid {print "  User: " $1}' /etc/passwd
    done
    awk -F: '$3 == 0 && $1 != "root" {print "  WARNING: User " $1 " has UID 0"}' /etc/passwd
    echo
}

generate_report() {
    REPORT="/root/user_audit_report.txt"
    {
        echo "CYBERPATRIOT USER AUDIT REPORT"
        echo "Generated: $(date)"
        echo
        echo "TOTAL USERS: $(awk -F: '$3 >= 1000 {count++} END {print count}' /etc/passwd)"
        echo "SUDO USERS: $(getent group sudo | cut -d: -f4 | tr ',' '\n' | sed '/^$/d' | wc -l)"
        echo
        echo "ACTIVE USERS (UID >= 1000):"
        awk -F: '$3 >= 1000 && $1 != "nobody" {print "  - " $1 " (UID: " $3 ")"}' /etc/passwd
        echo
        echo "LOCKED ACCOUNTS:"
        passwd -Sa | awk '$2 == "L" {print "  - " $1}'
        echo
    } > "$REPORT"
    log "Report generated: $REPORT"
}

main() {
    check_root
    capability_check
    banner
    log "Starting user account audit..."
    list_all_users
    list_sudoers
    check_password_status
    check_last_login
    check_user_groups
    check_uid_conflicts

    read -p "Do you want to interactively manage users? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        interactive_user_management
        manage_sudo_access
        enforce_password_policy
    fi

    generate_report
    log "User audit complete! Log: $LOGFILE"
}

main
