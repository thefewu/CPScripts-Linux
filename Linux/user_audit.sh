#!/bin/bash

# CyberPatriot User Account Audit Script
# TODO: might need to update this for the actual competition
# Helps identify unauthorized users and manage accounts

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color - reset

LOGFILE="user_audit_$(date +%Y%m%d_%H%M%S).log"

# Simple logging function - just outputs with timestamp
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOGFILE"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOGFILE"
}

# For things that definitely need attention
error() {
    echo -e "${RED}[ACTION NEEDED]${NC} $1" | tee -a "$LOGFILE"
}

# Make sure we're running as root, otherwise nothing will work
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
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
    log "═══════════════════════════════════════════════════════"
    log "ALL USER ACCOUNTS ON SYSTEM"
    log "═══════════════════════════════════════════════════════"
    echo
    
    echo -e "${BLUE}Username\t\tUID\tGID\tHome\t\t\tShell${NC}"
    echo "────────────────────────────────────────────────────────────────"
    
    # Read through /etc/passwd to get user info
    while IFS=: read -r username password uid gid gecos home shell; do
        # Only show regular users (UID >= 1000) and root (UID 0)
        if [ $uid -ge 1000 ] || [ $uid -eq 0 ]; then
            printf "%-16s\t%s\t%s\t%-24s\t%s\n" "$username" "$uid" "$gid" "$home" "$shell"
        fi
    done < /etc/passwd
    
    echo
}

list_sudoers() {
    log "═══════════════════════════════════════════════════════"
    log "USERS WITH SUDO/ADMIN PRIVILEGES"
    log "═══════════════════════════════════════════════════════"
    echo
    
    # Check the sudo group - most Ubuntu systems use this
    echo "Members of sudo group:"
    getent group sudo | cut -d: -f4 | tr ',' '\n' | while read user; do
        echo "  - $user"
    done
    echo
    
    # Some older systems might use admin group instead
    echo "Members of admin group:"
    getent group admin 2>/dev/null | cut -d: -f4 | tr ',' '\n' | while read user; do
        echo "  - $user"
    done
    echo
    
    # wheel is common on Red Hat systems but check anyway
    echo "Members of wheel group:"
    getent group wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n' | while read user; do
        echo "  - $user"
    done
    echo
}

check_password_status() {
    log "═══════════════════════════════════════════════════════"
    log "PASSWORD STATUS FOR ALL USERS"
    log "═══════════════════════════════════════════════════════"
    echo
    
    while IFS=: read -r username password uid gid gecos home shell; do
        if [ $uid -ge 1000 ] || [ $uid -eq 0 ]; then
            # Get password status using passwd -S
            status=$(passwd -S "$username" 2>/dev/null | awk '{print $2}')
            
            # P = password set, L = locked, NP = no password
            case $status in
                P)
                    echo -e "${GREEN}✓${NC} $username - Password set"
                    ;;
                L)
                    echo -e "${YELLOW}⚠${NC} $username - Account LOCKED"
                    ;;
                NP)
                    echo -e "${RED}✗${NC} $username - NO PASSWORD SET (CRITICAL)"
                    ;;
                *)
                    echo -e "${YELLOW}?${NC} $username - Unknown status: $status"
                    ;;
            esac
        fi
    done < /etc/passwd
    echo
}

check_last_login() {
    log "═══════════════════════════════════════════════════════"
    log "LAST LOGIN INFORMATION"
    log "═══════════════════════════════════════════════════════"
    echo
    
    # This helps identify accounts that have never been used or haven't been used recently
    while IFS=: read -r username password uid gid gecos home shell; do
        if [ $uid -ge 1000 ] || [ $uid -eq 0 ]; then
            lastlog=$(lastlog -u "$username" 2>/dev/null | tail -1)
            echo "$username: $lastlog"
        fi
    done < /etc/passwd
    echo
}

interactive_user_management() {
    echo
    log "═══════════════════════════════════════════════════════"
    log "INTERACTIVE USER MANAGEMENT"
    log "═══════════════════════════════════════════════════════"
    echo
    
    echo "Based on the README, enter authorized users (one per line, empty line to finish):"
    
    # Store authorized users in an array
    AUTHORIZED_USERS=()
    while true; do
        read -p "Authorized user: " user
        if [ -z "$user" ]; then
            break
        fi
        AUTHORIZED_USERS+=("$user")
    done
    
    echo
    log "Authorized users: ${AUTHORIZED_USERS[*]}"
    echo
    
    echo "Checking for unauthorized users..."
    
    # Go through each user and check if they're authorized
    while IFS=: read -r username password uid gid gecos home shell; do
        # Skip system users (UID < 1000) and nobody
        if [ $uid -ge 1000 ] && [ "$username" != "nobody" ]; then
            is_authorized=0
            
            # Check if this user is in our authorized list
            for auth_user in "${AUTHORIZED_USERS[@]}"; do
                if [ "$username" == "$auth_user" ]; then
                    is_authorized=1
                    break
                fi
            done
            
            # If not authorized, ask what to do
            if [ $is_authorized -eq 0 ]; then
                echo
                error "UNAUTHORIZED USER FOUND: $username"
                echo "UID: $uid, Home: $home, Shell: $shell"
                echo
                echo "Actions:"
                echo "1. Delete user and home directory"
                echo "2. Lock user account"
                echo "3. Skip (keep user)"
                read -p "Choose action [1-3]: " action
                
                case $action in
                    1)
                        # Delete user and their home directory
                        userdel -r "$username" 2>/dev/null && log "DELETED user: $username" || error "Failed to delete $username"
                        ;;
                    2)
                        # Just lock the account instead of deleting
                        passwd -l "$username" && log "LOCKED user: $username"
                        ;;
                    3)
                        warn "KEPT user: $username (marked as authorized)"
                        # Add to authorized list in case we see them again
                        AUTHORIZED_USERS+=("$username")
                        ;;
                esac
            fi
        fi
    done < /etc/passwd
}

check_user_groups() {
    log "═══════════════════════════════════════════════════════"
    log "USER GROUP MEMBERSHIPS"
    log "═══════════════════════════════════════════════════════"
    echo
    
    # List all groups each user belongs to
    while IFS=: read -r username password uid gid gecos home shell; do
        if [ $uid -ge 1000 ] || [ $uid -eq 0 ]; then
            groups_list=$(groups "$username" 2>/dev/null | cut -d: -f2)
            echo "$username: $groups_list"
        fi
    done < /etc/passwd
    echo
}

manage_sudo_access() {
    echo
    log "═══════════════════════════════════════════════════════"
    log "MANAGE SUDO ACCESS"
    log "═══════════════════════════════════════════════════════"
    echo
    
    echo "Users who should have sudo access (one per line, empty to finish):"
    
    SUDO_USERS=()
    while true; do
        read -p "Sudo user: " user
        if [ -z "$user" ]; then
            break
        fi
        SUDO_USERS+=("$user")
    done
    
    echo
    log "Authorized sudo users: ${SUDO_USERS[*]}"
    echo
    
    # Get current sudo group members
    current_sudo=$(getent group sudo | cut -d: -f4 | tr ',' ' ')
    
    # Remove unauthorized sudo users
    for user in $current_sudo; do
        is_authorized=0
        
        for auth_user in "${SUDO_USERS[@]}"; do
            if [ "$user" == "$auth_user" ]; then
                is_authorized=1
                break
            fi
        done
        
        if [ $is_authorized -eq 0 ]; then
            echo
            warn "User $user has sudo but is not authorized"
            read -p "Remove sudo access from $user? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                deluser "$user" sudo && log "Removed sudo from: $user"
                # Also try admin group just in case
                deluser "$user" admin 2>/dev/null
            fi
        fi
    done
    
    # Add authorized users to sudo group if they don't have it yet
    for user in "${SUDO_USERS[@]}"; do
        if ! groups "$user" 2>/dev/null | grep -q "\bsudo\b"; then
            read -p "Add sudo access to $user? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                adduser "$user" sudo && log "Added sudo to: $user"
            fi
        fi
    done
}

enforce_password_policy() {
    log "═══════════════════════════════════════════════════════"
    log "ENFORCE PASSWORD CHANGES"
    log "═══════════════════════════════════════════════════════"
    echo
    
    read -p "Force password change for all users at next login? (y/n): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        while IFS=: read -r username password uid gid gecos home shell; do
            # Only do this for regular users, not system accounts
            if [ $uid -ge 1000 ] && [ "$username" != "nobody" ]; then
                # chage -d 0 forces password change on next login
                chage -d 0 "$username" && log "Password change required for: $username"
            fi
        done < /etc/passwd
    fi
}

check_uid_conflicts() {
    log "═══════════════════════════════════════════════════════"
    log "CHECKING FOR UID CONFLICTS"
    log "═══════════════════════════════════════════════════════"
    echo
    
    # Look for duplicate UIDs (which is bad - can cause security issues)
    awk -F: '{print $3}' /etc/passwd | sort | uniq -d | while read uid; do
        error "Duplicate UID found: $uid"
        awk -F: -v uid="$uid" '$3 == uid {print "  User: " $1}' /etc/passwd
    done
    
    # Check for any other users with UID 0 besides root (big security problem!)
    awk -F: '$3 == 0 && $1 != "root" {print "  WARNING: User " $1 " has UID 0"}' /etc/passwd
    
    echo
}

generate_report() {
    REPORT="/root/user_audit_report.txt"
    
    # Generate a quick summary report
    {
        echo "═══════════════════════════════════════════════════════"
        echo "CYBERPATRIOT USER AUDIT REPORT"
        echo "Generated: $(date)"
        echo "═══════════════════════════════════════════════════════"
        echo
        
        echo "TOTAL USERS: $(awk -F: '$3 >= 1000 {count++} END {print count}' /etc/passwd)"
        echo "SUDO USERS: $(getent group sudo | cut -d: -f4 | tr ',' '\n' | wc -l)"
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

# Main function - runs everything
main() {
    banner
    check_root
    
    log "Starting user account audit..."
    echo
    
    list_all_users
    list_sudoers
    check_password_status
    check_last_login
    check_user_groups
    check_uid_conflicts
    
    # Ask if we want to interactively manage users
    read -p "Do you want to interactively manage users? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        interactive_user_management
        manage_sudo_access
        enforce_password_policy
    fi
    
    generate_report
    
    echo
    log "════════════════════════════════════════════════════════"
    log "User audit complete!"
    log "Log file: $LOGFILE"
    log "════════════════════════════════════════════════════════"
    echo
}

# Run the main function
main
