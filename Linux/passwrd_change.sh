#!/bin/bash

# Interactive User Password Manager for Ubuntu
# This script requires root privileges

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Color codes for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Interactive Password Manager${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# Get all users with UID >= 1000 (regular users) and root
# Excludes system users and nobody
users=$(awk -F: '$3 >= 1000 || $3 == 0 {print $1":"$3":"$6}' /etc/passwd | grep -v "nobody")

echo -e "${YELLOW}Found the following users:${NC}"
echo ""

# Display users
IFS=$'\n'
for user_info in $users; do
    username=$(echo "$user_info" | cut -d: -f1)
    uid=$(echo "$user_info" | cut -d: -f2)
    home=$(echo "$user_info" | cut -d: -f3)
    echo -e "  ${GREEN}•${NC} $username (UID: $uid, Home: $home)"
done

echo ""
echo -e "${YELLOW}You can now set passwords for each user.${NC}"
echo -e "${YELLOW}Press Enter to skip a user, or type 'q' to quit.${NC}"
echo ""

# Process each user
for user_info in $users; do
    username=$(echo "$user_info" | cut -d: -f1)
    
    echo -e "${BLUE}────────────────────────────────${NC}"
    read -p "Set password for user '$username'? [y/N/q]: " choice
    
    case "$choice" in
        q|Q)
            echo -e "${YELLOW}Exiting...${NC}"
            exit 0
            ;;
        y|Y)
            # Use passwd command which prompts for password twice
            passwd "$username"
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✓ Password updated successfully for $username${NC}"
            else
                echo -e "${RED}✗ Failed to update password for $username${NC}"
            fi
            ;;
        *)
            echo -e "${YELLOW}Skipped $username${NC}"
            ;;
    esac
    echo ""
done

echo -e "${BLUE}================================${NC}"
echo -e "${GREEN}Password management complete!${NC}"
echo -e "${BLUE}================================${NC}"
