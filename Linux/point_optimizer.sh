#!/bin/bash

# CyberPatriot Point Optimization Script
# Runs high-yield actions in minutes
# Summarizes most common missed actions


echo "== Point Optimization =="

# Remove unauthorized users
echo "[User Audit]"
for user in $(cut -d: -f1 /etc/passwd); do
  [[ "$(id -u $user)" -ge 1000 ]] && echo $user
done

# Check for unauthorized sudoers
echo "[Sudoers]"
grep -E -v '^#|^Defaults' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep NOPASSWD

# Fix admin group
echo "[Sudo Group]"
getent group sudo

# Check for world-writable files
echo "[World Writable Files]"
find / -xdev -type f -perm -0002 -ls 2>/dev/null | head -20

# Review firewall status
echo "[Firewall]"
ufw status

# Quick install updates
echo "[System Update]"
apt-get update && apt-get upgrade -y

# Remove hacking tools
echo "[Possible hacking tools]"
dpkg -l | grep -iE "john|hydra|nmap|netcat"

echo "Done! Review output and take action as needed."
