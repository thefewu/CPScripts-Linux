# CyberPatriot Linux Hardening Suite

**Version:** 4.0 (Competition Ready)  
**Target Systems:** Ubuntu 18.04, 20.04, 22.04, 24.04  
**Last Updated:** January 2026

## Table of Contents

1. [Overview](#overview)
2. [Critical Warning](#critical-warning)
3. [Pre-Execution Checklist](#pre-execution-checklist)
4. [Recommended Execution Order](#recommended-execution-order)
5. [Script Descriptions](#script-descriptions)
6. [Service Management Guidelines](#service-management-guidelines)
7. [Common Scenarios](#common-scenarios)
8. [Troubleshooting](#troubleshooting)
9. [Point Optimization Tips](#point-optimization-tips)

## Overview

This suite automates security hardening tasks for CyberPatriot Linux competitions. It addresses user management, service configuration, network security, forensics detection, and system hardening according to industry best practices and CyberPatriot scoring criteria.

**Key Features:**
- Comprehensive user account auditing and management
- Automated password policy enforcement
- Service analysis with intelligent recommendations
- Forensics scanning for malware and backdoors
- Media file detection and removal
- Browser security hardening
- Network and firewall configuration
- Audit logging and compliance checking

## Critical Warning

**READ THIS BEFORE RUNNING ANY SCRIPT**

These scripts make significant system changes. Running them incorrectly can:
- Disable required services (loss of points)
- Remove authorized users (loss of points)
- Break critical functionality (loss of points)
- Lock you out of the system

**Always:**
1. Read the scenario README thoroughly first
2. Identify all authorized users and administrators
3. Identify all required services (web server, database, file sharing, etc.)
4. Review script actions before confirming in interactive mode
5. Keep backups accessible

## Pre-Execution Checklist

Before running any script, complete this checklist:

### Step 1: Read the Scenario README
- [ ] Identify all authorized users (regular and administrators)
- [ ] Identify all prohibited users to remove
- [ ] Note required services (e.g., "This machine runs a web server")
- [ ] Note prohibited software to remove
- [ ] Check for allowed media files (some scenarios permit specific files)
- [ ] Note any custom requirements or exceptions

### Step 2: Document Current State
Create a quick reference document with:
- Authorized users: _______________
- Authorized administrators: _______________
- Required services: _______________
- Prohibited software: _______________
- Special notes: _______________

### Step 3: Prepare the Environment
```bash
# Make scripts executable
chmod +x *.sh

# Ensure you're running as root
sudo -i

# Update package lists (safe to do first)
apt-get update
```

## Recommended Execution Order

Follow this order for optimal results and minimum risk:

### Phase 1: Information Gathering (No Changes Made)
**Time: 5-10 minutes**

1. **user_audit.sh** - View only mode
   ```bash
   ./user_audit.sh
   # Review all users, do NOT make changes yet
   # Press 'n' when asked to manage users interactively
   ```
   - Review the generated report
   - Cross-reference with README authorized users
   - Mark unauthorized users for removal

2. **service_analyzer.sh** - Analysis only
   ```bash
   ./service_analyzer.sh
   # Press 'n' when asked to manage services
   ```
   - Review which services are running
   - Cross-reference with README requirements
   - Mark unnecessary services for disabling

3. **forensics.sh** - Scan for threats
   ```bash
   ./forensics.sh
   ```
   - Review findings in /root/forensics_findings.txt
   - Identify malware, backdoors, and suspicious files
   - Note items for removal

4. **media_scanner.sh** - Find prohibited files
   ```bash
   ./media_scanner.sh
   # Press 'n' when asked to delete interactively (review first)
   ```
   - Review prohibited_media.txt
   - Verify files are actually prohibited per README
   - Mark files for deletion

### Phase 2: User Management (High Priority)
**Time: 5-10 minutes**

5. **user_audit.sh** - Execute user changes
   ```bash
   ./user_audit.sh
   # Now press 'y' for interactive management
   ```
   - Remove unauthorized users
   - Fix administrator/sudo assignments
   - Enforce password requirements
   - Lock accounts as needed

### Phase 3: System Hardening
**Time: 10-15 minutes**

6. **main.sh** - Core hardening
   ```bash
   ./main.sh
   # Choose Option 2: Interactive Mode (recommended)
   # Choose Option 1: Full Automatic (only if standard workstation)
   ```
   
   **Interactive mode allows you to:**
   - Skip service disabling if unsure
   - Review each change before applying
   - Preserve required services
   
   **This script handles:**
   - System updates and automatic update configuration
   - Password policies (complexity, aging, history)
   - SSH hardening (disable root login, Protocol 2)
   - Firewall configuration (UFW)
   - Network security (sysctl settings)
   - PAM configuration (account lockout)
   - File permissions
   - Audit logging
   - Security tool installation

### Phase 4: Specialized Hardening
**Time: 5 minutes**

7. **browser_harden.sh** - Browser security
   ```bash
   ./browser_harden.sh
   ```
   - Hardens Firefox and Chrome/Chromium
   - Disables password managers
   - Enables pop-up blocking
   - Configures privacy settings

8. **advanced_hardening.sh** - Advanced security measures
   ```bash
   ./advanced_hardening.sh
   ```
   - GRUB protection
   - IPv6 hardening
   - /tmp security
   - AIDE integrity monitoring
   - Additional kernel hardening

9. **service_analyzer.sh** - Disable unnecessary services
   ```bash
   ./service_analyzer.sh
   # Now press 'y' to manage services interactively
   ```
   - Disable services marked in Phase 1
   - Verify required services remain running

### Phase 5: Cleanup and Verification
**Time: 5-10 minutes**

9. **media_scanner.sh** - Remove prohibited files
   ```bash
   ./media_scanner.sh
   # Press 'y' to delete interactively
   ```
   - Delete confirmed prohibited media
   - Remove unauthorized applications

10. **Final verification**
    ```bash
    # Verify critical services are running
    systemctl status apache2   # If web server required
    systemctl status mysql     # If database required
    systemctl status ssh       # SSH should be running
    
    # Verify firewall is active
    ufw status
    
    # Verify authorized users exist
    cat /etc/passwd | grep "authorized_username"
    
    # Check for remaining prohibited software
    dpkg -l | grep -iE "john|hydra|nmap|netcat"
    ```

## Script Descriptions

### main.sh - Core System Hardening

**Purpose:** Applies fundamental security configurations to the system.

**What it does:**
- Updates all packages to latest security versions
- Configures automatic security updates
- Sets password policies: minimum length 12, complexity requirements, 90-day max age
- Configures PAM for account lockout (5 failed attempts, 30-minute lockout)
- Hardens SSH: disables root login, enforces Protocol 2, disables empty passwords
- Configures UFW firewall: deny incoming, allow outgoing, rate-limit SSH
- Applies network security via sysctl: disable IP forwarding, enable SYN cookies, disable ICMP redirects
- Sets secure file permissions on critical files (/etc/passwd, /etc/shadow)
- Installs security tools: fail2ban, rkhunter, chkrootkit, AppArmor, AIDE
- Removes common hacking tools
- Disables USB storage
- Configures comprehensive audit logging
- Secures cron and at

**Modes:**
1. Full Automatic - Fastest, applies all changes without prompting
2. Interactive - Prompts before each major change (recommended for first run)
3. Quick Essential - Only critical items (updates, users, SSH, firewall)

**Estimated points:** 40-60

### user_audit.sh - User Account Management

**Purpose:** Manages user accounts, passwords, and administrative privileges.

**What it does:**
- Lists all user accounts with UID >= 1000
- Identifies users with sudo/admin privileges
- Checks password status (set, locked, or empty)
- Shows last login information
- Identifies UID conflicts and duplicate UID 0 accounts
- Interactively removes unauthorized users
- Manages sudo group membership
- Forces password changes on next login
- Generates comprehensive user audit report

**Critical for:**
- Removing unauthorized users
- Ensuring only authorized users have sudo access
- Identifying accounts with no passwords
- Finding backdoor accounts (UID 0)

**Estimated points:** 15-25

### service_analyzer.sh - Service Analysis and Management

**Purpose:** Identifies running services and helps determine which should be disabled.

**What it does:**
- Lists all active services with descriptions
- Shows listening network ports and associated processes
- Flags high-risk services (Telnet, FTP, etc.)
- Provides security assessment for each service
- Checks web server and database configurations
- Generates detailed service report
- Interactively disables unnecessary services

**Service categories:**
- High Risk: Always disable unless required (Telnet, RSH, Rlogin)
- Usually Unnecessary: Safe to disable unless specified (Avahi, CUPS, Bluetooth)
- Verify Requirements: Check README (Apache, MySQL, Samba, FTP)
- Never Disable: System critical (SSH, NetworkManager, UFW, rsyslog)

**Estimated points:** 10-20

### forensics.sh - Malware and Backdoor Detection

**Purpose:** Scans for indicators of compromise, hacking tools, and persistence mechanisms.

**What it does:**
- Scans for suspicious files by name (crack, hack, exploit, keylog)
- Identifies hidden files in user directories
- Finds unusual SUID/SGID binaries
- Checks cron jobs for malicious entries
- Scans startup scripts and systemd services for backdoors
- Checks bash profiles for malicious code
- Identifies suspicious listening ports (31337, 12345, etc.)
- Scans for unauthorized SSH keys
- Checks /etc/hosts for suspicious entries
- Searches for web shells in web directories
- Identifies unusual processes
- Checks for recently modified system binaries
- Detects LD_PRELOAD rootkits
- Runs rkhunter and chkrootkit if installed
- Identifies suspicious user accounts
- Generates HTML forensics report

**Common findings:**
- Netcat backdoors in cron
- Hidden files with hacking tools
- Unauthorized SSH keys for persistence
- Modified /etc/hosts for phishing
- Web shells in /var/www
- SUID binaries that shouldn't be

**Estimated points:** 10-20

### media_scanner.sh - Prohibited Media Detection

**Purpose:** Finds and removes prohibited media files (images, audio, video, games).

**What it does:**
- Scans for image files (JPG, PNG, GIF, BMP, etc.)
- Scans for video files (MP4, AVI, MKV, MOV, etc.)
- Scans for audio files (MP3, WAV, FLAC, AAC, etc.)
- Finds large archive files that may contain hidden content
- Identifies game directories (.steam, .minecraft, Games)
- Scans for files with suspicious names
- Checks Downloads and Desktop directories
- Identifies large files (>100MB)
- Scans browser download history
- Checks Trash/Recycle bins
- Generates summary report
- Interactively prompts for file deletion

**Important:** Always verify files are prohibited in the README. Some scenarios allow specific media for business purposes (e.g., company logo images, training videos).

**Estimated points:** 5-15

### browser_harden.sh - Browser Security

**Purpose:** Applies security policies to Firefox and Chrome/Chromium browsers.

**What it does:**
- Configures Firefox Enterprise Policies
- Disables Firefox password manager
- Blocks about:config access
- Enables pop-up blocking (locked)
- Configures cookie rejection for third-party
- Enables automatic cache/history clearing on shutdown
- Disables private browsing mode
- Configures Chrome Managed Policies
- Disables Chrome password manager
- Blocks third-party cookies
- Disables developer tools
- Disables incognito mode
- Enables safe browsing
- Disables sync and metrics

**Note:** Users must restart browsers for changes to take effect.

**Estimated points:** 3-8

## Service Management Guidelines

Service management is critical in CyberPatriot. Disabling a required service loses points, but leaving an unnecessary service running also loses points. Always check the scenario README first.

### Services to Disable (Almost Always)

These services are rarely needed in competition scenarios and represent security risks:

**Absolutely Disable:**
- telnet, rsh-server, rlogin, rexec - Unencrypted remote access protocols
- talk, ntalk - Ancient messaging protocols
- tftp - Trivial FTP (no authentication)
- isc-dhcp-server - Unless this is a DHCP server
- slapd - LDAP server (rarely needed)
- nfs-server - Network File System server
- rpcbind - RPC services (needed for NFS)
- snmpd - SNMP monitoring (unless specified)

### Services to Verify Before Disabling

Check the README before touching these:

**Web Services:**
- apache2, nginx, httpd - Only disable if NOT a web server
- Check for: "This machine hosts a website" or similar

**Database Services:**
- mysql, mariadb, postgresql - Only disable if NOT a database server
- Check for: "This machine runs a database" or web applications

**File Sharing:**
- vsftpd, proftpd - FTP servers (insecure, but might be required)
- smbd, nmbd - Samba/Windows file sharing
- Check for: "File server" or "Shares files with Windows clients"

**Mail Services:**
- dovecot, postfix, sendmail - Mail servers
- Check for: "Mail server" or "Email server"

**DNS:**
- bind9, named - DNS servers
- Check for: "DNS server" or "Name server"

### Services That Depend on Scenario

**Printing (Usually Safe to Disable):**
- cups, cups-browsed
- Disable unless: "Printing services required" or "Print server"

**Network Discovery (Usually Safe to Disable):**
- avahi-daemon
- Provides Bonjour/Zeroconf
- Disable unless: Specific network discovery requirement

**Bluetooth (Safe to Disable on Servers):**
- bluetooth
- Keep on desktop systems if users might need it
- Disable on servers

**Backup/Sync (Verify First):**
- rsync
- Might be used for legitimate backups
- Check if backup jobs are mentioned in README

**iSCSI (Usually Disable):**
- iscsid
- Network storage initiator
- Disable unless: "iSCSI storage" or "SAN" mentioned

### Never Disable These

Critical system services - disabling these will break the system:

- systemd services (systemd-*)
- dbus
- networking, NetworkManager
- ssh, sshd (unless explicitly told to disable SSH)
- ufw (firewall)
- rsyslog, syslog (logging)
- cron
- systemd-logind

## Common Scenarios

### Scenario 1: Standard Desktop Workstation
**Characteristics:** No server role mentioned, regular users

**Actions:**
- Disable: All server services (web, database, file sharing, mail)
- Disable: avahi-daemon, cups (unless printing mentioned)
- Keep: SSH (for remote administration)
- Keep: Desktop services (lightdm, NetworkManager)

### Scenario 2: Web Server
**Characteristics:** "This machine hosts a company website"

**Actions:**
- Keep: apache2 or nginx
- Keep: mysql/mariadb (if website uses database)
- Keep: SSH
- Disable: FTP (use SFTP instead), Samba, mail services
- Secure Apache: Disable directory listing, remove default pages, check permissions

### Scenario 3: Database Server
**Characteristics:** "This machine runs the company database"

**Actions:**
- Keep: mysql/mariadb/postgresql
- Keep: SSH
- Disable: Web servers (unless also mentioned), FTP, Samba
- Secure Database: Run mysql_secure_installation, remove anonymous users, set root password

### Scenario 4: File Server
**Characteristics:** "File server" or "Samba server"

**Actions:**
- Keep: smbd, nmbd (Samba)
- Keep: SSH
- Disable: Web, database, FTP
- Secure Samba: Check smb.conf for security settings, restrict shares

### Scenario 5: Mail Server
**Characteristics:** "Mail server" or "Email server"

**Actions:**
- Keep: postfix/sendmail, dovecot
- Keep: SSH
- Disable: Web (unless webmail mentioned), FTP, Samba
- Secure Mail: Check for open relay, require authentication

## Troubleshooting

### Problem: I lost points after running scripts

**Disabled Required Service**
```bash
# Check if a service is masked
systemctl status apache2

# If masked, unmask it
sudo systemctl unmask apache2

# Start and enable the service
sudo systemctl start apache2
sudo systemctl enable apache2

# Verify it's running
sudo systemctl status apache2
```

**Deleted Required User**
```bash
# Restore from backup
sudo cp /root/cyberpatriot_backup_*/passwd /etc/passwd
sudo cp /root/cyberpatriot_backup_*/shadow /etc/shadow

# Or recreate the user
sudo adduser username
sudo usermod -aG sudo username  # If they need sudo
```

**Broke Network Configuration**
```bash
# Disable firewall temporarily to test
sudo ufw disable

# If still broken, check sysctl settings
sudo sysctl -p

# Restore network settings from backup
sudo cp /root/cyberpatriot_backup_*/sysctl.conf /etc/sysctl.conf
```

**SSH Won't Start After Hardening**
```bash
# Test SSH configuration
sudo sshd -t

# If errors, restore backup config
sudo cp /root/cyberpatriot_backup_*/ssh/sshd_config /etc/ssh/sshd_config

# Restart SSH
sudo systemctl restart sshd
```

### Problem: Script fails with permission denied

```bash
# Make scripts executable
chmod +x *.sh

# Run with sudo
sudo ./script_name.sh

# Or become root
sudo -i
```

### Problem: Can't find prohibited media/users mentioned in README

**Finding Hidden Users:**
```bash
# List all users with valid shells
grep -v '/nologin\|/false' /etc/passwd

# Check for users with UID 0 (besides root)
awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd
```

**Finding Hidden Files:**
```bash
# Search for files by name
sudo find / -iname "*keyword*" 2>/dev/null

# Search in specific user's home
sudo find /home/username -type f -name ".*" 2>/dev/null
```

### Problem: Services keep restarting after disabling

```bash
# Use mask instead of just disable
sudo systemctl mask service_name

# This prevents the service from being started by dependencies
```

## Point Optimization Tips

### High-Value Quick Wins (Do These First)

1. **Remove Unauthorized Users** (3-5 points each)
   - Check scenario README for authorized users
   - Delete extras: `sudo userdel -r username`

2. **Fix Administrator Group** (5-10 points)
   - Ensure only authorized users in sudo group
   - Remove unauthorized: `sudo deluser username sudo`

3. **Update System** (5 points)
   - `sudo apt-get update && sudo apt-get upgrade -y`

4. **Enable Firewall** (5 points)
   - `sudo ufw enable`

5. **Disable Guest Account** (2 points)
   - See main.sh secure_users function

6. **Remove Prohibited Software** (3 points each)
   - Common: john, hydra, nmap, netcat
   - `sudo apt-get purge package_name`

### Medium-Value Improvements

7. **SSH Hardening** (10-15 points total)
   - Disable root login
   - Enforce Protocol 2
   - Disable empty passwords
   - Configure idle timeout

8. **Password Policies** (10-15 points total)
   - Set password complexity (PAM)
   - Configure password aging
   - Set account lockout policy

9. **Remove Prohibited Media** (2-3 points each)
   - Check for MP3, MP4, games
   - Verify against README first

10. **Audit Logging** (5 points)
    - Enable auditd
    - Configure audit rules

### Advanced Optimizations

11. **File Permissions** (5-10 points)
    - Fix /etc/shadow permissions (000)
    - Fix /etc/passwd permissions (644)
    - Secure SSH config

12. **Kernel Hardening** (5 points)
    - Disable IP forwarding
    - Enable SYN cookies
    - Configure sysctl parameters

13. **Service Hardening** (varies)
    - Disable unnecessary services
    - Secure required services (Apache, MySQL)

14. **Find Forensics Questions** (5-20 points)
    - Check for backdoors in cron
    - Find unauthorized SSH keys
    - Check for malicious processes

### Time Management

**First 30 Minutes:**
- Read README thoroughly (10 min)
- Run user_audit.sh and remove unauthorized users (10 min)
- Run forensics.sh and review findings (10 min)

**Next 30 Minutes:**
- Run main.sh in interactive mode (15 min)
- Review and disable unnecessary services (10 min)
- Remove prohibited software and media (5 min)

**Remaining Time:**
- Answer forensic questions if any
- Verify all required services still work
- Check for any missed vulnerabilities
- Review audit logs

### Common Point Losses to Avoid

- Disabling required services (big point loss)
- Deleting authorized users (big point loss)
- Breaking network connectivity (big point loss)
- Not reading README completely (missing easy points)
- Forgetting to remove prohibited media in Trash
- Missing users with UID 0
- Not checking all sudo/admin group members

## Forensic Question Examples

Competitions often include forensic questions in the README. Examples:

**Question:** "Which user has a backdoor in their crontab?"
**How to find:** Run forensics.sh or manually check:
```bash
for user in $(cut -d: -f1 /etc/passwd); do
  echo "=== $user ==="
  sudo crontab -u $user -l 2>/dev/null
done
```

**Question:** "What port is the backdoor listening on?"
**How to find:**
```bash
sudo netstat -tulpn | grep LISTEN
# or
sudo ss -tulpn
```

**Question:** "What is the password of user X?"
**How to find:** Check for password hints in:
- README itself
- User's home directory files
- /var/log files
- Hidden files in ~

## Additional Security Checks

### Manual Checks to Perform

1. **Check for world-writable files**
```bash
sudo find / -xdev -type f -perm -0002 -ls 2>/dev/null
```

2. **Check for files with no owner**
```bash
sudo find / -xdev -nouser -o -nogroup 2>/dev/null
```

3. **Check for SUID/SGID files**
```bash
sudo find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
```

4. **Check for empty password fields**
```bash
sudo awk -F: '($2 == "") {print $1}' /etc/shadow
```

5. **Check /etc/hosts for suspicious entries**
```bash
cat /etc/hosts | grep -v "^#" | grep -v "127.0.0.1"
```

6. **Check for unauthorized SSH keys**
```bash
sudo find /home -name "authorized_keys" -exec cat {} \;
```

7. **Check listening ports**
```bash
sudo ss -tulpn
```

## Files to Review

After running scripts, review these files:

- `/root/forensics_findings.txt` - Suspicious files and configurations
- `/root/prohibited_media.txt` - Media files found
- `/root/service_analysis_report.txt` - Service recommendations
- `/root/user_audit_report.txt` - User account summary
- `/root/sudoers_nopasswd.txt` - Sudo entries without password
- `/root/world_writable_files.txt` - Files anyone can modify
- `/var/log/auth.log` - Authentication attempts
- `/var/log/syslog` - System events

## Quick Reference Commands

```bash
# User Management
sudo adduser username              # Add user
sudo userdel -r username           # Delete user and home
sudo passwd username               # Change password
sudo usermod -aG sudo username     # Add to sudo group
sudo deluser username sudo         # Remove from sudo

# Service Management
systemctl status service_name      # Check service status
systemctl stop service_name        # Stop service
systemctl disable service_name     # Disable at boot
systemctl mask service_name        # Prevent service from starting
systemctl start service_name       # Start service
systemctl enable service_name      # Enable at boot
systemctl unmask service_name      # Allow service to start

# Firewall
sudo ufw status                    # Check firewall status
sudo ufw enable                    # Enable firewall
sudo ufw allow 22/tcp              # Allow SSH
sudo ufw deny 21/tcp               # Block FTP
sudo ufw status numbered           # Show rules with numbers
sudo ufw delete 3                  # Delete rule number 3

# Package Management
sudo apt-get update                # Update package lists
sudo apt-get upgrade               # Upgrade packages
sudo apt-get purge package_name    # Remove package completely
sudo apt-get autoremove            # Remove unused packages

# File Permissions
chmod 644 file                     # rw-r--r--
chmod 600 file                     # rw-------
chmod 755 file                     # rwxr-xr-x
chown user:group file              # Change owner

# Searching
grep -r "keyword" /path            # Search in files
find / -name "filename"            # Find file by name
find / -user username              # Find files by owner
```

## Version History

### advanced_hardening.sh - Additional Security Hardening

**Purpose:** Applies advanced security configurations beyond basic hardening.

**What it does:**
- GRUB bootloader password protection
- IPv6 hardening or disabling
- Secures /tmp and /var/tmp with noexec,nodev,nosuid
- Configures AIDE file integrity monitoring
- Disables core dumps and crash reporting
- Secures NFS if present
- Configures login banners
- Disables unnecessary network protocols (DCCP, SCTP, RDS, TIPC)
- Blacklists Firewire and Thunderbolt (DMA attack vectors)
- Disables Ctrl-Alt-Delete reboot
- Advanced audit rules for system calls
- SUID/SGID binary audit
- TCP Wrappers configuration
- Additional kernel parameter optimization

**When to run:** After main.sh, for additional hardening points

**Estimated points:** 15-25

## Version History

**Version 4.0:**
- NEW: advanced_hardening.sh for GRUB, IPv6, and kernel hardening
- Improved service management with intelligent categorization
- Enhanced main.sh with better PAM configuration
- Added kernel parameter hardening
- Enhanced forensics detection
- Better documentation with troubleshooting guide
- Added point optimization guide
- Removed all emojis from documentation

**Version 3.5:**
- Added browser hardening
- Improved user audit
- Enhanced media scanner

**Version 3.0:**
- Initial comprehensive suite
- Core hardening features
- Basic automation
