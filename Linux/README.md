# CyberPatriot Linux Hardening Suite

**Version:** 4.0 – Competition Ready  
**Target OS:** Ubuntu 18.04, 20.04, 22.04, 24.04  
**Last Update:** January 2026

## Quick Start

If you’re pressed for time:
1. Read the competition scenario notes/README.
2. List all authorized users and required services (web, database, file share, email).
3. Run `./user_audit.sh` and remove unauthorized users interactively.
4. Run `./service_analyzer.sh` to review services, disable unnecessary ones (be careful – never disable required ones).
5. Run `./main.sh` in interactive mode to apply core system updates and basic hardening.
6. Run `./forensics.sh` to scan for malware, backdoors, or suspicious files.
7. Run `./media_scanner.sh` to find and confirm deletion of prohibited media/games.
8. Verify critical services (apache2, mysql, ssh, ufw) are still running after changes.
9. Run `./point_optimizer.sh` for additional top scoring actions.
10. Review findings before making permanent changes. Back up configurations and user lists.

## What These Scripts Do

- **user_audit.sh**  
  Reviews all users, detects unauthorized or backdoor accounts (UID 0), audits sudo/admin lists, forces password resets, and removes unauthorized access.
- **service_analyzer.sh**  
  Audits active and enabled services; helps you avoid disabling required system and scenario services; flags security risks like FTP, Telnet, Samba, unchecked databases.
- **main.sh**  
  Applies core system hardening (system updates, password policies, PAM config, SSH+firewall hardening, network settings/fixes, file permissions, installs recommended security packages, disables hacking tools and USB storage, configures logging).
- **forensics.sh**  
  Scans for common malware, hacking tools, backdoors, unauthorized SSH keys, odd logins, unusual crontabs, suspicious hidden files, modified system binaries, odd open ports or processes.
- **media_scanner.sh**  
  Locates prohibited images, video, music, games, or large archives in user directories, downloads, desktop, trash – prompts you to confirm and delete.
- **browser_harden.sh**  
  Applies enterprise/competition security baseline to browsers (Firefox, Chrome): disables password storage, developer/incognito modes, enforces privacy.
- **advanced_hardening.sh**  
  Additional system hardening: GRUB password protection, disables IPv6/network protocols, locks down /tmp, applies AIDE file integrity monitoring, disables crash reporting, configures login banners, audits SUID/SGID binaries.
- **point_optimizer.sh**  
  High-yield, quick point wins: removes unauthorized users, audits sudoers, reviews firewall, checks for hacking tools, confirms updates applied.

## Before You Run Anything

**Warning:** These scripts make real changes to running systems.
- Disabling the wrong service, deleting the wrong user, or breaking networking will cost major points and may lock you out.
- Always work interactively and reference competition/school notes before making irreversible changes.

**Checklist:**
- List authorized users and services. Cross-check with scenario notes.
- Back up `/etc/passwd`, `/etc/shadow`, SSH configs, UFW/firewall rules.
- Keep a log of all changes.
- Run scripts in interactive mode; do not trust automatic mode unless standard desktop is confirmed.

## Script Execution Order

Recommended order for maximum points and lowest risk:

**Phase 1: Discovery**
- `user_audit.sh` (view only, no changes) – make a user list
- `service_analyzer.sh` (discover only) – note required and prohibited services
- `forensics.sh` – identify forensic findings (malware, backdoors, odd files)
- `media_scanner.sh` (view only) – list prohibited files and games.

**Phase 2: Removal and Management**
- `user_audit.sh` (interactive, fix users/groups/passwords)
- `service_analyzer.sh` (interactive, disable unnecessary services)

**Phase 3: System Hardening**
- `main.sh` (interactive, core hardening – only use auto mode for standard workstation without scenario complexity)
- `advanced_hardening.sh` (adds extra security – run after main.sh)

**Phase 4: Final Sweep**
- `browser_harden.sh`
- `media_scanner.sh` (interactive, confirm and delete files)
- `point_optimizer.sh`
- Manual quick-checks (see below)

**Phase 5: Verification**
- Check all authorized users and required services are present and running.
- Confirm no unauthorized users, open ports, or hacking tools remain.
- Review `/root/forensics_findings.txt`, `/root/prohibited_media.txt`, and other log files for remaining issues.
- Confirm firewall is active.
- Review SUID/SGID and world-writable file reports.

## Common Manual Checks

After running scripts, review:
```bash
# World writable files
sudo find / -xdev -type f -perm -0002 -ls 2>/dev/null

# Files with no owner/group
sudo find / -xdev -nouser -o -nogroup 2>/dev/null

# SUID/SGID binaries
sudo find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null

# Empty password fields
sudo awk -F: '($2 == "") {print $1}' /etc/shadow

# Listening ports
sudo ss -tulpn

# sudoers entries with NOPASSWD
grep -E -v '^#|^Defaults' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep NOPASSWD

# /etc/hosts for suspicious entries
cat /etc/hosts | grep -v "^#" | grep -v "127.0.0.1"
```

## Recovery/Troubleshooting

If points are lost or something breaks:
- Restore backups and re-add necessary users/services.
- Restart services (systemctl start service_name).
- Fix broken network/firewall by restoring configs or disabling UFW temporarily.
- Confirm SSH works after hardening changes (sshd -t for config test).
- Re-run browser and forensics scripts after major changes.

## Forensic Questions – How To Answer

Common forensic tasks:
- Find users with hidden backdoor crontabs: `for user in $(cut -d: -f1 /etc/passwd); do sudo crontab -u $user -l 2>/dev/null; done`
- Find which ports are open and what process is using them.
- Find evidence of login or password hints in home directories/logs.
- Review for recent suspicious binaries.
- Review recently installed/modified packages: `grep ' install ' /var/log/dpkg.log | tail`

## Version History

See the bottom of this README for full history and all security changes by version.

---

This documentation, scripts, and checklists are adapted from the latest Ubuntu security guidelines and CyberPatriot competitive resources.  
**Use them with caution, always reference scenario requirements, and never make automatic changes without reviewing output first.**
