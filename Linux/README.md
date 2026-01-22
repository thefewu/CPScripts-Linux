# CPScripts-Linux

**Ubuntu scripts I'm trying out for CyberPatriot, competition, and best practice Linux system hardening and auditing.**

This repo is organized for modular, safe, and competition-style use on Ubuntu systems (18.04, 20.04, 22.04, 24.04).  
Scripts are designed to be run independently—with clear separation between hardening, auditing, forensics, and media compliance checks.

---

## How to Use This Repository

**Recommended workflow:**
1. **Review scenario/README scoring requirements before anything else!**
2. **Run `main.sh`** to perform core system hardening and configuration.
3. **(Optional, but use with extreme caution) Run `advanced_hardening.sh` only if you need extra security controls.**
    - **Warning:** This script can break your system and lock out users (bootloader, network, kernel, and obscure settings).  
      You **most likely do not need to use it** for competition scoring, *unless you are absolutely certain the scenario requires it.*  
      If you do run it, make **SURE** to manually go through the code line by line and confirm that you want to make each change listed!
4. Run `browser_harden.sh` if you want to do that, otherwise, manually doing so is not too dificult. Make sure to agree with everything this script is doing first though.
5. Run `user_audit.sh`, `service_analyzer.sh`, and `forensics.sh` to generate additional security review or reporting for manual scoring.
6. Run `media_scanner.sh` if media compliance is part of your scoring or requirements.
7. Review all `/root/` log and report files after completion, before submitting image/box for scoring.

---

## Script Descriptions

### **main.sh**
- **Core hardening for Ubuntu:**  
  Updates system, configures auto-updates, hardens user accounts and passwords (inc. aging, complexity, lockout), disables guest/root logins, aggressively disables unnecessary/unused services.
- **Configures PAM, SSH, UFW firewall, sysctl (network, kernel hardening), cron/at whitelisting, critical file permissions, sudoers audit, USB/storage restrictions, installs security tools, restricts compilers and removes prohibited/unnecessary tools/games/hacking programs (incl. snap packages).**
- **Includes robust backup creation and a scoring system for tracking progress.**
- **Interactive and automatic modes available; review points in log.**
- **Now includes advanced reporting at the end (see reports below).**

### **advanced_hardening.sh**
- **Extra security moves** often needed for upper-level scoring:
  - GRUB/bootloader password protection/checks
  - IPv6 disabling/hardening (if not required)
  - /tmp and /var/tmp memory protections
  - NFS, core dump restrictions
  - Kernel/sysctl tweaks (deep privacy, logging, signal protections)
  - TCP wrappers and default account auditing

**⚠️ WARNING:**
- `advanced_hardening.sh` applies very aggressive security settings.
- **You almost never need it for CyberPatriot rounds, unless you are specifically instructed.**
- Running it can break network connectivity, cause boot failures, lock out legitimate users, and more.
- **BEFORE** you run it:
    - Review every line of code in `advanced_hardening.sh` and verify you want every change.
    - Confirm scenario requirements.
    - Expect possible breakage!

### **user_audit.sh**
- **User and group audit:**  
  Reviews all users and groups for unauthorized, backdoor, or UID 0 (“root-like”) accounts, audits admin/sudo users, optionally forces password reset, and warns/removes unauthorized access.

### **service_analyzer.sh**
- **Active/enabled services audit:**  
  Lists all running/enabled services for safe review so you don’t disable needed competition/scenario services by accident; especially flags FTP, SMB, databases, Telnet, and other risky/bonus-point services.

### **forensics.sh**
- **Comprehensive security and malware check:**  
  Scans for suspicious/hidden files, backdoors, unauthorized SSH keys, odd logins/cron jobs, modified critical system binaries, unusual listening ports and processes, loaded kernel modules, recent changes, and more.
- **Runs rootkit checks (`rkhunter`, `chkrootkit`) and generates reports.**

### **media_scanner.sh**
- **Prohibited/inappropriate media scanner:**  
  Flags images, videos, audio, or other forbidden media according to competition/policy. Run after the core hardening and before final review if required.

---

## Advanced Automated Reporting (added to `main.sh`)

After running `main.sh`, you will find advanced audit reports in `/root/` for additional scoring/manual review:

- `/root/sudoers_nopasswd.txt` – Sudo lines allowing passwordless execution (security risk)
- `/root/world_writable_files.txt` – World-writable file scan (backgrounded)
- `/root/rhosts_files.txt` – .rhosts files found/removed
- `/root/netrc_files.txt` – .netrc files found
- `/root/suid_sgid_files.txt` – SUID/SGID binaries on system
- `/root/login_shell_users.txt` – Users with active login shells (may be backdoors)
- `/root/listening_ports.txt` – All listening ports/services
- `/root/ssh_auth_keys.txt` – Authorized SSH keys for all users
- `/root/systemd_services.txt` – Executable systemd/unit scripts
- `/root/rc.local.txt` – rc.local startup script contents
- `/root/all_user_crontabs.txt` – All user crontab jobs
- `/root/shadow_group.txt` – Shadow group membership
- `/root/valid_shells.txt` – Shells listed in /etc/shells
- `/root/insecure_home_dirs.txt` – Home directories with weak permissions
- `/root/sudoers_lint.txt` – `visudo -c` output for syntax errors
- `/root/rkhunter_report.txt` – Rootkit report
- `/root/chkrootkit_report.txt` – Malware/rootkit scan report

---

## Compatibility and Safety

- **All scripts are modular and independent.**  
  Run any in any order; outputs do not collide and files are not overwritten except for expected logs and reports.
- **No script auto-modifies other scripts’ output/configs.**  
  Vulnerable changes (like user removal/unlocking/disabling services) are **always logged/reported before modification**—review reports before making further changes!
- **Backups automatically created before configuration changes.**  
  See `main.sh` for backup details.

## Additional Resources

- [Marshall Cyber Club Ultimate Linux Checklist (PDF)](https://marshallcyberclub.github.io/resources/Ultimate%20Linux%20Checklist.pdf)
- [SANS Linux Security Checklist (PDF)](https://www.sans.org/media/score/checklists/LinuxCheatsheet_2.pdf)
- [decalage2/awesome-security-hardening](https://github.com/decalage2/awesome-security-hardening) – up-to-date links to Linux hardening checklists, guides, and exam resources
- [How to Win CyberPatriot (blog)](https://akshayrohatgi.com/blog/posts/How-To-Win-CyberPatriot/)
- [Sample competition scripts](https://github.com/tanav-malhotra/cyberpatriot-scripts/tree/main/linux), [Other script repos](https://github.com/BiermanM/CyberPatriot-Scripts), [More](https://github.com/Exaphis/cyberpatriot-ubuntu-script)

## Quick Start

```sh
sudo bash main.sh         # Choose your hardening mode (full auto/interactive/quick)
sudo bash advanced_hardening.sh   # (OPTIONAL, ONLY IF YOU KNOW WHAT YOU ARE DOING)
sudo bash forensics.sh    # Comprehensive audit/forensics scan
sudo bash user_audit.sh   # Advanced user/group audit
sudo bash service_analyzer.sh     # Service review/report
sudo bash media_scanner.sh        # Media compliance check
```

## After Running Scripts

- **Review all `/root/` logs and reports before scoring or submitting!**
- **Check README for competition requirements—DO NOT disable required/bonus services.**
- **If unsure, leave questionable users/files/services in place and document in your report.**

---
