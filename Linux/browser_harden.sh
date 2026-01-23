#!/bin/bash

# CyberPatriot Browser Hardening Script
# Detects snap vs deb Firefox, ensures Chrome/Chromium managed policy JSON is written correctly.
# Also supports migration between snap and deb Firefox installations

LOG_DIR="/root/cyberpatriot_logs"
mkdir -p "$LOG_DIR"
LOGFILE="$LOG_DIR/browser_hardening_$(date +%Y%m%d_%H%M%S).log"
APPLY=false
if [[ "$1" == "--apply" ]]; then APPLY=true; shift; fi

log() {
    echo -e "[$(date +'%T')] $1" | tee -a "$LOGFILE"
}

warn() {
    echo -e "[$(date +'%T')] WARNING: $1" | tee -a "$LOGFILE"
}

check_capabilities() {
    log "Checking environment capabilities..."
    if command -v snap &>/dev/null; then
        log "snap present"
        SNAP=true
    else
        SNAP=false
    fi
    if command -v ss &>/dev/null; then
        log "ss present"
    fi
    if command -v rkhunter &>/dev/null; then
        log "rkhunter present"
    fi
    echo
    log "This script will apply Enterprise policies to browsers. Destructive changes require --apply."
}

backup_firefox_profile() {
    log "Backing up Firefox profiles..."
    local BACKUP_DIR="/root/firefox_profile_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # Backup both snap and regular profile locations
    if [ -d "$HOME/.mozilla/firefox" ]; then
        cp -r "$HOME/.mozilla/firefox" "$BACKUP_DIR/mozilla_firefox" 2>/dev/null
        log "Backed up ~/.mozilla/firefox to $BACKUP_DIR"
    fi
    if [ -d "$HOME/snap/firefox/common/.mozilla/firefox" ]; then
        cp -r "$HOME/snap/firefox/common/.mozilla/firefox" "$BACKUP_DIR/snap_firefox" 2>/dev/null
        log "Backed up snap Firefox profile to $BACKUP_DIR"
    fi
    
    echo "$BACKUP_DIR"
}

migrate_snap_to_deb() {
    log "=== Starting migration from snap Firefox to deb (PPA) Firefox ==="
    
    if ! snap list firefox &>/dev/null; then
        warn "Snap Firefox is not installed. Nothing to migrate."
        return 1
    fi
    
    local BACKUP_DIR=$(backup_firefox_profile)
    
    # Remove snap Firefox
    log "Removing snap Firefox..."
    snap remove firefox
    if [ $? -ne 0 ]; then
        warn "Failed to remove snap Firefox"
        return 1
    fi
    
    # Add Mozilla PPA and install Firefox deb
    log "Adding Mozilla PPA..."
    add-apt-repository -y ppa:mozillateam/ppa
    
    # Create pin file to prefer PPA over snap
    log "Configuring APT to prefer Mozilla PPA..."
    cat > /etc/apt/preferences.d/mozilla-firefox <<'EOF'
Package: *
Pin: release o=LP-PPA-mozillateam
Pin-Priority: 950
EOF
    
    log "Installing Firefox from PPA..."
    apt update
    apt install -y firefox
    
    if [ $? -eq 0 ]; then
        log "Successfully migrated to deb Firefox"
        log "Profile backup location: $BACKUP_DIR"
        
        # Copy snap profile to standard location if it doesn't exist
        if [ -d "$BACKUP_DIR/snap_firefox" ] && [ ! -d "$HOME/.mozilla/firefox" ]; then
            mkdir -p "$HOME/.mozilla"
            cp -r "$BACKUP_DIR/snap_firefox" "$HOME/.mozilla/firefox"
            log "Restored Firefox profile from snap backup"
        fi
        
        return 0
    else
        warn "Failed to install deb Firefox"
        return 1
    fi
}

migrate_deb_to_snap() {
    log "=== Starting migration from deb Firefox to snap Firefox ==="
    
    if ! dpkg -l | grep -q "^ii.*firefox"; then
        warn "Deb Firefox is not installed. Nothing to migrate."
        return 1
    fi
    
    local BACKUP_DIR=$(backup_firefox_profile)
    
    # Remove deb Firefox and PPA
    log "Removing deb Firefox..."
    apt remove -y firefox
    apt autoremove -y
    
    if [ -f /etc/apt/preferences.d/mozilla-firefox ]; then
        rm /etc/apt/preferences.d/mozilla-firefox
        log "Removed Mozilla PPA preferences"
    fi
    
    if grep -q "mozillateam/ppa" /etc/apt/sources.list.d/*.list 2>/dev/null; then
        add-apt-repository -y --remove ppa:mozillateam/ppa
        log "Removed Mozilla PPA"
    fi
    
    # Install snap Firefox
    log "Installing Firefox snap..."
    snap install firefox
    
    if [ $? -eq 0 ]; then
        log "Successfully migrated to snap Firefox"
        log "Profile backup location: $BACKUP_DIR"
        
        # Copy standard profile to snap location if it doesn't exist
        if [ -d "$BACKUP_DIR/mozilla_firefox" ] && [ ! -d "$HOME/snap/firefox/common/.mozilla/firefox" ]; then
            mkdir -p "$HOME/snap/firefox/common/.mozilla"
            cp -r "$BACKUP_DIR/mozilla_firefox" "$HOME/snap/firefox/common/.mozilla/firefox"
            log "Restored Firefox profile from deb backup"
        fi
        
        return 0
    else
        warn "Failed to install snap Firefox"
        return 1
    fi
}

apply_firefox_policies_deb() {
    local INSTALL_DIR="/usr/lib/firefox/distribution"
    mkdir -p "$INSTALL_DIR"
    cat > "$INSTALL_DIR/policies.json" <<'EOF'
{
  "policies": {
    "DisableAppUpdate": false,
    "BlockAboutConfig": true,
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisablePocket": true,
    "DisablePrivateBrowsing": false,
    "DisableFormHistory": false,
    "OfferToSaveLogins": false,
    "PasswordManagerEnabled": false,
    "PopupBlocking": {
        "Default": true,
        "Locked": true
    },
    "Cookies": {
        "Behavior": "reject-third-party",
        "Locked": true
    },
    "SanitizeOnShutdown": {
        "Cache": true,
        "Cookies": true,
        "History": true,
        "Sessions": true,
        "SiteSettings": true,
        "OfflineApps": true,
        "Locked": true
    },
    "Homepage": {
        "URL": "about:blank",
        "Locked": false
    }
  }
}
EOF
    log "Firefox (deb) policies written to $INSTALL_DIR/policies.json"
}

apply_firefox_policies_snap() {
    # For snap-based Firefox the distribution directory is read-only; use /etc/firefox or per-user policies where supported.
    local TARGET_DIR="/etc/firefox"
    mkdir -p "$TARGET_DIR"
    cat > "$TARGET_DIR/policies.json" <<'EOF'
{
  "policies": {
    "DisableAppUpdate": false,
    "BlockAboutConfig": true,
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisablePocket": true,
    "OfferToSaveLogins": false,
    "PasswordManagerEnabled": false,
    "PopupBlocking": {
        "Default": true,
        "Locked": true
    },
    "Cookies": {
        "Behavior": "reject-third-party",
        "Locked": true
    },
    "SanitizeOnShutdown": {
        "Cache": true,
        "Cookies": true,
        "History": true,
        "Sessions": true,
        "SiteSettings": true,
        "OfflineApps": true,
        "Locked": true
    },
    "Homepage": {
        "URL": "about:blank",
        "Locked": false
    }
  }
}
EOF
    log "Firefox (snap) policies written to $TARGET_DIR/policies.json (snap may ignore some locations; verify snap documentation)"
}

apply_chrome_policies() {
    # Ensure valid keys; remove DownloadDirectory entry which uses invalid placeholder
    local JSON='{
  "PasswordManagerEnabled": false,
  "BrowserSignin": 0,
  "AllowOutdatedPlugins": false,
  "AlwaysAuthorizePlugins": false,
  "BlockThirdPartyCookies": true,
  "DeveloperToolsDisabled": true,
  "IncognitoModeAvailability": 1,
  "SafeBrowsingEnabled": true,
  "MetricsReportingEnabled": false,
  "ShowHomeButton": true,
  "HomepageLocation": "about:blank",
  "SyncDisabled": true,
  "SavingBrowserHistoryDisabled": false,
  "DefaultPopupsSetting": 2
}'
    mkdir -p /etc/opt/chrome/policies/managed /etc/chromium/policies/managed
    echo "$JSON" > /etc/opt/chrome/policies/managed/cyberpatriot_hardening.json
    echo "$JSON" > /etc/chromium/policies/managed/cyberpatriot_hardening.json
    log "Chrome/Chromium managed policies applied to /etc/opt/chrome/policies/managed and /etc/chromium/policies/managed"
}

show_migration_menu() {
    echo
    log "=== Firefox Migration Options ==="
    echo "1) Migrate from snap Firefox to deb (PPA) Firefox"
    echo "2) Migrate from deb Firefox to snap Firefox"
    echo "3) Skip migration"
    echo
    read -p "Select option (1-3): " -n 1 -r
    echo
    
    case $REPLY in
        1)
            if [[ "$APPLY" = true ]] || ( read -p "Proceed with snap->deb migration? (y/N): " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] ); then
                migrate_snap_to_deb
            fi
            ;;
        2)
            if [[ "$APPLY" = true ]] || ( read -p "Proceed with deb->snap migration? (y/N): " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] ); then
                migrate_deb_to_snap
            fi
            ;;
        3)
            log "Migration skipped"
            ;;
        *)
            warn "Invalid option, skipping migration"
            ;;
    esac
}

# Main
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

check_capabilities
log "Starting Browser Hardening..."

# Show migration menu first
show_migration_menu

echo
log "=== Applying Browser Policies ==="

# FIREFOX
if $SNAP && snap list firefox &>/dev/null; then
    log "Firefox installed as snap - applying snap-friendly policy location"
    if [[ "$APPLY" = true ]] || ( read -p "Write Firefox snap policy now? (y/N): " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] ); then
        apply_firefox_policies_snap
    else
        warn "Firefox policy write skipped (use --apply to automate)"
    fi
elif command -v firefox &>/dev/null; then
    log "Firefox (packaged) detected"
    if [[ "$APPLY" = true ]] || ( read -p "Write Firefox policy now? (y/N): " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] ); then
        apply_firefox_policies_deb
    else
        warn "Firefox policy write skipped (use --apply to automate)"
    fi
else
    log "Firefox not detected"
fi

# CHROME/CHROMIUM
if [ -d "/etc/opt/chrome" ] || [ -d "/etc/chromium" ]; then
    if [[ "$APPLY" = true ]] || ( read -p "Write Chrome/Chromium managed policies now? (y/N): " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] ); then
        apply_chrome_policies
    else
        warn "Chrome policy write skipped (use --apply to automate)"
    fi
else
    log "No Chrome/Chromium managed policy directories found"
fi

log "Browser hardening complete. Restart browsers to see effects."
