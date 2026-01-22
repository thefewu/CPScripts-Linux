#!/bin/bash

# CyberPatriot Browser Hardening Script
# Detects snap vs deb Firefox, ensures Chrome/Chromium managed policy JSON is written correctly,

LOG_DIR="/root/cyberpatriot_logs"
mkdir -p "$LOG_DIR"
LOGFILE="$LOG_DIR/browser_hardening_$(date +%Y%m%d_%H%M%S).log"
APPLY=false
if [[ "$1" == "--apply" ]]; then APPLY=true; shift; fi

log() {
    echo -e "[$(date +'%T')] $1" | tee -a "$LOGFILE"
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

# Main
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

check_capabilities
log "Starting Browser Hardening..."

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
