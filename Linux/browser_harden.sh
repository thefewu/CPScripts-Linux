#!/bin/bash

# CyberPatriot Browser Hardening Script
# Hardens Firefox using Enterprise Policies (most reliable method for Ubuntu 18.04+)
# Also attempts basic Chrome hardening

LOGFILE="browser_hardening.log"

log() {
    echo -e "[$(date +'%T')] $1" | tee -a "$LOGFILE"
}

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1 
fi

log "Starting Browser Hardening..."

# --- FIREFOX HARDENING ---
if command -v firefox &> /dev/null; then
    log "Firefox detected. Applying Enterprise Policies..."
    
    # Create the distribution directory if it doesn't exist
    INSTALL_DIR="/usr/lib/firefox/distribution"
    mkdir -p "$INSTALL_DIR"
    
    # Write policies.json
    # This forces settings regardless of what the user tries to change
    cat > "$INSTALL_DIR/policies.json" <<EOF
{
  "policies": {
    "DisableAppUpdate": false,
    "AppUpdateURL": "https://www.mozilla.org/en-US/firefox/new/",
    "BlockAboutConfig": true,
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisablePocket": true,
    "DisablePrivateBrowsing": true,
    "DisableFormHistory": true,
    "OfferToSaveLogins": false,
    "PasswordManagerEnabled": false,
    "PopupBlocking": {
        "Default": true,
        "Locked": true
    },
    "Cookies": {
        "Behavior": "reject-foreign",
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
    log "Firefox policies applied to $INSTALL_DIR/policies.json"
else
    log "Firefox not found."
fi

# --- CHROME/CHROMIUM HARDENING ---
# Chrome uses "Managed Policies" via JSON files in /etc/opt/chrome/policies/managed/

check_chrome_variant() {
    if [ -d "/etc/opt/chrome" ] || [ -d "/etc/chromium" ]; then
        return 0
    fi
    return 1
}

if check_chrome_variant; then
    log "Chrome/Chromium directories detected. Applying policies..."
    
    # Ensure directories exist
    mkdir -p /etc/opt/chrome/policies/managed
    mkdir -p /etc/chromium/policies/managed
    
    POLICY_CONTENT='{
        "PasswordManagerEnabled": false,
        "BrowserSignin": 0,
        "AllowOutdatedPlugins": false,
        "AlwaysAuthorizePlugins": false,
        "BlockThirdPartyCookies": true,
        "DeveloperToolsDisabled": true,
        "DownloadDirectory": "${home}/Downloads",
        "IncognitoModeAvailability": 1,
        "SafeBrowsingEnabled": true,
        "MetricsReportingEnabled": false,
        "ShowHomeButton": true,
        "HomepageLocation": "about:blank",
        "SyncDisabled": true,
        "SavingBrowserHistoryDisabled": false,
        "DefaultPopupsSetting": 2
    }'
    
    echo "$POLICY_CONTENT" > /etc/opt/chrome/policies/managed/cyberpatriot_hardening.json
    echo "$POLICY_CONTENT" > /etc/chromium/policies/managed/cyberpatriot_hardening.json
    
    log "Chrome/Chromium managed policies applied."
else
    log "No Chrome/Chromium config directories found."
fi

log "Browser hardening complete. Restart browsers to see effects."
