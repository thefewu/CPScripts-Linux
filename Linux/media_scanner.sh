#!/bin/bash

# CyberPatriot Prohibited Media Scanner
# Scans for inappropriate images, videos, audio, and other media files
# Remember to check README to see what's actually allowed!

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOGFILE="media_scan_$(date +%Y%m%d_%H%M%S).log"
FINDINGS="/root/prohibited_media.txt"

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOGFILE"
}

warn() {
    echo -e "${YELLOW}[FOUND]${NC} $1" | tee -a "$LOGFILE" | tee -a "$FINDINGS"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
}

banner() {
    clear
    echo -e "${YELLOW}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║        CyberPatriot Prohibited Media Scanner          ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

scan_images() {
    log "Scanning for image files..."
    
    # Common image file extensions
    EXTENSIONS=("jpg" "jpeg" "png" "gif" "bmp" "tiff" "webp" "svg" "ico")
    
    for ext in "${EXTENSIONS[@]}"; do
        # Search /home for these file types
        find /home -type f -iname "*.$ext" 2>/dev/null | while read file; do
            size=$(stat -c%s "$file")
            # Only report files larger than 10KB to avoid tiny icons/thumbnails
            if [ $size -gt 10240 ]; then
                warn "IMAGE: $file ($(du -h "$file" | cut -f1))"
            fi
        done
    done
}

scan_videos() {
    log "Scanning for video files..."
    
    # Video file extensions - these are usually big and prohibited
    EXTENSIONS=("mp4" "avi" "mkv" "mov" "wmv" "flv" "webm" "m4v" "mpg" "mpeg")
    
    for ext in "${EXTENSIONS[@]}"; do
        find /home -type f -iname "*.$ext" 2>/dev/null | while read file; do
            warn "VIDEO: $file ($(du -h "$file" | cut -f1))"
        done
    done
}

scan_audio() {
    log "Scanning for audio files..."
    
    # Audio file extensions
    EXTENSIONS=("mp3" "wav" "flac" "aac" "ogg" "wma" "m4a" "opus")
    
    for ext in "${EXTENSIONS[@]}"; do
        find /home -type f -iname "*.$ext" 2>/dev/null | while read file; do
            size=$(stat -c%s "$file")
            # Only report files > 100KB (skip system sounds)
            if [ $size -gt 102400 ]; then
                warn "AUDIO: $file ($(du -h "$file" | cut -f1))"
            fi
        done
    done
}

scan_archives() {
    log "Scanning for archive files (may contain hidden media)..."
    
    # Archive files can hide prohibited content
    EXTENSIONS=("zip" "rar" "7z" "tar" "gz" "bz2" "xz")
    
    for ext in "${EXTENSIONS[@]}"; do
        find /home -type f -iname "*.$ext" 2>/dev/null | while read file; do
            size=$(stat -c%s "$file")
            # Only report large archives (> 1MB) since small ones are probably just config backups
            if [ $size -gt 1048576 ]; then
                warn "ARCHIVE: $file ($(du -h "$file" | cut -f1))"
            fi
        done
    done
}

scan_games() {
    log "Scanning for game files and executables..."
    
    # Common game directories - these are usually not allowed in CP
    GAME_DIRS=(
        ".steam"
        ".minecraft"
        "Games"
        ".wine"
        ".local/share/Steam"
    )
    
    for dir in "${GAME_DIRS[@]}"; do
        find /home -type d -name "$dir" 2>/dev/null | while read gamedir; do
            warn "GAME DIRECTORY: $gamedir ($(du -sh "$gamedir" 2>/dev/null | cut -f1))"
        done
    done
    
    # Windows executables are also suspicious on Linux
    find /home -type f -iname "*.exe" 2>/dev/null | while read file; do
        warn "WINDOWS EXECUTABLE: $file"
    done
}

scan_suspicious_filenames() {
    log "Scanning for files with suspicious names..."
    
    # Keywords that might indicate inappropriate content or hacking tools
    KEYWORDS=(
        "*inappropriate*"
        "*adult*"
        "*xxx*"
        "*porn*"
        "*hack*"
        "*crack*"
        "*warez*"
        "*pirate*"
        "*torrent*"
    )
    
    for keyword in "${KEYWORDS[@]}"; do
        find /home -type f -iname "$keyword" 2>/dev/null | while read file; do
            warn "SUSPICIOUS FILENAME: $file"
        done
    done
}

scan_downloads() {
    log "Scanning Downloads directories..."
    
    # Downloads folders are common places for prohibited files
    find /home -type d -name "Downloads" 2>/dev/null | while read dldir; do
        if [ -d "$dldir" ]; then
            log "Checking: $dldir"
            find "$dldir" -type f 2>/dev/null | while read file; do
                ext="${file##*.}"
                # Check if file extension matches media types
                case "${ext,,}" in  # ${ext,,} converts to lowercase
                    jpg|jpeg|png|gif|mp4|avi|mkv|mp3|exe|zip|rar)
                        warn "DOWNLOAD: $file ($(du -h "$file" | cut -f1))"
                        ;;
                esac
            done
        fi
    done
}

scan_desktop() {
    log "Scanning Desktop directories..."
    
    # Check Desktop folders too
    find /home -type d -name "Desktop" 2>/dev/null | while read desktop; do
        if [ -d "$desktop" ]; then
            log "Checking: $desktop"
            find "$desktop" -type f 2>/dev/null | while read file; do
                ext="${file##*.}"
                case "${ext,,}" in
                    jpg|jpeg|png|gif|mp4|avi|mkv|mp3|exe)
                        warn "DESKTOP FILE: $file"
                        ;;
                esac
            done
        fi
    done
}

scan_large_files() {
    log "Scanning for unusually large files (>100MB)..."
    
    # Large files are suspicious - could be videos, games, etc.
    find /home -type f -size +100M 2>/dev/null | while read file; do
        warn "LARGE FILE: $file ($(du -h "$file" | cut -f1))"
    done
}

scan_browser_downloads() {
    log "Scanning browser download history..."
    
    # Firefox stores downloads history in places.sqlite
    find /home -path "*/.mozilla/firefox/*/places.sqlite" 2>/dev/null | while read db; do
        if command -v sqlite3 &> /dev/null; then
            warn "Firefox downloads database found: $db"
        fi
    done
    
    # Chrome history database
    find /home -path "*/.config/google-chrome/*/History" 2>/dev/null | while read db; do
        warn "Chrome history database found: $db"
    done
    
    # Chromium history
    find /home -path "*/.config/chromium/*/History" 2>/dev/null | while read db; do
        warn "Chromium history database found: $db"
    done
}

check_recycle_bin() {
    log "Checking Trash/Recycle bins..."
    
    # Don't forget to check the trash!
    find /home -type d -path "*/.local/share/Trash/files" 2>/dev/null | while read trash; do
        if [ -d "$trash" ]; then
            file_count=$(find "$trash" -type f 2>/dev/null | wc -l)
            if [ $file_count -gt 0 ]; then
                warn "TRASH DIRECTORY: $trash ($file_count files)"
                # Show first 20 files in trash
                find "$trash" -type f 2>/dev/null | head -20 | while read file; do
                    warn "  - $(basename "$file")"
                done
            fi
        fi
    done
}

generate_summary() {
    log "Generating summary report..."
    
    echo "═══════════════════════════════════════════════════════" | tee -a "$FINDINGS"
    echo "PROHIBITED MEDIA SCAN SUMMARY" | tee -a "$FINDINGS"
    echo "Generated: $(date)" | tee -a "$FINDINGS"
    echo "═══════════════════════════════════════════════════════" | tee -a "$FINDINGS"
    echo | tee -a "$FINDINGS"
    
    # Count how many of each type we found
    echo "IMAGE FILES FOUND:" | tee -a "$FINDINGS"
    grep "IMAGE:" "$FINDINGS" 2>/dev/null | wc -l | tee -a "$FINDINGS"
    echo | tee -a "$FINDINGS"
    
    echo "VIDEO FILES FOUND:" | tee -a "$FINDINGS"
    grep "VIDEO:" "$FINDINGS" 2>/dev/null | wc -l | tee -a "$FINDINGS"
    echo | tee -a "$FINDINGS"
    
    echo "AUDIO FILES FOUND:" | tee -a "$FINDINGS"
    grep "AUDIO:" "$FINDINGS" 2>/dev/null | wc -l | tee -a "$FINDINGS"
    echo | tee -a "$FINDINGS"
    
    echo "═══════════════════════════════════════════════════════" | tee -a "$FINDINGS"
}

interactive_delete() {
    echo
    read -p "Do you want to interactively review and delete files? (y/n): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Go through each media file and ask to delete
        grep -E "IMAGE:|VIDEO:|AUDIO:" "$FINDINGS" | while read line; do
            # Extract the file path from the line
            filepath=$(echo "$line" | sed 's/.*: //' | sed 's/ (.*//')
            
            if [ -f "$filepath" ]; then
                echo
                echo -e "${YELLOW}File: $filepath${NC}"
                echo "Type: $(file "$filepath")"
                echo "Size: $(du -h "$filepath" | cut -f1)"
                echo
                
                read -p "Delete this file? (y/n/q): " -n 1 -r
                echo
                
                case $REPLY in
                    [Yy])
                        rm -f "$filepath" && log "DELETED: $filepath"
                        ;;
                    [Qq])
                        log "Interactive deletion cancelled by user"
                        break
                        ;;
                    *)
                        log "KEPT: $filepath"
                        ;;
                esac
            fi
        done
    fi
}

# Main execution
main() {
    banner
    check_root
    
    # Clear findings file at start
    > "$FINDINGS"
    
    log "Starting prohibited media scan..."
    log "This may take several minutes depending on filesystem size..."
    echo
    
    scan_images
    scan_videos
    scan_audio
    scan_archives
    scan_games
    scan_suspicious_filenames
    scan_downloads
    scan_desktop
    scan_large_files
    scan_browser_downloads
    check_recycle_bin
    
    generate_summary
    
    echo
    log "════════════════════════════════════════════════════════"
    log "Media scan complete!"
    log "Results saved to: $FINDINGS"
    log "Log file: $LOGFILE"
    log "════════════════════════════════════════════════════════"
    echo
    
    echo -e "${YELLOW}IMPORTANT:${NC}"
    echo "1. Review $FINDINGS carefully"
    echo "2. Check README to see if any media is ALLOWED"
    echo "3. Delete prohibited files according to scenario"
    echo "4. Some files may be legitimate - use judgment"
    echo
    
    interactive_delete
}

main
