#!/bin/bash
# =============================================================================
# UFW Blacklist Script - Block scanner/malicious networks using ipset
# https://github.com/AndreyTimoschuk/nonorkn
# =============================================================================
# Version: 1.0.0
# License: MIT
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION - Edit these values as needed
# =============================================================================

# Blacklist source (Russian government networks)
# Source: https://github.com/C24Be/AS_Network_List
BLACKLIST_URL="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist.txt"

# ipset names
IPSET_BLACKLIST="blacklist"
IPSET_WHITELIST="whitelist"

# Paths
LOG_FILE="/var/log/ufw_blacklist.log"
IPSET_SAVE_FILE="/etc/ipset.rules"
TEMP_FILE="/tmp/blacklist_subnets.txt"

# Whitelist IPs - add your trusted IPs here (servers, VPN endpoints, etc.)
# These IPs will NEVER be blocked even if they appear in blacklist
WHITELIST_IPS=(
    # Example: "1.2.3.4"
    # Example: "10.0.0.0/8"
)

# =============================================================================
# FUNCTIONS
# =============================================================================

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $*" | tee -a "$LOG_FILE"
}

# Check and install required packages
install_packages() {
    local packages_to_install=()
    
    if ! command -v ipset &> /dev/null; then
        packages_to_install+=("ipset")
    fi
    
    if ! command -v curl &> /dev/null; then
        packages_to_install+=("curl")
    fi
    
    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        log "Installing required packages: ${packages_to_install[*]}"
        apt-get update -qq
        apt-get install -y -qq "${packages_to_install[@]}"
    fi
}

# Create ipset sets
create_ipsets() {
    log "Creating ipset sets..."
    
    # Destroy old sets if exist
    ipset destroy "$IPSET_BLACKLIST" 2>/dev/null || true
    ipset destroy "$IPSET_WHITELIST" 2>/dev/null || true
    
    # Create new sets (hash:net for subnets)
    ipset create "$IPSET_BLACKLIST" hash:net maxelem 131072 -exist
    ipset create "$IPSET_WHITELIST" hash:net maxelem 65536 -exist
    
    log "ipset sets created: $IPSET_BLACKLIST, $IPSET_WHITELIST"
}

# Apply whitelist IPs
apply_whitelist() {
    log "Applying whitelist..."
    
    ipset flush "$IPSET_WHITELIST" 2>/dev/null || true
    
    local count=0
    for ip in "${WHITELIST_IPS[@]}"; do
        if [[ -n "$ip" && ! "$ip" =~ ^# ]]; then
            ipset add "$IPSET_WHITELIST" "$ip" -exist 2>/dev/null && ((count++)) || true
        fi
    done
    
    log "Whitelist applied: $count IPs"
}

# Download and apply blacklist
apply_blacklist() {
    log "Downloading blacklist from $BLACKLIST_URL..."
    
    if ! curl -sf --connect-timeout 30 --max-time 120 "$BLACKLIST_URL" -o "$TEMP_FILE"; then
        log "ERROR: Failed to download blacklist"
        return 1
    fi
    
    # Filter valid subnets (IPv4 CIDR notation)
    local valid_subnets_file="/tmp/valid_subnets.txt"
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' "$TEMP_FILE" | \
        grep -v '^#' | \
        sort -u > "$valid_subnets_file"
    
    local subnet_count
    subnet_count=$(wc -l < "$valid_subnets_file")
    log "Valid subnets found: $subnet_count"
    
    # Flush and reload blacklist using ipset restore (fast)
    ipset flush "$IPSET_BLACKLIST" 2>/dev/null || true
    
    local restore_file="/tmp/ipset_restore.txt"
    echo "create $IPSET_BLACKLIST hash:net maxelem 131072 -exist" > "$restore_file"
    while IFS= read -r subnet; do
        echo "add $IPSET_BLACKLIST $subnet -exist" >> "$restore_file"
    done < "$valid_subnets_file"
    
    if ipset restore < "$restore_file" 2>/dev/null; then
        log "Blacklist applied successfully: $subnet_count subnets"
    else
        log "ERROR: Failed to restore ipset"
        return 1
    fi
    
    rm -f "$restore_file" "$valid_subnets_file"
}

# Integrate ipset with UFW
integrate_with_ufw() {
    log "Integrating with UFW..."
    
    local before_rules="/etc/ufw/before.rules"
    local marker_start="# BEGIN IPSET BLACKLIST"
    local marker_end="# END IPSET BLACKLIST"
    local tmp_rules="/tmp/ipset_ufw_rules.txt"
    
    if [[ ! -f "$before_rules" ]]; then
        log "ERROR: $before_rules not found. Is UFW installed?"
        return 1
    fi
    
    # Remove old ipset rules
    if grep -q "$marker_start" "$before_rules"; then
        log "Removing old ipset rules..."
        sed -i "/$marker_start/,/$marker_end/d" "$before_rules"
    fi
    
    # Create rules file
    # Order matters:
    # 1. ESTABLISHED,RELATED - allow responses to OUR outgoing connections
    # 2. Whitelist - allow trusted IPs
    # 3. Blacklist - block bad IPs (only NEW incoming connections)
    cat > "$tmp_rules" << EOF

$marker_start
# Allow responses to our outgoing connections (important for APIs, updates, etc.)
-A ufw-before-input -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Whitelist - trusted IPs bypass blacklist
-A ufw-before-input -m set --match-set $IPSET_WHITELIST src -j ACCEPT
# Blacklist - block malicious networks
-A ufw-before-input -m set --match-set $IPSET_BLACKLIST src -j DROP
$marker_end
EOF
    
    # Insert after "# End required lines" or after :ufw-before-input
    if grep -q "# End required lines" "$before_rules"; then
        sed -i "/# End required lines/r $tmp_rules" "$before_rules"
        log "Rules added after '# End required lines'"
    else
        sed -i "/:ufw-before-input/r $tmp_rules" "$before_rules"
        log "Rules added after :ufw-before-input"
    fi
    
    rm -f "$tmp_rules"
    
    if grep -q "$marker_start" "$before_rules"; then
        log "UFW integration successful"
    else
        log "ERROR: UFW integration failed"
        return 1
    fi
}

# Save ipset for persistence across reboots
save_ipset() {
    log "Saving ipset rules for persistence..."
    
    ipset save > "$IPSET_SAVE_FILE" 2>/dev/null
    
    # Create systemd service for loading ipset at boot
    cat > /etc/systemd/system/ipset-load.service << 'EOF'
[Unit]
Description=Load ipset rules
Before=ufw.service
After=network-pre.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c '[[ -f /etc/ipset.rules ]] && /sbin/ipset restore < /etc/ipset.rules'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable ipset-load.service 2>/dev/null
    
    log "ipset persistence configured"
}

# Reload UFW
reload_ufw() {
    log "Reloading UFW..."
    
    if ufw reload 2>/dev/null; then
        log "UFW reloaded successfully"
    else
        log "WARNING: UFW reload failed (maybe UFW is disabled?)"
    fi
}

# Show statistics
show_stats() {
    echo ""
    echo "=========================================="
    echo "           BLACKLIST STATISTICS"
    echo "=========================================="
    echo "Blacklist entries: $(ipset list "$IPSET_BLACKLIST" 2>/dev/null | grep -c "^[0-9]" || echo 0)"
    echo "Whitelist entries: $(ipset list "$IPSET_WHITELIST" 2>/dev/null | grep -c "^[0-9]" || echo 0)"
    echo "Log file: $LOG_FILE"
    echo "=========================================="
}

# =============================================================================
# MAIN
# =============================================================================

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root"
    exit 1
fi

log "=========================================="
log "Starting UFW Blacklist update"
log "=========================================="

install_packages
create_ipsets
apply_blacklist
apply_whitelist
integrate_with_ufw
save_ipset
reload_ufw
show_stats

rm -f "$TEMP_FILE"

log "UFW Blacklist update completed"
