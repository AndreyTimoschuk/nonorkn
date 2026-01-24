#!/bin/bash

# =============================================================================
# UFW + IPSET Blacklist - Block unwanted networks
# https://github.com/AndreyTimoschuk/nonorkn
# =============================================================================
# Integrates with UFW via /etc/ufw/before.rules
# Source: https://github.com/C24Be/AS_Network_List
# =============================================================================

# === QUICK DIAGNOSTICS ===
# 1. Check ipset sets
# ipset list whitelist | head -5
# ipset list blacklist | head -5
# echo "Whitelist: $(ipset list whitelist | grep -c '^[0-9]') | Blacklist: $(ipset list blacklist | grep -c '^[0-9]')"
#
# 2. Check rules in UFW before.rules
# grep -A5 "IPSET BLACKLIST" /etc/ufw/before.rules
#
# 3. Check iptables rules (order matters!)
# iptables -L ufw-before-input -v -n --line-numbers | head -10
#
# 4. Check specific IP
# ipset test whitelist 1.2.3.4
# ipset test blacklist 1.2.3.4
#
# 5. Check systemd service
# systemctl status ipset-load.service
#
# 6. View recent blocks
# tail -20 /var/log/ufw.log | grep BLOCK
#
# 7. Check ipset persistence
# ls -lh /etc/ipset.rules
#
# 8. UFW status
# ufw status verbose | head -5

# =============================================================================
# CONFIGURATION
# =============================================================================

# Blacklist URL (Russian government networks)
URL="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist.txt"

# Paths
TEMP_FILE="/tmp/blacklist_subnets.txt"
LOG_FILE="/var/log/ufw_blacklist.log"
IPSET_BLACKLIST="blacklist"
IPSET_WHITELIST="whitelist"
IPSET_SAVE_FILE="/etc/ipset.rules"
IPSET_LOAD_SCRIPT="/usr/local/bin/load-ipset-blacklist.sh"

# =============================================================================
# WHITELIST - IPs that should ALWAYS be allowed
# Add your trusted IPs here (home IP, office, VPN servers, etc.)
# =============================================================================
WHITELIST_IPS=(
    # Example: "1.2.3.4"
    # Example: "10.0.0.0/8"
)

# Check root
[[ $EUID -ne 0 ]] && { echo "Error: must be run as root (sudo)" | tee -a "$LOG_FILE"; exit 1; }

# Install required packages
install_packages() {
    echo "Checking required packages..." | tee -a "$LOG_FILE"
    
    if ! command -v ipset &> /dev/null; then
        echo "Installing ipset..." | tee -a "$LOG_FILE"
        apt-get update >> "$LOG_FILE" 2>&1
        apt-get install -y ipset >> "$LOG_FILE" 2>&1
    fi
}

# Create ipset sets
create_ipsets() {
    echo "Creating ipset sets..." | tee -a "$LOG_FILE"
    
    # Create sets if not exist (|| true ignores "already exists" error)
    ipset create "$IPSET_WHITELIST" hash:net family inet hashsize 1024 maxelem 65536 2>/dev/null || true
    ipset create "$IPSET_BLACKLIST" hash:net family inet hashsize 65536 maxelem 1000000 2>/dev/null || true
    
    echo "ipset sets created/verified" | tee -a "$LOG_FILE"
}

# Apply whitelist IPs
apply_whitelist() {
    echo "Applying whitelist IPs..." | tee -a "$LOG_FILE"
    
    local added_count=0
    
    # Flush whitelist
    ipset flush "$IPSET_WHITELIST" 2>/dev/null
    
    for ip in "${WHITELIST_IPS[@]}"; do
        [[ -z "$ip" ]] && continue
        
        if ipset add "$IPSET_WHITELIST" "$ip" 2>/dev/null; then
            ((added_count++))
        fi
    done
    
    echo "Whitelist: added $added_count IPs" | tee -a "$LOG_FILE"
}

# Download and apply blacklist
apply_blacklist() {
    echo "Downloading blacklist..." | tee -a "$LOG_FILE"
    
    if ! curl -s --connect-timeout 10 --max-time 60 --retry 3 "$URL" -o "$TEMP_FILE" 2>> "$LOG_FILE"; then
        echo "Error: failed to download blacklist" | tee -a "$LOG_FILE"
        exit 1
    fi
    
    [[ ! -s "$TEMP_FILE" ]] && { echo "Error: downloaded file is empty" | tee -a "$LOG_FILE"; exit 1; }

    echo "Validating subnets..." | tee -a "$LOG_FILE"
    local valid_subnets_file="/tmp/blacklist_valid.txt"
    
    # Filter valid IPv4 subnets
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' "$TEMP_FILE" | sort -u > "$valid_subnets_file"
    
    local total=$(wc -l < "$valid_subnets_file")
    [[ "$total" -eq 0 ]] && { echo "Error: no valid subnets found" | tee -a "$LOG_FILE"; exit 1; }
    
    echo "Found $total valid subnets" | tee -a "$LOG_FILE"
    
    # Flush blacklist
    ipset flush "$IPSET_BLACKLIST" 2>/dev/null
    
    # Create restore file
    echo "Loading subnets into ipset..." | tee -a "$LOG_FILE"
    local restore_file="/tmp/ipset_restore.txt"
    > "$restore_file"
    
    while IFS= read -r subnet; do
        [[ -z "$subnet" ]] && continue
        echo "add $IPSET_BLACKLIST $subnet" >> "$restore_file"
    done < "$valid_subnets_file"
    
    # Load all rules at once (-! ignores duplicates)
    if ipset restore -! < "$restore_file" 2>> "$LOG_FILE"; then
        echo "Blacklist: loaded $total subnets" | tee -a "$LOG_FILE"
    else
        echo "Warning: some subnets failed to load (see log)" | tee -a "$LOG_FILE"
    fi
    
    rm -f "$restore_file" "$valid_subnets_file"
}

# Integrate with UFW via before.rules
integrate_with_ufw() {
    echo "Integrating with UFW..." | tee -a "$LOG_FILE"
    
    local before_rules="/etc/ufw/before.rules"
    local marker_start="# BEGIN IPSET BLACKLIST"
    local marker_end="# END IPSET BLACKLIST"
    local tmp_rules="/tmp/ipset_ufw_rules.txt"
    
    if [[ ! -f "$before_rules" ]]; then
        echo "Error: $before_rules not found. Is UFW installed?" | tee -a "$LOG_FILE"
        return 1
    fi
    
    # Remove diagnostic logging rules if any
    iptables -D ufw-before-input -m set --match-set "$IPSET_BLACKLIST" src -j LOG --log-prefix "[BLACKLIST-BLOCK] " --log-level 4 2>/dev/null
    
    # Remove old ipset rules
    if grep -q "$marker_start" "$before_rules"; then
        echo "Removing old ipset rules..." | tee -a "$LOG_FILE"
        sed -i "/$marker_start/,/$marker_end/d" "$before_rules"
    fi
    
    # Create rules file
    # Order matters:
    # 1. ESTABLISHED,RELATED - allow responses to OUR outgoing connections
    # 2. Whitelist - allow trusted IPs
    # 3. Blacklist - block bad IPs (only NEW connections)
    cat > "$tmp_rules" << EOF

$marker_start
# ESTABLISHED/RELATED - allow responses to our outgoing connections
# This allows connecting TO servers in blacklist (APIs, CDNs, etc.)
-A ufw-before-input -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Whitelist - allow trusted IPs (before blacklist!)
-A ufw-before-input -m set --match-set $IPSET_WHITELIST src -j ACCEPT
# Blacklist - block NEW incoming connections from blacklist
-A ufw-before-input -m set --match-set $IPSET_BLACKLIST src -j DROP
$marker_end
EOF
    
    # Insert rules after "# End required lines"
    if grep -q "# End required lines" "$before_rules"; then
        sed -i "/# End required lines/r $tmp_rules" "$before_rules"
        echo "Rules added after '# End required lines'" | tee -a "$LOG_FILE"
    else
        sed -i "/:ufw-before-input/r $tmp_rules" "$before_rules"
        echo "Rules added after :ufw-before-input" | tee -a "$LOG_FILE"
    fi
    
    rm -f "$tmp_rules"
    
    if grep -q "$marker_start" "$before_rules"; then
        echo "UFW integration successful" | tee -a "$LOG_FILE"
    else
        echo "ERROR: UFW integration failed!" | tee -a "$LOG_FILE"
        return 1
    fi
}

# Save ipset for persistence
save_ipset() {
    echo "Saving ipset for persistence..." | tee -a "$LOG_FILE"
    
    # Save current ipset
    ipset save > "$IPSET_SAVE_FILE" 2>/dev/null
    
    # Create load script
    cat > "$IPSET_LOAD_SCRIPT" << 'LOADSCRIPT'
#!/bin/bash
# Load ipset at system startup
IPSET_SAVE_FILE="/etc/ipset.rules"
[[ -f "$IPSET_SAVE_FILE" ]] && ipset restore < "$IPSET_SAVE_FILE"
LOADSCRIPT
    chmod +x "$IPSET_LOAD_SCRIPT"
    
    # Create systemd service to load ipset before UFW
    cat > /etc/systemd/system/ipset-load.service << 'SERVICEEOF'
[Unit]
Description=Load ipset rules
Before=ufw.service
After=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/load-ipset-blacklist.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICEEOF
    
    systemctl daemon-reload
    systemctl enable ipset-load.service >> "$LOG_FILE" 2>&1
    
    echo "Persistence configured" | tee -a "$LOG_FILE"
}

# Reload UFW
reload_ufw() {
    echo "Reloading UFW..." | tee -a "$LOG_FILE"
    ufw reload >> "$LOG_FILE" 2>&1
    echo "UFW reloaded" | tee -a "$LOG_FILE"
}

# Show statistics
show_stats() {
    echo "" | tee -a "$LOG_FILE"
    echo "=== Statistics ===" | tee -a "$LOG_FILE"
    echo "Whitelist IPs: $(ipset list "$IPSET_WHITELIST" 2>/dev/null | grep -c '^[0-9]' || echo 0)" | tee -a "$LOG_FILE"
    echo "Blacklist subnets: $(ipset list "$IPSET_BLACKLIST" 2>/dev/null | grep -c '^[0-9]' || echo 0)" | tee -a "$LOG_FILE"
    
    if [[ ${#WHITELIST_IPS[@]} -gt 0 ]]; then
        echo "" | tee -a "$LOG_FILE"
        echo "=== Whitelist IPs ===" | tee -a "$LOG_FILE"
        ipset list "$IPSET_WHITELIST" 2>/dev/null | grep '^[0-9]' | tee -a "$LOG_FILE"
    fi
    
    echo "" | tee -a "$LOG_FILE"
    echo "=== UFW before.rules check ===" | tee -a "$LOG_FILE"
    grep -A5 "BEGIN IPSET BLACKLIST" /etc/ufw/before.rules 2>/dev/null | tee -a "$LOG_FILE"
}

# =============================================================================
# MAIN
# =============================================================================
echo "========================================" >> "$LOG_FILE"
echo "UFW + IPSET Blacklist started $(date)" | tee -a "$LOG_FILE"

install_packages
create_ipsets
apply_blacklist      # First load blacklist
apply_whitelist      # Then whitelist
integrate_with_ufw   # Integrate with UFW (whitelist BEFORE blacklist)
save_ipset           # Save for persistence
reload_ufw           # Reload UFW
show_stats

rm -f "$TEMP_FILE"
echo "Script completed successfully $(date)" | tee -a "$LOG_FILE"
