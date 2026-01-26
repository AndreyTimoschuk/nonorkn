#!/bin/bash

# =============================================================================
# UFW + IPSET Multi-Level Blacklist
# https://github.com/AndreyTimoschuk/nonorkn
# =============================================================================
# Two-level blocking:
# 1. blacklist_dangerous - dangerous networks (botnets, malware, Tor, spam)
#    → blocks EVERYTHING: incoming (src) + outgoing (dst) + ESTABLISHED
# 2. blacklist_ru - Russian government networks (optional)
#    → blocks only incoming, allows outgoing (for APIs, CDNs)
# =============================================================================
#
# Sources:
# - Dangerous lists: https://github.com/firehol/blocklist-ipsets
# - RU list: https://github.com/C24Be/AS_Network_List
#
# =============================================================================

# === QUICK DIAGNOSTICS ===
# ipset list -t
# echo "Whitelist: $(ipset list whitelist 2>/dev/null | grep -c '^[0-9]')"
# echo "Dangerous: $(ipset list blacklist_dangerous 2>/dev/null | grep -c '^[0-9]')"
# echo "RU: $(ipset list blacklist_ru 2>/dev/null | grep -c '^[0-9]')"
# grep -A15 "IPSET BLACKLIST" /etc/ufw/before.rules
# iptables -L ufw-before-input -v -n --line-numbers | head -15
# iptables -L ufw-before-output -v -n --line-numbers | head -10

# =============================================================================
# CONFIGURATION
# =============================================================================

LOG_FILE="/var/log/ufw_blacklist.log"
IPSET_SAVE_FILE="/etc/ipset.rules"
IPSET_LOAD_SCRIPT="/usr/local/bin/load-ipset-blacklist.sh"

# ipset set names
IPSET_WHITELIST="whitelist"
IPSET_DANGEROUS="blacklist_dangerous"  # Dangerous - block ALL: INPUT + OUTPUT + ESTABLISHED
IPSET_RU="blacklist_ru"                # Russian gov - block only INPUT

# =============================================================================
# LIST SOURCES
# =============================================================================

# Russian government networks (block incoming, allow outgoing)
# Comment out or set empty to disable
URL_RU="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist.txt"

# Dangerous networks - block COMPLETELY (even ESTABLISHED)
# Source: https://github.com/firehol/blocklist-ipsets
# Comment out entries you don't need
URLS_DANGEROUS=(
    # Spamhaus DROP - hijacked networks, professional spam/cybercrime
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset"
    # Spamhaus EDROP - extended DROP list
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_edrop.netset"
    # Blocklist.de - brute force attacks (SSH, FTP, etc) - last 48 hours
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de.ipset"
    # Feodo tracker - banking trojans (Emotet, Dridex, etc)
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/feodo.ipset"
    # TOR exit nodes - anonymous traffic
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits.ipset"
    # DShield - top 20 attacking subnets
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset"
)

# =============================================================================
# WHITELIST - IPs that should ALWAYS be allowed
# Add your trusted IPs here (home IP, office, VPN servers, etc.)
# =============================================================================
WHITELIST_IPS=(
    # Example: "1.2.3.4"
    # Example: "10.0.0.0/8"
)

# =============================================================================
# FUNCTIONS
# =============================================================================

[[ $EUID -ne 0 ]] && { echo "Error: script must be run as root (sudo)" | tee -a "$LOG_FILE"; exit 1; }

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $*" | tee -a "$LOG_FILE"
}

install_packages() {
    log "Checking packages..."
    if ! command -v ipset &> /dev/null; then
        log "Installing ipset..."
        apt-get update >> "$LOG_FILE" 2>&1
        apt-get install -y ipset >> "$LOG_FILE" 2>&1
    fi
}

create_ipsets() {
    log "Creating ipset sets..."
    
    # Whitelist
    ipset create "$IPSET_WHITELIST" hash:net family inet hashsize 1024 maxelem 65536 2>/dev/null || true
    
    # Dangerous - large set
    ipset create "$IPSET_DANGEROUS" hash:net family inet hashsize 65536 maxelem 500000 2>/dev/null || true
    
    # Russian government networks
    ipset create "$IPSET_RU" hash:net family inet hashsize 8192 maxelem 100000 2>/dev/null || true
    
    log "ipset sets created"
}

apply_whitelist() {
    log "Loading whitelist..."
    
    ipset flush "$IPSET_WHITELIST" 2>/dev/null || true
    
    local count=0
    for ip in "${WHITELIST_IPS[@]}"; do
        [[ -z "$ip" ]] && continue
        ipset add "$IPSET_WHITELIST" "$ip" 2>/dev/null && ((count++)) || true
    done
    
    log "Whitelist: $count IPs"
}

# Load list into ipset
load_list_to_ipset() {
    local url="$1"
    local ipset_name="$2"
    local temp_file="/tmp/blacklist_$(basename "$url")"
    
    if ! curl -sf --connect-timeout 10 --max-time 60 --retry 2 "$url" -o "$temp_file" 2>/dev/null; then
        log "WARN: Failed to download $url"
        return 1
    fi
    
    # Filter valid IPv4 subnets
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' "$temp_file" 2>/dev/null | while read -r subnet; do
        echo "add $ipset_name $subnet"
    done
    
    rm -f "$temp_file"
}

apply_dangerous_blacklist() {
    log "Loading DANGEROUS lists (blocking ALL including ESTABLISHED)..."
    
    if [[ ${#URLS_DANGEROUS[@]} -eq 0 ]]; then
        log "WARN: URLS_DANGEROUS is empty - dangerous blocking disabled"
        return 0
    fi
    
    ipset flush "$IPSET_DANGEROUS" 2>/dev/null || true
    
    local restore_file="/tmp/ipset_dangerous_restore.txt"
    > "$restore_file"
    
    for url in "${URLS_DANGEROUS[@]}"; do
        log "  Downloading: $(basename "$url")"
        load_list_to_ipset "$url" "$IPSET_DANGEROUS" >> "$restore_file"
    done
    
    # Remove duplicates and load
    sort -u "$restore_file" > "${restore_file}.sorted"
    local count=$(wc -l < "${restore_file}.sorted")
    
    if ipset restore -! < "${restore_file}.sorted" 2>> "$LOG_FILE"; then
        log "Dangerous blacklist: $count subnets"
    else
        log "WARN: Errors loading dangerous blacklist"
    fi
    
    rm -f "$restore_file" "${restore_file}.sorted"
}

apply_ru_blacklist() {
    log "Loading RU list (blocking incoming, allowing outgoing)..."
    
    if [[ -z "$URL_RU" ]]; then
        log "WARN: URL_RU is empty - RU blocking disabled"
        return 0
    fi
    
    ipset flush "$IPSET_RU" 2>/dev/null || true
    
    local temp_file="/tmp/blacklist_ru.txt"
    
    if ! curl -sf --connect-timeout 10 --max-time 60 --retry 3 "$URL_RU" -o "$temp_file" 2>/dev/null; then
        log "WARN: Failed to download RU list"
        return 1
    fi
    
    local restore_file="/tmp/ipset_ru_restore.txt"
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' "$temp_file" | \
        sort -u | \
        while read -r subnet; do echo "add $IPSET_RU $subnet"; done > "$restore_file"
    
    local count=$(wc -l < "$restore_file")
    
    if ipset restore -! < "$restore_file" 2>> "$LOG_FILE"; then
        log "RU blacklist: $count subnets"
    else
        log "WARN: Errors loading RU blacklist"
    fi
    
    rm -f "$temp_file" "$restore_file"
}

integrate_with_ufw() {
    log "Integrating with UFW..."
    
    local before_rules="/etc/ufw/before.rules"
    local marker_start="# BEGIN IPSET BLACKLIST"
    local marker_end="# END IPSET BLACKLIST"
    local tmp_rules="/tmp/ipset_ufw_rules.txt"
    
    [[ ! -f "$before_rules" ]] && { log "ERROR: $before_rules not found"; return 1; }
    
    # Remove old rules
    if grep -q "$marker_start" "$before_rules"; then
        sed -i "/$marker_start/,/$marker_end/d" "$before_rules"
    fi
    
    # IMPORTANT: Rule order is critical!
    # 1. Whitelist - always allow
    # 2. Dangerous - block ALL (BEFORE ESTABLISHED check!)
    # 3. ESTABLISHED,RELATED - allow responses to our connections
    # 4. RU blacklist - block only new incoming
    cat > "$tmp_rules" << EOF

$marker_start
# === WHITELIST - always allow trusted IPs ===
-A ufw-before-input -m set --match-set $IPSET_WHITELIST src -j ACCEPT
-A ufw-before-output -m set --match-set $IPSET_WHITELIST dst -j ACCEPT

# === DANGEROUS - block ALL (botnets, malware, Tor, spammers) ===
# Incoming from dangerous IPs
-A ufw-before-input -m set --match-set $IPSET_DANGEROUS src -j DROP
# Outgoing TO dangerous IPs (prevent server connecting to botnets/malware)
-A ufw-before-output -m set --match-set $IPSET_DANGEROUS dst -j DROP

# === ESTABLISHED/RELATED - allow responses to OUR connections ===
# (only for IPs NOT in dangerous list - they're already blocked above)
-A ufw-before-input -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# === RU BLACKLIST - block only NEW incoming connections ===
# Can make outgoing connections to these IPs (APIs, CDNs, etc)
-A ufw-before-input -m set --match-set $IPSET_RU src -j DROP
$marker_end
EOF
    
    # Insert rules
    if grep -q "# End required lines" "$before_rules"; then
        sed -i "/# End required lines/r $tmp_rules" "$before_rules"
    else
        sed -i "/:ufw-before-input/r $tmp_rules" "$before_rules"
    fi
    
    rm -f "$tmp_rules"
    
    if grep -q "$marker_start" "$before_rules"; then
        log "UFW integration successful"
    else
        log "ERROR: UFW integration failed!"
        return 1
    fi
}

save_ipset() {
    log "Saving ipset..."
    
    ipset save > "$IPSET_SAVE_FILE" 2>/dev/null
    
    cat > "$IPSET_LOAD_SCRIPT" << 'LOADSCRIPT'
#!/bin/bash
IPSET_SAVE_FILE="/etc/ipset.rules"
[[ -f "$IPSET_SAVE_FILE" ]] && ipset restore < "$IPSET_SAVE_FILE"
LOADSCRIPT
    chmod +x "$IPSET_LOAD_SCRIPT"
    
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
    
    log "Persistence configured"
}

reload_ufw() {
    log "Reloading UFW..."
    ufw reload >> "$LOG_FILE" 2>&1
}

show_stats() {
    echo ""
    echo "==========================================" | tee -a "$LOG_FILE"
    echo "              STATISTICS                  " | tee -a "$LOG_FILE"
    echo "==========================================" | tee -a "$LOG_FILE"
    echo "Whitelist:                 $(ipset list "$IPSET_WHITELIST" 2>/dev/null | grep -c '^[0-9]' || echo 0) IPs" | tee -a "$LOG_FILE"
    echo "Dangerous (IN+OUT block):  $(ipset list "$IPSET_DANGEROUS" 2>/dev/null | grep -c '^[0-9]' || echo 0) subnets" | tee -a "$LOG_FILE"
    echo "RU (INPUT only block):     $(ipset list "$IPSET_RU" 2>/dev/null | grep -c '^[0-9]' || echo 0) subnets" | tee -a "$LOG_FILE"
    echo "==========================================" | tee -a "$LOG_FILE"
    echo ""
    echo "Whitelist IPs:" | tee -a "$LOG_FILE"
    ipset list "$IPSET_WHITELIST" 2>/dev/null | grep '^[0-9]' | head -20 | tee -a "$LOG_FILE"
    echo ""
    echo "UFW rules (INPUT):" | tee -a "$LOG_FILE"
    iptables -L ufw-before-input -n --line-numbers 2>/dev/null | head -8 | tee -a "$LOG_FILE"
    echo ""
    echo "UFW rules (OUTPUT):" | tee -a "$LOG_FILE"
    iptables -L ufw-before-output -n --line-numbers 2>/dev/null | head -5 | tee -a "$LOG_FILE"
}

# =============================================================================
# MAIN
# =============================================================================

log "========================================"
log "UFW + IPSET Multi-Blacklist started"
log "========================================"

install_packages
create_ipsets
apply_whitelist
apply_dangerous_blacklist    # First dangerous (block ALL)
apply_ru_blacklist           # Then RU (block only incoming)
integrate_with_ufw
save_ipset
reload_ufw
show_stats

log "Script completed successfully"
