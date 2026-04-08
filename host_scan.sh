#!/bin/bash

OUTPUT="data/host_scan.json"

# HTTPS check
HTTPS_ENABLED=false
if ss -tuln | grep -q ":443"; then
    HTTPS_ENABLED=true
fi

# Disk encryption
DISK_ENCRYPTION="none"
if lsblk -o NAME,TYPE | grep -q crypt; then
    DISK_ENCRYPTION="full"
fi

# PATCH MANAGEMENT (simple check)
PATCH_STATUS="unknown"
if ls /var/lib/apt/periodic/update-success-stamp >/dev/null 2>&1; then
    PATCH_STATUS="recent"
else
    PATCH_STATUS="outdated"
fi

# FIREWALL CHECK
FIREWALL_ENABLED=false
if ufw status | grep -q "Status: active"; then
    FIREWALL_ENABLED=true
fi

# AUTO UPDATES
AUTO_UPDATES=false
if systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
    AUTO_UPDATES=true
fi

# SYSTEM LOGGING
SYSTEM_LOGGING=false
if systemctl is-active rsyslog >/dev/null 2>&1; then
    SYSTEM_LOGGING=true
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat <<EOF > $OUTPUT
{
 "https_enabled": $HTTPS_ENABLED,
 "encryption_at_rest": "$DISK_ENCRYPTION",

 "extra_security_signals": {
   "patch_management_status": "$PATCH_STATUS",
   "firewall_enabled": $FIREWALL_ENABLED,
   "automatic_updates": $AUTO_UPDATES,
   "system_logging_enabled": $SYSTEM_LOGGING
 },

 "host_scan_timestamp": "$TIMESTAMP"
}
EOF

echo "Host scan completed"