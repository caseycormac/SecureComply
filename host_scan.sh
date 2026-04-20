#!/bin/bash

OUTPUT="data/host_scan.json"

# ─────────────────────────────────────────────
# HTTPS CHECK
# Checks whether the server is listening on port 443 (the standard port for
# secure/encrypted web traffic). If something is on that port, we assume
# HTTPS is enabled.
# ─────────────────────────────────────────────
HTTPS_ENABLED=false
if ss -tuln | grep -q ":443"; then   # 'ss -tuln' lists all open network ports;
                                      # grep looks for port 443 specifically
    HTTPS_ENABLED=true
fi


# ─────────────────────────────────────────────
# DISK ENCRYPTION CHECK
# Checks whether the hard drive is encrypted. Encrypted disks show up as
# type "crypt" in the block device list. If none are found, encryption is
# assumed to be off.
# ─────────────────────────────────────────────
DISK_ENCRYPTION="none"
if lsblk -o NAME,TYPE | grep -q crypt; then   # 'lsblk' lists storage devices;
                                               # 'crypt' means the disk is encrypted
    DISK_ENCRYPTION="full"
fi


# ─────────────────────────────────────────────
# PATCH MANAGEMENT CHECK
# Checks whether the system has recently downloaded security updates.
# Linux systems leave a "stamp" file behind after a successful update check —
# if that file exists, updates are considered recent; if not, they may be outdated.
# ─────────────────────────────────────────────
PATCH_STATUS="unknown"
if ls /var/lib/apt/periodic/update-success-stamp >/dev/null 2>&1; then   # This file is
                                                                           # created after
                                                                           # a successful
                                                                           # apt update run
    PATCH_STATUS="recent"
else
    PATCH_STATUS="outdated"
fi


# ─────────────────────────────────────────────
# OPEN PORT COUNT (Attack Surface)
# Counts how many network "doors" (ports) are currently open on this machine.
# Every open port is a potential entry point for attackers, so fewer is better.
# The list is deduplicated and sorted so each port is only counted once.
# ─────────────────────────────────────────────
OPEN_PORT_COUNT=0
OPEN_PORTS=$(ss -tuln 2>/dev/null | awk 'NR>1 {print $5}' | awk -F: '{print $NF}' | sort -n | uniq)
#            └──────────────────┘   └─────────────────────┘   └──────────────────┘   └──────────┘
#            List all open ports    Skip header, grab address  Extract just the       Sort and
#            (TCP & UDP)            column from each line       port number            remove duplicates

# Reformat the port list into a single comma-separated line (e.g. "22,80,443")
OPEN_PORTS=$(echo "$OPEN_PORTS" | paste -sd "," -)

# Safety fallback: if no open ports were found at all, label it "none"
if [ -z "$OPEN_PORTS" ]; then
  OPEN_PORTS="none"
fi

# Count how many ports are in the comma-separated list
OPEN_PORT_COUNT=$(echo "$OPEN_PORTS" | tr ',' '\n' | wc -l)
#                                       └──────────┘   └─────┘
#                                       Split on commas  Count the resulting lines


# ─────────────────────────────────────────────
# FIREWALL CHECK
# A firewall controls which network traffic is allowed in and out.
# This checks whether 'ufw' (Uncomplicated Firewall, common on Ubuntu/Debian)
# is turned on. An inactive firewall means all ports are unfiltered.
# ─────────────────────────────────────────────
FIREWALL_ENABLED=false
if ufw status | grep -q "Status: active"; then   # 'ufw status' reports whether the
                                                  # firewall is on or off
    FIREWALL_ENABLED=true
fi


# ─────────────────────────────────────────────
# AUTOMATIC UPDATES CHECK
# Checks whether the system is configured to install security patches
# automatically without needing a human to trigger them manually.
# 'unattended-upgrades' is the Linux service responsible for this.
# ─────────────────────────────────────────────
AUTO_UPDATES=false
if systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then   # 'systemctl is-enabled'
                                                                      # checks if a service
                                                                      # is set to run on boot
    AUTO_UPDATES=true
fi


# ─────────────────────────────────────────────
# SYSTEM LOGGING CHECK
# Checks whether the system is actively recording logs (a history of
# system events, errors, and activity). Logs are essential for diagnosing
# problems and investigating security incidents.
# 'rsyslog' is the most common logging service on Linux.
# ─────────────────────────────────────────────
SYSTEM_LOGGING=false
if systemctl is-active rsyslog >/dev/null 2>&1; then   # 'is-active' checks if the
                                                        # logging service is currently running
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
   "system_logging_enabled": $SYSTEM_LOGGING,
   "open_port_count": $OPEN_PORT_COUNT,
   "open_ports": "$OPEN_PORTS"
 },

 "host_scan_timestamp": "$TIMESTAMP"
}
EOF

echo "Host scan completed"