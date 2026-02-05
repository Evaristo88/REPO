#!/bin/bash
# Simple security check script (modified for lab)
# Purpose: perform quick host checks useful for basic security posture review.
#
# What it checks:
# - Counts recent failed SSH authentication attempts from the system auth log
# - Reads `/etc/ssh/sshd_config` to report the `PermitRootLogin` setting
# - Scans `/etc/passwd` for additional UID 0 accounts
#
# Notes / requirements:
# - The script inspects system log files and may need to be run with sufficient
#   privileges (or via `sudo`) to read `/var/log/auth.log` or `/var/log/secure`.
# - This is a simple, educational audit script and not a replacement for
#   centralized logging/host hardening tooling.

echo "Security check - quick system audit"

# ----------------------
# Configuration
# ----------------------
# Threshold for failed SSH authentication attempts to raise an alert
THRESHOLD_FAILED=5

# Potential auth log locations (Debian/Ubuntu vs RHEL/CentOS)
AUTH_LOG=""
for f in /var/log/auth.log /var/log/secure; do
	[ -f "$f" ] && { AUTH_LOG="$f"; break; }
done

# ----------------------
# Count failed SSH auth attempts
# ----------------------
if [ -n "$AUTH_LOG" ]; then
	FAILED_COUNT=$(grep -i "Failed password" "$AUTH_LOG" | wc -l)
else
	FAILED_COUNT=0
fi

# ----------------------
# Check sshd configuration for root login
# ----------------------
SSHD_CONFIG="/etc/ssh/sshd_config"
PERMIT_ROOT="unknown"
if [ -f "$SSHD_CONFIG" ]; then
	PERMIT_ROOT=$(grep -i '^PermitRootLogin' "$SSHD_CONFIG" | awk '{print tolower($2)}' || true)
fi

# ----------------------
# Check for additional UID 0 users
# ----------------------
UID0_USERS=$(awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null)

# ----------------------
# Output results (security-focused messages)
# ----------------------
echo "Auth log: ${AUTH_LOG:-not found}"
echo "Failed SSH auth attempts: $FAILED_COUNT"
if [ "$FAILED_COUNT" -ge "$THRESHOLD_FAILED" ]; then
	echo "ALERT: High number of failed SSH authentication attempts (threshold: $THRESHOLD_FAILED). Investigate for brute-force activity."
else
	echo "OK: Failed SSH attempts below threshold ($THRESHOLD_FAILED)."
fi

if [ -f "$SSHD_CONFIG" ]; then
	if [ "$PERMIT_ROOT" = "yes" ]; then
		echo "WARNING: PermitRootLogin is enabled in $SSHD_CONFIG — this increases risk. Recommend setting it to 'no' and using sudo for admin tasks."
	else
		echo "OK: PermitRootLogin is set to '$PERMIT_ROOT'."
	fi
else
	echo "NOTICE: $SSHD_CONFIG not found — cannot evaluate root SSH login setting."
fi

if [ -n "$UID0_USERS" ]; then
	if [ "$UID0_USERS" = "root" ] || [ "$(echo "$UID0_USERS" | wc -l)" -eq 1 ]; then
		echo "OK: Only 'root' has UID 0."
	else
		echo "ALERT: Multiple UID 0 accounts found: $UID0_USERS — review authorized admin accounts."
	fi
else
	echo "NOTICE: Could not read /etc/passwd to check UID 0 users."
fi

exit 0
