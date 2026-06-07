#!/bin/sh
# Dwaar uninstaller — https://dwaar.dev
# Usage: curl -fsSL https://dwaar.dev/uninstall.sh | sh
#
# Removes the dwaar binary and the service-manager integration that install.sh
# created (systemd unit on Linux, launchd agent on macOS). User configuration
# and logs are left in place — remove them manually if you want a clean wipe:
#   /etc/dwaar, /var/log/dwaar            (system install)
#   ~/.config/dwaar, ~/Library/Logs/dwaar (user install)
set -eu

SYSTEM_BIN="/usr/local/bin/dwaar"
USER_BIN="${HOME}/.local/bin/dwaar"
SYSTEMD_UNIT="/etc/systemd/system/dwaar.service"
LAUNCHD_PLIST="${HOME}/Library/LaunchAgents/com.permanu.dwaar.plist"

# Run a command as root via sudo when not already root.
as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        printf "Error: need root to run: %s\n" "$*" >&2
        return 1
    fi
}

removed_any=0

# --- Stop and remove the systemd service (Linux) ---
if command -v systemctl >/dev/null 2>&1 && [ -f "${SYSTEMD_UNIT}" ]; then
    printf "Stopping and disabling dwaar systemd service...\n"
    as_root systemctl stop dwaar 2>/dev/null || true
    as_root systemctl disable dwaar 2>/dev/null || true
    as_root rm -f "${SYSTEMD_UNIT}"
    as_root systemctl daemon-reload 2>/dev/null || true
    removed_any=1
fi

# --- Unload and remove the launchd agent (macOS) ---
if [ -f "${LAUNCHD_PLIST}" ]; then
    printf "Unloading launchd agent...\n"
    launchctl unload "${LAUNCHD_PLIST}" 2>/dev/null || true
    rm -f "${LAUNCHD_PLIST}"
    removed_any=1
fi

# --- Remove the binary (system or user location) ---
for bin in "${SYSTEM_BIN}" "${USER_BIN}"; do
    if [ -f "${bin}" ]; then
        printf "Removing %s\n" "${bin}"
        if [ -w "$(dirname "${bin}")" ]; then
            rm -f "${bin}"
        else
            as_root rm -f "${bin}"
        fi
        removed_any=1
    fi
done

if [ "${removed_any}" -eq 0 ]; then
    printf "dwaar does not appear to be installed.\n" >&2
    exit 1
fi

printf "\ndwaar has been uninstalled.\n"
printf "Configuration and logs were left in place. Remove them manually if desired:\n"
printf "  /etc/dwaar  /var/log/dwaar  ~/.config/dwaar  ~/Library/Logs/dwaar\n"
