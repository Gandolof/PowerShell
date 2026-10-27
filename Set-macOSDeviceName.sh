#!/bin/bash

# Set-MacDeviceName.sh
# Automatically names macOS devices based on the signed-in
# user's region and the device serial number.
#
# Examples:
# SE-C02ABC123XYZ
# DK-C02ABC123XYZ
# NO-C02ABC123XYZ
# FI-C02ABC123XYZ
#
# Run as root through Microsoft Intune.

LOG_FILE="/Library/Logs/Set-MacDeviceName.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

log "Starting macOS device naming."

# Identify currently signed-in user
CURRENT_USER=$(/usr/bin/stat -f "%Su" /dev/console)

if [[ -z "$CURRENT_USER" || "$CURRENT_USER" == "root" || "$CURRENT_USER" == "loginwindow" ]]; then
    log "No interactive user signed in. Exiting."
    exit 1
fi

log "Signed-in user: $CURRENT_USER"

# Read user's regional settings
USER_UID=$(/usr/bin/id -u "$CURRENT_USER")

LOCALE=$(/bin/launchctl asuser "$USER_UID" \
    /usr/bin/sudo -u "$CURRENT_USER" \
    /usr/bin/defaults read -g AppleLocale 2>/dev/null)

if [[ -z "$LOCALE" ]]; then
    log "Unable to determine AppleLocale. Exiting."
    exit 1
fi

log "Detected locale: $LOCALE"

# Extract country from locale, e.g. sv_SE -> SE, en_DK -> DK
COUNTRY=$(echo "$LOCALE" | /usr/bin/sed -E 's/.*[_-]([A-Za-z]{2})(@.*)?$/\1/' | /usr/bin/tr '[:lower:]' '[:upper:]')

# Only supported Nordic countries
case "$COUNTRY" in
    SE|DK|NO|FI)
        ;;
    *)
        log "Unsupported country: $COUNTRY. Exiting."
        exit 1
        ;;
esac

# Retrieve hardware serial number
SERIAL=$(/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice |
    /usr/bin/awk -F'"' '/IOPlatformSerialNumber/ {print $4; exit}')

if [[ -z "$SERIAL" ]]; then
    log "Unable to retrieve serial number. Exiting."
    exit 1
fi

# Build device name
NEW_NAME="${COUNTRY}-${SERIAL}"

log "Target device name: $NEW_NAME"

# Retrieve current computer names
CURRENT_COMPUTER_NAME=$(/usr/sbin/scutil --get ComputerName 2>/dev/null)
CURRENT_LOCAL_HOST_NAME=$(/usr/sbin/scutil --get LocalHostName 2>/dev/null)
CURRENT_HOST_NAME=$(/usr/sbin/scutil --get HostName 2>/dev/null)

# Skip if all names are already correct
if [[ "$CURRENT_COMPUTER_NAME" == "$NEW_NAME" &&
      "$CURRENT_LOCAL_HOST_NAME" == "$NEW_NAME" &&
      "$CURRENT_HOST_NAME" == "$NEW_NAME" ]]; then
    log "Device already has correct name. No changes required."
    exit 0
fi

# Rename device
/usr/sbin/scutil --set ComputerName "$NEW_NAME" || exit 1
/usr/sbin/scutil --set LocalHostName "$NEW_NAME" || exit 1
/usr/sbin/scutil --set HostName "$NEW_NAME" || exit 1

log "Successfully renamed device to $NEW_NAME"

exit 0