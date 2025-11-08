#!/bin/bash
###################################################################################################
#  DESCRIPTION:                                                                                   #
#    This is used to get the current version of Semaphore installed on a server and update it if  #
#    the current running version is not up to date                                                #
#                                                                                                 #
#   Company: OsbornePro LLC.                                                                      #
#   Website: https://osbornepro.com                                                               #
#   Author: Robert H. Osborne                                                                     #
#   Contact: rosborne@osbornepro.com                                                              #
###################################################################################################
# --------------------------  LOCK FILE  -----------------------------------------
LOCKFILE="/var/run/semaphore-update.lock"

# Acquire an exclusive lock (fd 9).  If another instance holds it, exit immediately.
if ! exec 9>"$LOCKFILE"; then
    echo "[x] Failed to create lock file $LOCKFILE" >&2
    exit 1
fi

if ! flock -n 9; then
    echo "[x] Another update is already running (lock $LOCKFILE held)." >&2
    exit 1
fi

# Ensure the lock is removed on any exit (normal, error, signal)
cleanup() {
    rm -f "$LOCKFILE" 2>/dev/null || true
}
trap cleanup EXIT

# --------------------------  PRE-CHECKS  ---------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "[x] This script must be run as root." >&2
    exit 1
fi

for cmd in jq pg_dump curl wget tar sha256sum; do
    command -v "$cmd" >/dev/null || { echo "[x] $cmd is required but not installed."; exit 1; }
done

# --------------------------  CONFIG & DB  --------------------------------------
SERVICE_NAME="semaphore.service"
BACKUP_DIR="/root/semaphore_backup"
TMP_DIR="/tmp"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Extract --config path from the systemd unit (robust)
CONFIG_FILE=$(systemctl show --property=ExecStart --value "$SERVICE_NAME" |
              grep -Eo '--config "[^"]+"' | cut -d'"' -f2)

[[ -f "$CONFIG_FILE" ]] || { echo "[x] Config file not found at $CONFIG_FILE"; exit 1; }

# Parse PostgreSQL credentials with jq (requires JSON config)
DB_USER=$(jq -r '.postgres.user // empty' "$CONFIG_FILE")
DB_NAME=$(jq -r '.postgres.name // empty' "$CONFIG_FILE")

[[ -n "$DB_USER" && -n "$DB_NAME" ]] || { echo "[x] DB user/name not found in config."; exit 1; }

# --------------------------  VERSION HELPERS  ----------------------------------
get_latest_version() {
    curl -s "https://api.github.com/repos/semaphoreui/semaphore/releases/latest" |
        jq -r '.tag_name' | sed 's/^v//'
}

get_current_version() {
    semaphore version 2>/dev/null | cut -d'-' -f1 || echo "unknown"
}

# --------------------------  BACKUPS  -----------------------------------------
echo "[-] Backing up config..."
cp -a "$CONFIG_FILE" "$BACKUP_DIR/config.json.bak.$TIMESTAMP"

echo "[-] Backing up PostgreSQL database..."
BACKUP_SQL="$BACKUP_DIR/semaphore_db_${TIMESTAMP}.dump.gz"

# Prefer passwordless auth via .pgpass; fall back to prompt if missing
if [[ -f "/root/.pgpass" ]] && grep -q ":$DB_NAME:$DB_USER:" /root/.pgpass; then
    pg_dump -U "$DB_USER" -d "$DB_NAME" | gzip > "$BACKUP_SQL"
else
    echo "[!] No suitable .pgpass entry. Password required."
    read -rsp "PostgreSQL password for $DB_USER: " DB_PASS
    echo
    export PGPASSWORD="$DB_PASS"
    pg_dump -U "$DB_USER" -d "$DB_NAME" | gzip > "$BACKUP_SQL"
    unset PGPASSWORD
fi

[[ ${PIPESTATUS[0]} -eq 0 ]] || { echo "[x] pg_dump failed."; exit 1; }

# --------------------------  VERSION CHECK  -----------------------------------
LATEST=$(get_latest_version)
CURRENT=$(get_current_version)

echo "[-] Current Semaphore version: $CURRENT"
echo "[-] Latest Semaphore version : $LATEST"

[[ "$CURRENT" == "$LATEST" ]] && { echo "[-] Already up to date."; exit 0; }

# --------------------------  ARCH & DOWNLOAD  ---------------------------------
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    i?86)   ARCH="386"   ;;
    *) echo "[x] Unsupported architecture: $ARCH"; exit 1 ;;
esac

FILE="semaphore_${LATEST}_linux_${ARCH}.tar.gz"
URL="https://github.com/semaphoreui/semaphore/releases/download/v${LATEST}/${FILE}"
CHKSUM_URL="https://github.com/semaphoreui/semaphore/releases/download/v${LATEST}/semaphore_${LATEST}_checksums.txt"

cd "$TMP_DIR"
echo "[-] Downloading $FILE ..."
wget -q "$URL" -O "$FILE"
wget -q "$CHKSUM_URL" -O "checksums.txt"

# Verify checksum
if ! grep "$FILE" checksums.txt | sha256sum --check --status; then
    echo "[x] Checksum verification failed!"; exit 1
fi

# --------------------------  UPDATE  ------------------------------------------
echo "[-] Stopping Semaphore service..."
systemctl stop "$SERVICE_NAME"

echo "[-] Extracting new binary..."
tar -xzf "$FILE"

CURRENT_BIN=$(which semaphore)
[[ -n "$CURRENT_BIN" && -x "$CURRENT_BIN" ]] || { echo "[x] Existing binary not found in PATH."; exit 1; }

echo "[-] Replacing binary at $CURRENT_BIN ..."
cp -f semaphore "$CURRENT_BIN"
chmod +x "$CURRENT_BIN"

# --------------------------  START & VERIFY  ----------------------------------
echo "[-] Starting Semaphore service..."
systemctl start "$SERVICE_NAME"

sleep 3
if systemctl is-active --quiet "$SERVICE_NAME"; then
    NEW_VER=$(get_current_version)
    echo "[-] Semaphore successfully updated to $NEW_VER"
else
    echo "[x] Service failed to start after update."
    journalctl -u "$SERVICE_NAME" -n 20 --no-pager -l
    exit 1
fi

# --------------------------  CLEANUP (handled by trap) -------------------------
# Lock file is removed automatically via trap
