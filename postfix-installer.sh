#!/bin/bash
###################################################################################################
#  DESCRIPTION:                                                                                   #
#  This script is used to quickly and easily configure the postmap service on a Linux device      #
#  Configuration steps vary for different SMTP servers                                            #
#                                                                                                 #
#   Company: OsbornePro LLC.                                                                      #
#   Website: https://osbornepro.com                                                               #
#   Author: Robert H. Osborne                                                                     #
#   Contact: rosborne@osbornepro.com                                                              #
#                                                                                                 #
###################################################################################################
# === Detect OS ===
HOSTNAME=$(hostname)
OSID=$(grep ^ID_LIKE= /etc/os-release | cut -d'=' -f2 | tr -d '"')

if echo "$OSID" | grep -qw "debian"; then
    printf "[*] Using Debian-based OS settings\n"
    CAFILE="/etc/ssl/certs/ca-certificates.crt"
    CAPATH="/etc/ssl/certs"
    CERTFILE="/etc/ssl/certs/ssl-cert-snakeoil.pem"
    KEYFILE="/etc/ssl/private/ssl-cert-snakeoil.key"
    apt-get update -qq > /dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libsasl2-modules postfix mailutils > /dev/null 2>&1

elif echo "$OSID" | grep -Eqw "fedora|rhel|centos"; then
    printf "[*] Using Fedora/RHEL-based OS settings (AlmaLinux 10+)\n"
    CAFILE="/etc/pki/tls/certs/ca-bundle.crt"
    CAPATH="/etc/pki/tls/certs"
    CERTFILE="/etc/pki/tls/certs/postfix.pem"
    KEYFILE="/etc/pki/tls/private/postfix.key"
    dnf install -y -q postfix mailutils cyrus-sasl-plain > /dev/null 2>&1

else
    printf "[!] Unsupported OS. ID_LIKE: %s\n" "$OSID"
    exit 1
fi

# === Backup ===
[ -f /etc/postfix/main.cf ] && cp -p /etc/postfix/main.cf /etc/postfix/main.cf.orig

# === Provider ===
OPTIONS=("Office365" "Gmail" "Custom" "Quit")
PS3="[?] Choose provider: "
select opt in "${OPTIONS[@]}"; do
    case $REPLY in
        1) PROVIDER="office365"; break ;;
        2) PROVIDER="gmail"; break ;;
        3) PROVIDER="custom"; break ;;
        4) exit 0 ;;
        *) echo "[!] Invalid";;
    esac
done

case $PROVIDER in
    office365) DEFAULT_SERVER="smtp.office365.com"; DEFAULT_PORT="587" ;;
    gmail)     DEFAULT_SERVER="smtp.gmail.com";     DEFAULT_PORT="587" ;;
    custom)    DEFAULT_SERVER="";                   DEFAULT_PORT="" ;;
esac

# === TLS / Port ===
echo
echo "[?] Submission method:"
echo " 1) STARTTLS (587) – Recommended"
echo " 2) SMTPS / Implicit TLS (465)"
echo " 3) Opportunistic / Plain (25)"
read -p "[-] Choice [1-3]: " TLS_CHOICE

case $TLS_CHOICE in
    1) PORT="587"; TLS_LEVEL="encrypt"; TLS_WRAPPER="no" ;;
    2) PORT="465"; TLS_LEVEL="encrypt"; TLS_WRAPPER="yes" ;;
    3) PORT="25";  TLS_LEVEL="may";     TLS_WRAPPER="no" ;;
    *) PORT="587"; TLS_LEVEL="encrypt"; TLS_WRAPPER="no" ;;
esac

# === Server & Port ===
if [[ -n "$DEFAULT_SERVER" ]]; then
    read -p "[?] Use $DEFAULT_SERVER:$PORT? (Y/n): " use_def
    [[ ! $use_def =~ ^[Nn]$ ]] && SMTPSERVER="$DEFAULT_SERVER" || read -p "[?] SMTP Server: " SMTPSERVER
else
    read -p "[?] SMTP Server: " SMTPSERVER
fi

read -p "[?] Port [$PORT]: " input_port
[[ -n "$input_port" ]] && PORT="$input_port"
[[ ! "$PORT" =~ ^[0-9]+$ ]] && { echo "[!] Invalid port"; exit 1; }

# === Domain & Sender ===
read -p "[?] Domain (e.g. example.com): " DOMAIN
read -p "[?] Sender Email (optional): " EMAIL
PASS=""
if [[ -n "$EMAIL" ]]; then
    read -s -p "[?] SMTP Password (optional): " PASS
    echo
fi

# === Logic ===
USE_SASL=false
USE_SENDER_REWRITE=false
if [[ -n "$EMAIL" ]]; then
    USE_SENDER_REWRITE=true
    if [[ -n "$PASS" && "$TLS_LEVEL" == "encrypt" ]]; then
        USE_SASL=true
    fi
fi

# === Hostname ===
HOSTNAME=$(hostname -f 2>/dev/null || hostname)
MYHOSTNAME="${HOSTNAME}.${DOMAIN}"
[[ "$MYHOSTNAME" == "." ]] && MYHOSTNAME="$HOSTNAME"

# === /etc/mailname ===
echo "$DOMAIN" > /etc/mailname

# === DH Params ===
openssl dhparam -out /etc/ssl/certs/postfix-dh1024.pem 1024 2>/dev/null
chmod 644 /etc/ssl/certs/postfix-dh1024.pem

# === Aliases – Only add if not already present ===
if [[ -n "$EMAIL" ]]; then
    if ! grep -q "^root:[[:space:]]*$EMAIL" /etc/aliases; then
        echo "root: $EMAIL" >> /etc/aliases
        printf "[*] Added root alias to /etc/aliases\n"
    else
        printf "[*] Root alias already exists in /etc/aliases\n"
    fi
fi

# === SASL (texthash) ===
SASL_DIR="/etc/postfix/sasl"
SASL_PASSWD="$SASL_DIR/sasl_passwd"
if $USE_SASL; then
    mkdir -p "$SASL_DIR"
    echo "[$SMTPSERVER]:$PORT $EMAIL:$PASS" > "$SASL_PASSWD"
    chmod 600 "$SASL_PASSWD"
    chown root:root "$SASL_PASSWD"
else
    rm -rf "$SASL_DIR"
fi

# === Sender Rewrite (texthash) ===
GENERIC_FILE="/etc/postfix/generic"
if $USE_SENDER_REWRITE; then
    cat > "$GENERIC_FILE" <<EOF
root@$HOSTNAME $EMAIL
root@localhost $EMAIL
root $EMAIL
@$HOSTNAME $EMAIL
@$DOMAIN $EMAIL
EOF
    chmod 600 "$GENERIC_FILE"
    chown root:root "$GENERIC_FILE"

    cat > /etc/postfix/sender_canonical_maps <<EOF
/^.+$/ $EMAIL
EOF
    chmod 600 /etc/postfix/sender_canonical_maps
    chown root:root /etc/postfix/sender_canonical_maps

    cat > /etc/postfix/header_check <<EOF
/^From:.*$/ REPLACE From: $EMAIL
EOF
    chmod 600 /etc/postfix/header_check
    chown root:root /etc/postfix/header_check
else
    rm -f "$GENERIC_FILE" /etc/postfix/sender_canonical_maps /etc/postfix/header_check
fi

# === MIME Checks (texthash) ===
cat > /etc/postfix/mime_header_checks <<'EOF'
/name=[^>]*\.(bat|cmd|com|exe|scr|pif|vbs|js|jar)/ REJECT Executable blocked
EOF
chmod 600 /etc/postfix/mime_header_checks
chown root:root /etc/postfix/mime_header_checks

# === main.cf (LMDB + texthash + NO btree AT ALL) ===
cat > /etc/postfix/main.cf <<EOF
# === Auto-generated – AlmaLinux 10+ (LMDB + texthash + no btree) ===
compatibility_level = 3.8
queue_directory = /var/spool/postfix
command_directory = /usr/sbin
daemon_directory = /usr/libexec/postfix
data_directory = /var/lib/postfix
mail_owner = postfix

myhostname = $MYHOSTNAME
mydomain = $DOMAIN
myorigin = \$mydomain
append_dot_mydomain = no

inet_interfaces = loopback-only
inet_protocols = ipv4
mynetworks = 127.0.0.0/8

relayhost = [$SMTPSERVER]:$PORT
relay_destination_concurrency_limit = 20
header_size_limit = 4096000

# SMTPUTF8 – Disable to avoid relay rejection
smtputf8_enable = no

# TLS Client
smtp_tls_security_level = $TLS_LEVEL
smtp_tls_loglevel = 1
EOF

# === Trusted CA (only for encrypt) ===
if [[ "$TLS_LEVEL" == "encrypt" ]]; then
    cat >> /etc/postfix/main.cf <<EOF

# Trusted CA for STARTTLS/SMTPS
smtp_tls_CAfile = $CAFILE
smtp_tls_CApath = $CAPATH
EOF
fi

# === SMTPS Wrapper Mode (only for port 465) ===
if [[ "$TLS_WRAPPER" == "yes" ]]; then
    cat >> /etc/postfix/main.cf <<EOF

# Required for SMTPS (port 465)
smtp_tls_wrappermode = yes
EOF
fi

# === SASL (texthash) ===
if $USE_SASL; then
    cat >> /etc/postfix/main.cf <<EOF

# SASL
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = texthash:$SASL_PASSWD
smtp_sasl_security_options = noanonymous
EOF
fi

# === Server TLS + Maps (LMDB) ===
cat >> /etc/postfix/main.cf <<EOF

# Server TLS
smtpd_tls_security_level = may
smtpd_tls_cert_file = $CERTFILE
smtpd_tls_key_file = $KEYFILE
smtpd_tls_loglevel = 1
smtpd_tls_received_header = yes

# Security
disable_vrfy_command = yes
strict_rfc821_envelopes = yes
smtpd_banner = \$myhostname ESMTP

# Maps (LMDB for aliases, texthash for others)
alias_maps = lmdb:/etc/aliases
alias_database = lmdb:/etc/aliases
mime_header_checks = texthash:/etc/postfix/mime_header_checks
EOF

# === Sender Rewrite (texthash) ===
if $USE_SENDER_REWRITE; then
    cat >> /etc/postfix/main.cf <<EOF
smtp_generic_maps = texthash:$GENERIC_FILE
sender_canonical_maps = texthash:/etc/postfix/sender_canonical_maps
smtp_header_checks = texthash:/etc/postfix/header_check
EOF
fi

# === TLS Hardening ===
cat >> /etc/postfix/main.cf <<EOF

tls_high_cipherlist = EECDH+AESGCM:EDH+AESGCM
tls_preempt_cipherlist = yes
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_ciphers = high
tls_ssl_options = NO_COMPRESSION
smtpd_tls_dh1024_param_file = /etc/ssl/certs/postfix-dh1024.pem
default_database_type = lmdb
EOF

# === Permissions ===
chown root:root /etc/postfix/main.cf
chmod 644 /etc/postfix/main.cf

# === Start ===
printf "[*] Enabling and starting Postfix...\n"
systemctl enable --now postfix >/dev/null 2>&1
sleep 5

# === Test ===
if [[ -n "$EMAIL" ]]; then
    printf "[*] Sending test email to %s...\n" "$EMAIL"
    {
        echo "Subject: Postfix Test – $(date)"
        echo "To: $EMAIL"
        echo ""
        echo "Host: $(hostname)"
        echo "Relay: [$SMTPSERVER]:$PORT"
        echo "TLS: $TLS_LEVEL"
        echo "SASL: $( $USE_SASL && echo enabled || echo disabled )"
    } | sendmail -f "$EMAIL" "$EMAIL"
else
    printf "[*] No test email\n"
fi

printf "[*] Done! Logs: journalctl -u postfix -f\n"
