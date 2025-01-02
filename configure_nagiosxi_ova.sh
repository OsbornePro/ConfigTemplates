#!/bin/bash
# OsbornePro - Server Hardening Script
# Harden CentOS for hosting NagiosXI with enhanced security and maintainability
#-------------------------------------------------------------------------------
# How to use this script
#-------------------------------------------------------------------------------
# 1.) Download your NagiosXI image from https://www.nagios.com/products/nagios-xi/downloads/#downloads
# 2.) Login to the image you setup and run this script

# Trap signals and clean up
trap 'echo "[x] Script interrupted. Exiting."; exit 1' INT TERM

# Function to generate a random password
generate_password() {
    local password
    password=$(openssl rand -base64 18 | tr -d '+/=' | head -c 26)
    echo "$password"
}

# Function for logging messages
log_message() {
    local level=$1
    local message=$2
    printf "[%s] %s\n" "$level" "$message"
}

# Function to configure SELinux booleans
configure_selinux_boolean() {
    local boolean=$1
    local value=$2
    current_value=$(getsebool "$boolean" | awk '{print $3}')
    if [[ "$current_value" != "$value" ]]; then
        log_message "INFO" "Setting SELinux boolean '$boolean' to '$value'."
        if ! setsebool -P "$boolean" "$value"; then
            log_message "ERROR" "Failed to set SELinux boolean: $boolean"
            exit 1
        fi
    else
        log_message "INFO" "SELinux boolean '$boolean' is already set to '$value'. Skipping."
    fi
}

# Function to configure SELinux file context
configure_selinux_context() {
    local path=$1
    local context=$2
    log_message "INFO" "Configuring SELinux context for $path to $context."
    semanage fcontext -a -t "$context" "$path"
    restorecon -R "$path" || {
        log_message "ERROR" "Failed to apply SELinux context for $path."
        exit 1
    }
}

# Function to create error pages
create_error_pages() {
    local error_codes=(
        400 401 402 403 404 405 406 407 408 409 410
        411 412 413 414 415 416 417 418 421 422 423
        424 425 426 428 429 431 451 500 501 502 503
        504 505 506 507 508 510 511
    )
    local output_dir="/var/www/html/errors"
    mkdir -p "$output_dir"
    for code in "${error_codes[@]}"; do
        local file_path="$output_dir/$code.html"
        echo "ErrorDocument $code /errors/$code.html" >> /etc/httpd/conf/httpd.conf
        if ! printf '<h1>Error %s</h1>\n' "$code" > "$file_path"; then
            printf '[x] Failed to create error page for code: %s\n' "$code" >&2
            return 1
        fi
    done
    printf '[*] Error pages created in %s\n' "$output_dir"
}

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "[x] This script must be run as root. Use sudo."
    exit 1
fi

log_message "INFO" "====== Preparing the Host for NagiosXI ======"

# Prompt for input values
read -p "[?] Enter the Virtual Hostname (VHOST name) (e.g., nagiosxi.contoso.com): " VHOST_NAME
[[ -z "$VHOST_NAME" ]] && { log_message "ERROR" "VHOST name cannot be empty."; exit 1; }

read -p "[?] Enter the state (e.g., Massachusetts): " STATE
[[ -z "$STATE" ]] && { log_message "ERROR" "STATE name cannot be empty."; exit 1; }

read -p "[?] Enter the city (e.g., Boston): " CITY
[[ -z "$CITY" ]] && { log_message "ERROR" "CITY name cannot be empty."; exit 1; }

read -p "[?] Enter the Organization name (e.g., Contoso Inc.): " ORG_NAME
[[ -z "$ORG_NAME" ]] && { log_message "ERROR" "ORG_NAME name cannot be empty."; exit 1; }

# Global variables
OSCAP_DIR="/root/oscap-scans"
SSL_DIR="/var/www/html/ssl"
CERT_FILE="${SSL_DIR}/server.crt"
KEY_FILE="${SSL_DIR}/server.key"
ROOT_PASSWORD=$(generate_password)
USER_PASSWORD=$(generate_password)
NAGIOSADMIN_PASSWORD=$(generate_password)
ADMIN_USER="nagiosadmin"
HTTPD_VHOST_CONF="/etc/httpd/conf.d/vhost.conf"
HTTPD_SECURITY_CONF="/etc/httpd/conf.d/security.conf"
MODSEC_RULES_PATH="/etc/httpd/modsecurity.conf.d/mod_security_excluded_rules.conf"

# Local Variables
editor_config="export EDITOR=vim"
visual_config="export VISUAL=vim"

# Set hostname
hostnamectl hostname $VHOST_NAME

# Create admin user
if id "${ADMIN_USER}" &>/dev/null; then
    log_message "INFO" "User '${ADMIN_USER}' already exists."
else
    log_message "INFO" "Creating user '${ADMIN_USER}'."
    useradd -m -s /bin/bash "${ADMIN_USER}" || { log_message "ERROR" "Failed to create user '${ADMIN_USER}'."; exit 1; }
fi

# Add user to wheel group
log_message "INFO" "Adding '${ADMIN_USER}' to the 'wheel' group."
usermod -aG wheel "${ADMIN_USER}" || { log_message "ERROR" "Failed to add user '${ADMIN_USER}' to the wheel group."; exit 1; }

# Generate SSL certificates
mkdir -p "${SSL_DIR}"
if [[ -f "${CERT_FILE}" && -f "${KEY_FILE}" ]]; then
    log_message "INFO" "SSL certificates already exist in ${SSL_DIR}."
else
    log_message "INFO" "Generating SSL certificates."
    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:4096 \
        -keyout "${KEY_FILE}" \
        -out "${CERT_FILE}" \
        -subj "/C=US/ST=${STATE}/L=${CITY}/O=${ORG_NAME}/OU=Certificates/CN=${VHOST_NAME}" || {
        log_message "ERROR" "Failed to generate SSL certificates."
        exit 1
    }
    chmod 600 "${KEY_FILE}"
    chmod 644 "${CERT_FILE}"
    chown apache:apache "${KEY_FILE}" "${CERT_FILE}"
fi

# Update the system
log_message "INFO" "Updating the OS to the latest versions."
dnf -y update || { log_message "ERROR" "System update failed."; exit 1; }

# Install required packages
log_message "INFO" "Installing required packages."
dnf install -y vim mlocate epel-release mod_security mod_ssl policycoreutils-python-utils aide scap-security-guide tuned auditd || {
    log_message "ERROR" "Failed to install required packages."
    exit 1
}

# Configure /etc/skel for new users
cd /etc/skel || exit 1
umask 077
chmod 700 /etc/skel
find /etc/skel -type f -exec chmod 600 {} \;
find /etc/skel -type d -exec chmod 700 {} \;

# Set global umask in /etc/profile for all users
if ! grep -q "umask 077" /etc/profile; then
    echo "umask 077" >> /etc/profile
fi
log_message "INFO" "Configured /etc/skel permissions and global umask"

# Set permissions for each user's home directory
cd /home || exit 1
for user in *; do
    if [ -d "$user" ]; then
        chmod 700 "$user"
        user_bashrc="/home/${user}/.bashrc"
        if [ -w "$user_bashrc" ]; then
            echo "umask 077" >> "$user_bashrc"
        else
            echo "umask 077" > "$user_bashrc"
        fi
                if ! grep -q "^${editor_config}" "$user_bashrc"; then
            echo "$editor_config" >> "$user_bashrc"
        fi
        if ! grep -q "^${visual_config}" "$user_bashrc"; then
            echo "$visual_config" >> "$user_bashrc"
        fi
        chmod 600 "$user_bashrc"
        chown "$user:$user" "$user_bashrc"
        log_message "INFO" "Permissions set to 700 for /home/$user, umask configured in .bashrc"
    fi
done

# Used the recommended tuned profile
log_message "INFO" "Using the recommended tuned-adm profile $(tuned-adm recommend)."
systemctl enable --now tuned
tuned-adm profile $(tuned-adm recommend)

# Perform regular security audits
mkdir -p $OSCAP_DIR
cd $OSCAP_DIR
umask 066
cd -
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --results ${OSCAP_DIR}/scan.xml /usr/share/xml/scap/ssg/content/ssg-centos9-ds.xml

# Setup Intrusition Protection and Monitoring
log_message "INFO" "Initializing 'Aide' Intrusion detection and monitoring."
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Configure Apache headers
log_message "INFO" "Configuring Apache headers."
cat <<EOL > $HTTPD_SECURITY_CONF
# Hide Apache version information
ServerTokens Prod
ServerSignature Off

# Disable TRACE HTTP method
TraceEnable Off

# Enable X-Content-Type-Options header
Header always set X-Content-Type-Options "nosniff"

# Enable X-Frame-Options header
Header always set X-Frame-Options "SAMEORIGIN"

# Enable HSTS (HTTP Strict Transport Security)
#Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

# Disable weak protocols and ciphers
SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
SSLHonorCipherOrder On
EOL

# Configure Apache headers
log_message "INFO" "Configuring Apache SSL settings."
cat <<EOL > $HTTPD_VHOST_CONF
# Redirect HTTP (port 80) to HTTPS
<VirtualHost *:80>
    # Set the ServerName for the redirect target
    ServerName {{VHOST_NAME}}
    # Redirect all traffic to HTTPS
    Redirect permanent / https://{{VHOST_NAME}}/
</VirtualHost>

# Secure HTTPS VirtualHost
<VirtualHost *:443>
    # ServerName for the HTTPS site
    ServerName {{VHOST_NAME}}

    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /etc/httpd/ssl/server.crt
    SSLCertificateKeyFile /etc/httpd/ssl/server.key

    # Strong SSL/TLS protocols and ciphers
    SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
    SSLHonorCipherOrder On

    # Document Root
    DocumentRoot /usr/local/nagios/share

    # Ensure requests match ServerName
    <Directory "/usr/local/nagios/share">
        Options None
        AllowOverride None
        Require all granted
    </Directory>

    # Log files
    ErrorLog /var/log/httpd/nagiosxi_error.log
    CustomLog /var/log/httpd/nagiosxi_access.log combined
</VirtualHost>
EOL

# Configure mod_security rules
log_message "INFO" "Configuring mod_security rules."
mkdir -p "$(dirname "$MODSEC_RULES_PATH")"
cat <<EOL > "$MODSEC_RULES_PATH"
<LocationMatch .*>
  <IfModule mod_security2.c>
    SecRuleRemoveById 981203
    SecRuleRemoveById 981204
    SecRuleRemoveById 950117
    SecRuleRemoveById 950005
    SecRuleRemoveById 960008
    SecRuleRemoveById 960015
    SecRuleRemoveById 960017
    SecRuleRemoveById 950109
    SecRuleRemoveById 950901
    SecRuleRemoveById 950908
    SecRuleRemoveById 960024
    SecRuleRemoveById 981173
    SecRuleRemoveById 981257
    SecRuleRemoveById 981245
    SecRuleRemoveById 981242
    SecRuleRemoveById 981246
    SecRuleRemoveById 973306
    SecRuleRemoveById 973332
    SecRuleRemoveById 973333
    SecRuleRemoveById 973335
    SecRuleRemoveByID 981318
    SecRuleRemoveByID 921130
    SecRuleRemoveByID 932160
    SecRuleRemoveByID 932260
    SecRuleRemoveByID 941100
    SecRuleRemoveByID 941130
    SecRuleRemoveByID 941140
    SecRuleRemoveByID 941160
    SecRuleRemoveByID 941170
    SecRuleRemoveByID 941180
    SecRuleRemoveByID 941190
    SecRuleRemoveByID 941260
    SecRuleRemoveByID 942190
    SecRuleRemoveByID 942290
    SecRuleRemoveByID 949110
    SecRuleRemoveByID 980170
  </IfModule>
</LocationMatch>
EOL

# Configure SELinux policies
log_message "INFO" "Configuring SELinux policies."
configure_selinux_boolean httpd_can_network_connect 1
configure_selinux_boolean httpd_enable_cgi 1
configure_selinux_boolean httpd_can_network_connect_db 1
configure_selinux_boolean httpd_can_connect_ldap 1
#configure_selinux_boolean httpd_can_sendmail 1
# Use Microsoft OAuth to send emails not sendmail


if [ -d "/usr/local/nagios" ]; then
    configure_selinux_context "/usr/local/nagios(/.*)?" "httpd_sys_content_t"
    configure_selinux_context "/usr/local/nagios/var(/.*)?" "httpd_sys_rw_content_t"
    configure_selinux_context "/var/www/html/ssl(/.*)?" "httpd_sys_content_t"
    configure_selinux_context "/usr/local/nagiosxi(/.*)?" "httpd_sys_content_t"
else
    echo "[!] Directory /usr/local/nagios does not exist. Skipping SELinux relabeling."
fi

# Set SELinux to enforcing mode
if [[ "$(getenforce)" != "Enforcing" ]]; then
    log_message "INFO" "Enabling enforcing mode for SELinux."
    setenforce 1
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
fi

# Create HTML custom error pages
create_error_pages

# Ensure auditd logging is enabled
systemctl enable --now auditd

# Set root and user passwords
log_message "INFO" "Setting user passwords."
 echo "root:${ROOT_PASSWORD}" | chpasswd
 echo " ${ROOT_PASSWORD}"  # Password output for password manager
chsh -s /usr/sbin/nologin root
 echo "${ADMIN_USER}:${USER_PASSWORD}" | chpasswd
 echo " ${USER_PASSWORD}"  # Password output for password manager

# Configure Nagios admin password
log_message "INFO" "Configuring Nagios admin password."
htpasswd -b /usr/local/nagios/etc/htpasswd.users nagiosadmin "$NAGIOSADMIN_PASSWORD"
 echo " ${NAGIOSADMIN_PASSWORD}"  # Password output for password manager

log_message "INFO" "Ensuring run level is multi-user."
systemctl set-default multi-user.target

log_message "INFO" "====== NagiosXI Host Configuration Complete ======"
