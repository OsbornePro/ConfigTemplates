#!/bin/bash
# OsbornePro - Server Hardening Script
# Harden CentOS for hosting NagiosXI with enhanced security and maintainability
#-------------------------------------------------------------------------------
# How to use this script
#-------------------------------------------------------------------------------
# 1.) Download your NagiosXI image from https://www.nagios.com/products/nagios-xi/downloads/#downloads
# 2.) Login to the image you setup and run this script
# 3.) Save the passwords printed out at the end so you can use them to login
# NOTE: SELinux is unable to be turned on in the NagiosXI OVA file so I commented those parts out in this script

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

# Function to set apache configuration settings
set_or_update_httpd_ssl_setting() {
    local setting="$1"
    local value="$2"
    local file="$3"

    if grep -qE "^${setting}\b" "$file"; then
        sed -i "s|^${setting}.*|${setting} ${value}|" "$file"
        echo "Updated: ${setting} ${value}"
    else
        echo "${setting} ${value}" >> "$file"
        echo "Added: ${setting} ${value}"
    fi
}

# Function to create error pages
create_error_pages() {
    local error_codes=(
        400 401 402 403 404 405 406 407 408 409 410
        411 412 413 414 415 416 417 418 421 422 423
        424 425 426 428 429 431 451 500 501 502 503
        504 505 506 507 508 510 511
    )
    local output_dir="/usr/local/nagios/share/errors"
    mkdir -p "$output_dir"
    for code in "${error_codes[@]}"; do
        local file_path="$output_dir/$code.html"
        # echo "ErrorDocument $code /errors/$code.html" >> /etc/httpd/conf/httpd.conf
        if ! printf '<h1>Error %s</h1>\n' "$code" > "$file_path"; then
            log_message "ERROR" "Failed to create error page for code: $code"
            return 1
        fi
    done
    chown -R nagios:nagios ${output_dir}/
    log_message "INFO" "Error pages created in $output_dir"
}

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    log_message "ERROR" "This script must be run as root. Use sudo."
    exit 1
fi
log_message "INFO" "====== Preparing the Host for NagiosXI ======"

# Update the system
log_message "INFO" "Updating the OS to the latest versions."
dnf -y update || { log_message "ERROR" "System update failed."; exit 1; }

# Install required packages
log_message "INFO" "Installing required packages."
dnf install -y vim mlocate epel-release mod_security mod_ssl policycoreutils-python-utils aide scap-workbench scap-security-guide tuned audit || {
    log_message "ERROR" "Failed to install required packages."
    exit 1
}

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
OSCAP_DIR="/var/log/openscap"
SSL_DIR="/etc/httpd/ssl"
CERT_FILE="${SSL_DIR}/server.crt"
KEY_FILE="${SSL_DIR}/server.key"
ROOT_PASSWORD=$(generate_password)
USER_PASSWORD=$(generate_password)
NAGIOSADMIN_PASSWORD=$(generate_password)
ADMIN_USER="nagiosadmin"
SSL_CONF="/etc/httpd/conf.d/ssl.conf"
HTTPD_CONF="/etc/httpd/conf/httpd.conf"
MODSEC_RULES_PATH="/etc/httpd/modsecurity.d/mod_security_excluded_rules.conf"
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

# Ensure the journal directory exists
JOURNAL_DIR="/var/log/journal"
if [ ! -d "$JOURNAL_DIR" ]; then
    log_message "INFO" "Creating persistent journal directory: $JOURNAL_DIR"
    mkdir -p "$JOURNAL_DIR"
    chmod 2755 "$JOURNAL_DIR"
    log_message "INFO" "Directory created successfully."
else
    log_message "INFO" "Persistent journal directory already exists."
fi

# Update the systemd journald configuration and restart the service
CONFIG_FILE="/etc/systemd/journald.conf"
if grep -q "^#Storage=" "$CONFIG_FILE"; then
    log_message "INFO" "Updating Storage option in $CONFIG_FILE"
    sed -i 's/^#Storage=.*/Storage=persistent/' "$CONFIG_FILE"
elif grep -q "^Storage=" "$CONFIG_FILE"; then
    log_message "INFO" "Ensuring Storage option is set to persistent in $CONFIG_FILE"
    sed -i 's/^Storage=.*/Storage=persistent/' "$CONFIG_FILE"
else
    log_message "INFO" "Appending Storage option to $CONFIG_FILE"
    echo "Storage=persistent" >> "$CONFIG_FILE"
fi
log_message "INFO" "Restarting systemd-journald service"
systemctl restart systemd-journald

log_message "INFO" "Ensuring run level is multi-user."
systemctl set-default multi-user.target

# Configure /etc/skel for new users
curl -k https://raw.githubusercontent.com/OsbornePro/ConfigTemplates/refs/heads/main/.vimrc -o /etc/skel/.vimrc || wget https://raw.githubusercontent.com/OsbornePro/ConfigTemplates/refs/heads/main/.vimrc -o /etc/skel/.vimrc
cd /etc/skel
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
cd /home
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
if ! grep -q "^${editor_config}" /etc/skel/.bashrc; then
    echo "$editor_config" >> /etc/skel/.bashrc
fi
if ! grep -q "^${visual_config}" /etc/skel/.bashrc; then
    echo "$visual_config" >> /etc/skel/.bashrc
fi

# Ensure auditd logging is enabled
systemctl enable --now auditd

# Used the recommended tuned profile
log_message "INFO" "Using the recommended tuned-adm profile $(tuned-adm recommend)."
systemctl start tuned
systemctl enable --now tuned
tuned-adm profile $(tuned-adm recommend)

# Perform security audits
log_message "INFO" "Running OpenSCAP scan in background. Saving results to $OSCAP_DIR"
mkdir -p $OSCAP_DIR
chmod 700 $OSCAP_DIR
cd $OSCAP_DIR
umask 066
cd -
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --results "${OSCAP_DIR}/scan.xml" /usr/share/xml/scap/ssg/content/ssg-c*-ds.xml > /dev/null 2>&1 &

# Setup Intrusition Protection and Monitoring
log_message "INFO" "Initializing 'Aide' Intrusion detection and monitoring."
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Configure Apache to use HTTPS
set_or_update_httpd_ssl_setting "ServerTokens" "Prod" "$HTTPD_CONF"
set_or_update_httpd_ssl_setting "ServerSignature" "Off" "$HTTPD_CONF"
set_or_update_httpd_ssl_setting "TraceEnable" "Off" "/etc/httpd/conf.d/nagiosxi.conf"
set_or_update_httpd_ssl_setting "Header always set X-Content-Type-Options" "\"nosniff\"" "$SSL_CONF"
set_or_update_httpd_ssl_setting "Header always set X-Frame-Options" "\"SAMEORIGIN\"" "$SSL_CONF"
set_or_update_httpd_ssl_setting "SSLProtocol" "All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1" "$SSL_CONF"
set_or_update_httpd_ssl_setting "SSLCipherSuite" "HIGH:!aNULL:!MD5:!3DES" "$SSL_CONF"
set_or_update_httpd_ssl_setting "SSLHonorCipherOrder" "On" "$SSL_CONF"
set_or_update_httpd_ssl_setting "SSLEngine" "on" "$SSL_CONF"
set_or_update_httpd_ssl_setting "SSLCertificateFile" "/etc/httpd/ssl/server.crt" "$SSL_CONF"
set_or_update_httpd_ssl_setting "SSLCertificateKeyFile" "/etc/httpd/ssl/server.key" "$SSL_CONF"
log_message "INFO" "SSL configuration has been updated."

# Create HTML custom error pages
create_error_pages

# Delete default welcome page which gives away version if ever exposed
rm -rf -- /etc/httpd/conf.d/welcome.conf

# Configure mod_security rules
log_message "INFO" "Configuring mod_security rules."
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

log_message "INFO" "Testing Apache configuration"
if apachectl configtest; then
    log_message "INFO" "Apache configuration is valid. Restarting httpd"
    systemctl restart httpd
    log_message "INFO" "Apache restarted successfully"
else
    log_message "ERROR" "Apache configuration test failed. Use systemctl and journal to see what is wrong"
fi

# NOTE: The NagiosXI Image does not appear to allow you to use SELinux
# Configure SELinux policies
#log_message "INFO" "Configuring SELinux policies."
#configure_selinux_boolean httpd_can_network_connect 1
#configure_selinux_boolean httpd_enable_cgi 1
#configure_selinux_boolean httpd_can_network_connect_db 1
#configure_selinux_boolean httpd_can_connect_ldap 1
#configure_selinux_boolean httpd_can_sendmail 1
# Use Microsoft OAuth to send emails not sendmail

#if [ -d "/usr/local/nagios" ]; then
#    configure_selinux_context "/usr/local/nagios(/.*)?" "httpd_sys_content_t"
#    configure_selinux_context "/usr/local/nagios/var(/.*)?" "httpd_sys_rw_content_t"
#    configure_selinux_context "/var/www/html/ssl(/.*)?" "httpd_sys_content_t"
#    configure_selinux_context "/usr/local/nagiosxi(/.*)?" "httpd_sys_content_t"
#else
#    echo "[!] Directory /usr/local/nagios does not exist. Skipping SELinux relabeling."
#fi

# Set SELinux to enforcing mode
#if [[ "$(getenforce)" != "Enforcing" ]]; then
#    log_message "INFO" "Enabling enforcing mode for SELinux."
#    setenforce 1
#    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
#fi

# Set root and user passwords
log_message "INFO" "Setting user passwords."
 echo "root:${ROOT_PASSWORD}" | chpasswd
 echo " ${ROOT_PASSWORD}"  # Password output for password manager
usermod -s /usr/sbin/nologin root
 echo "${ADMIN_USER}:${USER_PASSWORD}" | chpasswd
 echo " ${USER_PASSWORD}"  # Password output for password manager

# Configure Nagios admin password
log_message "INFO" "Configuring Nagios admin password."
 /usr/local/nagiosxi/scripts/reset_nagiosadmin_password.php --password="$NAGIOSADMIN_PASSWORD"
 echo " ${NAGIOSADMIN_PASSWORD}"  # Password output for password manager

log_message "INFO" "====== NagiosXI Host Configuration Complete ======"
