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
HOSTNAME=$(hostname)
OSID=$(grep ID_LIKE /etc/os-release | cut -d"=" -f 2)
if [ "$OSID" == '"debian"' ]; then

        printf "[*] Using the Debian based OS settings \n"
        CAFILE="/etc/ssl/certs/ca-certificates.crt"
        CAPATH="/etc/ssl/certs"
        CERTFILE="/etc/ssl/certs/ssl-cert-snakeoil.pem"
        KEYFILE="/etc/ssl/private/ssl-cert-snakeoil.key"

        apt-get update && apt-get install -y libsasl2-modules postfix mailutils
        wait

elif [ "$OSID" == '"fedora"' ]; then

        printf "[*] Using the Fedora based OS settings \n"
        CAFILE="/etc/pki/tls/certs/ca-bundle.crt"
        CAPATH="/etc/pki/tls/certs"
        CERTFILE="/etc/pki/tls/certs/postfix.pem"
        KEYFILE="/etc/pki/tls/private/postfix.key"

        printf "[*] Installing the postfix service \n"
        dnf install -y postfix
        wait

else
        printf "[!] Operating system ID is not Debian or Fedora \n"
        exit 1
fi


printf "[*] Backing up original main.cf file \n"
cp /etc/postfix/main.cf /etc/postfix/main.cf.orig


OPTIONS=("Office365" "Gmail" "Custom" "Quit")
echo "    1.) ${OPTIONS[0]}"
echo "    2.) ${OPTIONS[1]}"
echo "    3.) ${OPTIONS[2]}"
echo "    4.) ${OPTIONS[3]}"

read -p "[?] Choose from one of the email providers below: " OPT
case $OPT in
        1)
                printf "[*] Office365 SMTP values will be defined using STARTTLS \n"

                printf "[*] Prompting for the required variable values \n"
                SMTPSERVER="smtp.office365.com"
                PORT="587"

                printf "[?] Enter the domain to send emails from : ";
                read DOMAIN

                printf "[?] Enter the email address to send from : ";
                read EMAIL

                printf "[?] Enter the email accounts password : ";
                read -s PASS
        ;;
        2)
                printf "[*] Gmail SMTP values will be defined using STARTTLS \n"

                SMTPSERVER="smtp.gmail.com"
                PORT="587"

                printf "[*] Prompting for the required variable values \n"
                printf "[?] Enter the domain to send emails from : ";
                read DOMAIN

                printf "[?] Enter the email address to send from : ";
                read EMAIL

                printf "[?] Enter your Application-Specific Gmail accounts password : ";
                read -s PASS
        ;;
        3)
                printf "[*] Custom SMTP values will be defined \n"
                printf "[*] Prompting for the required variable values \n"

                printf "[?] Enter the domain to send emails from : ";
                read DOMAIN

                printf "[?] Enter the email address to send from : ";
                read EMAIL

                printf "[?] Enter the email accounts password : ";
                read -s PASS

                printf "[?] Enter your SMTP server address EXAMPLE: smtp.office365.com : ";
                read SMTPSERVER

                printf "[?] Enter the SMTP port to use. Recommended is 587 [465|587] : ";
                read PORT
        ;;
        4)
                break
        ;;
        *)
                printf "[x] Invalid option $REPLY \n"
        ;;
esac


printf "[*] Creating Diffie-Hellman keys \n"
openssl dhparam -out /etc/ssl/certs/postfix-dh1024.tmp 1024 && mv /etc/ssl/certs/postfix-dh1024.tmp /etc/ssl/certs/postfix-dh1024.pem
wait
chmod 644 /etc/ssl/certs/postfix-dh1024.pem


printf "[*] Creating /etc/mailname file \n"
echo "${DOMAIN}" > /etc/mailname


printf "[*] Using encrypted SASL Authentication \n"
mkdir -p /etc/postfix/sasl
echo "[${SMTPSERVER}]:${PORT} ${EMAIL}:${PASS}" > /etc/postfix/sasl/sasl_passwd
postmap /etc/postfix/sasl/sasl_passwd
if [ -f /etc/postfix/sasl/sasl_passwd.db ]; then
        printf "[*] Created encrypted password file sasl_passwd.db \n"
        rm -rf /etc/postfix/sasl/sasl_passwd
else
        printf "[!] Verify the file /etc/postfix/sasl/sasl_passwd.db \n"
        printf "[i] Delete the file /etc/posftix/sasl/sasl_passwd once verified \n"
fi
printf "[*] Securing permissions on the /etc/postfix/sasl directory \n"
chown -R root:root /etc/postfix/sasl/
chmod -R 0600 /etc/postfix/sasl/


printf "[*] Updating email aliases for local user accounts \n"
echo "root:           ${EMAIL}" >> /etc/aliases
newaliases
postalias /etc/aliases
wait


printf "[*] Defining MIME header checks that block emails sending executable files \n"
echo '/name=[^>]*\.(bat|com|exe|dll|vbs)/ REJECT' > /etc/postfix/mime_header_checks


printf "[*] Creating main.cf file using the values you defined \n"
CONFIG=$(cat <<EOF > /etc/postfix/main.cf
smtpd_banner = $DOMAIN SMTP Server
biff=no
compatibility_level = 2
queue_directory = /var/spool/postfix
command_directory = /usr/sbin
daemon_directory = /usr/libexec/postfix
data_directory = /var/lib/postfix
mail_owner = postfix
unknown_local_recipient_reject_code = 550
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
home_mailbox = Maildir/
sendmail_path = /usr/sbin/sendmail.postfix
newaliases_path = /usr/bin/newaliases.postfix
mailq_path = /usr/bin/mailq.postfix
setgid_group = postdrop
html_directory = no
manpage_directory = /usr/share/man
sample_directory = /usr/share/doc/postfix/samples
readme_directory = no
smtpd_tls_cert_file = $CERTFILE
smtpd_tls_key_file = $KEYFILE
smtpd_tls_security_level = may
smtp_tls_CApath = $CAPATH
smtp_tls_CAfile = $CAFILE
smtp_tls_security_level = may
meta_directory = /etc/postfix
shlib_directory = /usr/lib64/postfix
smtp_generic_maps = hash:/etc/postfix/generic
myhostname = $HOSTNAME
mydomain = $DOMAIN
masquerade_domains = $DOMAIN
myorigin = /etc/mailname
append_dot_mydomain=no
inet_protocols = ipv4
mynetworks = 127.0.0.0/8
inet_interfaces = loopback-only
relayhost = [$SMTPSERVER]:$PORT
relay_destination_concurrency_limit=20
header_size_limit=4096000
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_sasl_tls_security_options = noanonymous
smtp_use_tls = yes
smtp_always_send_ehlo = yes
disable_vrfy_command=yes
smtpd_discard_ehlo_keywords = chunking
recipient_delimiter = +
tls_high_cipherlist=ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:-DES:!RC4:!MD5:!PSK:!aECDH:EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA
smtpd_tls_mandatory_exclude_ciphers=aNULL
smtpd_tls_exclude_ciphers=aNULL
tls_preempt_cipherlist = no
smtpd_tls_dh1024_param_file=/etc/ssl/certs/postfix-dh1024.pem
smtp_tls_loglevel=1
smtpd_tls_loglevel=1
smtpd_tls_received_header=yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
tls_ssl_options=NO_COMPRESSION
smtp_use_tls=yes
smtpd_use_tls=yes
smtpd_tls_mandatory_protocols=!SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_protocols=!SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_ciphers=high
mime_header_checks = regexp:/etc/postfix/mime_header_checks

sender_canonical_classes = envelope_sender, header_sender
sender_canonical_maps =  regexp:/etc/postfix/sender_canonical_maps
smtp_header_checks = regexp:/etc/postfix/header_check

strict_rfc821_envelopes=yes
EOF
)


printf "[*] Telling Postfix service to start at login and to start up \n"
systemctl enable --now postfix


printf "[*] Waiting for Postfix service to create /etc/postfix/generic \n"
while [ ! -f /etc/postfix/generic ]; do
        systemctl start postfix
        sleep 10s
done

echo "root@localhost" >> /etc/postfix/generic
echo "root@${HOSTNAME}.local" >> /etc/postfix/generic
echo "root@${HOSTNAME} ${EMAIL}" >> /etc/postfix/generic
echo "@${HOSTNAME} ${EMAIL}" >> /etc/postfix/generic
echo "/.+/    ${EMAIL}" > /etc/postfix/sender_canonical_maps
echo "/From:.*/ REPLACE From: ${EMAIL}" > /etc/postfix/header_check


printf "[*] Securing permissions on the /etc/postfix/generic file \n"
chown root:root /etc/postfix
chown root:root /etc/postfix/generic
chmod 0600 /etc/postfix/generic
postmap /etc/postfix/generic
wait


printf "[*] Restarting the Postfix service to apply changes \n"
systemctl restart postfix


printf "[*] Sending test email to ${EMAIL} \n"
echo -e "FROM: root\nTO: root\nSubject: Test Email\n\nThis is a test email" | /sbin/sendmail -t
