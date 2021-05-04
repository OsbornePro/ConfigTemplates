#!/bin/bash
#
# This script is meant to be used as a cron job that runs once a year. This deletes the expired key and certificate and generates a new certificate for the VSFTPD server to use
# Follow best practices by placing the cronjob-vsftpd-cert-expires.sh script into /usr/local/sbin/ allowing the root user to execute it. Then modify permissions so only the root user can see the script
# chmod 700 /usr/local/sbin/cronjob-vsftpd-cert-expires.sh
#
# CRONTAB ENTRY EXAMPLE THAT RUNS ONCE A YEAR AS ROOT ON MAY FIRST
# 0 0 1 5 * /bin/bash /usr/local/sbin/cronjob-vsftpd-cert-expires.sh

/bin/echo "[*] Deleting expired certificate"
/bin/rm -rf --preserve-root -- /etc/ssl/certs/vsftpd.crt
/bin/echo "[*] Deleting expired certificate key"
/bin/rm -rf --preserve-root -- /etc/ssl/private/vsftpd.pem

/bin/sleep 3s

/bin/echo "[*] Generating new SSL certificate and key replacement"
/usr/bin/openssl req -newkey rsa:2048 -x509 -sha256 -days 365 -subj '/C=US/ST=Colorado/L=Colorado Springs/CN=ftp.osbornepro.com/O=OsbornePro LLC./OU=Certificates/emailAddress=info@osbornepro.com' -nodes -out /etc/ssl/certs/vsftpd.crt -keyout /etc/ssl/private/vsftpd.pem

/bin/echo "[*] Restarting the VSFTPD service"
/bin/systemctl restart vsftpd.service
