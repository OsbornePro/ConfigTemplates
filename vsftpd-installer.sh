#!/bin/bash
###################################################################################################
#  DESCRIPTION:                                                                                   #
#  This script is used to quickly and easily configure a secure FTP over SSL server on Linux      #
#  This will allow whitelisted authenticated users upload and download access to personal FTP dir #  
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
	      CONFFILE="/etc/vsftpd.conf"
	      CERTFILE="/etc/ssl/certs/vsftpd.crt"
	      KEYFILE="/etc/ssl/private/vsftpd.key"
	      USERLIST="/etc/vsftpd.userlist"

        printf "[*] Installing the vsftpd service \n"
        apt-get update && apt-get install -y vsftpd openssl ufw
        wait

	      printf "[*] Opening firewall rules for FTP service"
	      ufw allow 20:21/tcp
        ufw allow 40000:41000/tcp
        ufw reload

elif [ "$OSID" == '"fedora"' ]; then

        printf "[*] Using the Fedora based OS settings \n"
	      CONFFILE="/etc/vsftpd/vsftpd.conf"
	      CERTFILE="/etc/pki/tls/certs/vsftpd.crt"
	      KEYFILE="/etc/pki/tls/private/vsftpd.key"
	      USERLIST="/etc/vsftpd/vsftpd.userlist"

        printf "[*] Installing the vsftpd service \n"
        dnf install -y vsftpd openssl
        wait

	      printf "[*] Opening firewall rules for FTP service"
	      firewall-cmd --zone=public --add-port=21/tcp --permanent
        firewall-cmd --zone=public --add-port=20/tcp --permanent
        firewall-cmd --zone=public --add-port=40000-41000/tcp
        firewall-cmd --reload

else
        printf "[!] Operating system ID is not Debian or Fedora \n"
        exit 1
fi


printf "[*] Backing up original vsftpd.conf file \n"
cp "${CONFFILE}" "${CONFFILE}.orig" && printf "[*] Created backup of originali vsftpd.conf file at ${CONFFILE}.orig \n"


CONFIG=$(cat <<EOF > $CONFFILE 
#------------------------------------------------------------------------------
# CONFIGURED SETTINGS
#------------------------------------------------------------------------------
# LISTENERS
listen=YES
listen_port=21
listen_ipv6=NO
session_support=YES
pasv_enable=YES
connect_from_port_20=YES
ftp_data_port=20
pasv_min_port=40000
pasv_max_port=41000

# SET THE BELOW VALUE IF YOUR FTP SERVER IS PUBLICLY ACCESSIBLE
#pasv_address=<Public IP Address or hostname>
#pasv_addr_resolve=YES

# RESTRICT COMMANDS THAT CAN BE EXECUTED
#cmds_allowed=ABOR,ACCT,ALLO,APPE,BINARY,CDUP,CWD,DELE,EPRT,EPSV,FEAT,HELP,LIST,MDTM,MODE,NLST,NOOP,OPTS,PASS,PASV,PORT,PWD,QUIT,REIN,REST,RETR,RMD,RNFR,RNTO,SITE,SIZE,SMNT,STAT,STOR,STOU,STRU,SYST,TYPE,USER,XCUP,XCWD,XPWD,XRMD
#cmds_denied=PUT,MPUT,RM,RMD,RMDIR,XRMD,MKD,MKDIR,XMKD

# PERMISSIONS
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
anon_upload_enable=NO
anon_mkdir_write_enable=NO
user_sub_token=$USER
local_root=/home/$USER/ftp
userlist_enable=YES
userlist_file=$USERLIST
userlist_deny=NO
allow_writeable_chroot=NO
nopriv_user=ftpsecure
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd/empty
ls_recurse_enable=NO

# LOGGING
syslog_enable=NO
dual_log_enable=YES
vsftpd_log_file=/var/log/vsftpd.log
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
xferlog_file=/var/log/vsftpd.log
xferlog_std_format=NO
log_ftp_protocol=YES
debug_ssl=YES

# SESSIONS
idle_session_timeout=600
data_connection_timeout=120

# CHAR
ascii_upload_enable=NO
ascii_download_enable=NO
#utf8_filesystem=YES

# BANNER
ftpd_banner=FTP over SSL Server
# OR You can use a file to load a banner
#banner_file=/etc/vsftpd.welcome_banner

# SERVICE
pam_service_name=ftp

# SSL SETTINGS
rsa_cert_file=$CERTFILE
rsa_private_key_file=$KEYFILE
ssl_enable=YES
ssl_ciphers=HIGH
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO

# SET THIS TO YES IF YOU ARE USING PORT 990
implicit_ssl=NO
EOF
)

printf "[*] Generating a self signed SSL certificate \n"
openssl req -newkey rsa:2048 -x509 -sha256 -days 365 -subj "/CN=${HOSTNAME}/OU=Certificates" -nodes -out $CERTFILE -keyout $KEYFILE
wait

printf "[*] Creating least privilege 'ftpsecure' user for FTP service \n"
useradd ftpsecure

printf "[*] Creating an FTP directory for all local users on this device and adding them to the allowed FTP users list in $USERLIST \n"
USERS=$(ls /home)
for u in $USERS; do
	echo $u >> $USERLIST 
	mkdir -p /home/$u/ftp/files
	chown nobody:nogroup /home/$u/ftp
	chown $u:$u /home/$u/ftp/files
	chmod a-w /home/$u/ftp
 done

printf "[*] Backing up current VSFTPD configuration file \n"
cp "${CONFFILE}" "${CONFFILE}.bak" && printf "[*] Created backup of active vsftpd.conf file at ${CONFFILE}.bak \n"

printf "[*] Restarting the VSFTPD service with latest config"
systemctl enable --now vsftpd.service && systemctl status vsftpd.service
