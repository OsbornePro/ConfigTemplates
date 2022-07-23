#!/bin/bash
##########################################################################################################################
#  DESCRIPTION:                                                                                                          #
#  This script is used to quickly and easily configure the SSH service on a Linux device with key authentication         #
#                                                                                                                        #
#   Company: OsbornePro LLC.                                                                                             #
#   Website: https://osbornepro.com                                                                                      #
#   Author: Robert H. Osborne                                                                                            #
#   Contact: rosborne@osbornepro.com                                                                                     #
#                                                                                                                        #
##########################################################################################################################
HOSTNAME=$(hostname)
OSID=$(grep ID_LIKE /etc/os-release | cut -d"=" -f 2)
if [ "$OSID" == '"debian"' ]; then

        printf "[*] Using the Debian based OS settings \n"
	printf "[*] Installing the SSH service \n"
        apt-get update && apt-get install openssh-server openssh-client 
        wait

	printf "[*] Opening firewall rules for SSH service"
	DEBIANBANNER="DebianBanner no"
	SYSLOGFACIL="USER"
	ufw allow 22/tcp
        ufw reload

elif [ "$OSID" == '"fedora"' ]; then

        printf "[*] Using the Fedora based OS settings \n"
        printf "[*] Installing the SSH service \n"
        dnf install -y openssh-server openssh-clients 
        wait

	printf "[*] Opening firewall rules for SSH service"
	DEBIANBANNER=" "
	SYSLOGFACIL="AUTHPRIV"
	firewall-cmd --zone=public --add-port=22/tcp --permanent
        firewall-cmd --reload

else
        printf "[!] Operating system ID is not Debian or Fedora \n"
        exit 1
fi

printf "[*] Creating SSH users security group and adding users to group"
groupadd sshusers
USERS=$(ls /home)
for u in $USERS; do
	usermod -aG sshusers $u
done


CONFFILE="/etc/ssh/sshd_config"
printf "[*] Backing up original sshd_config file \n"
cp "${CONFFILE}" "${CONFFILE}.orig" && printf "[*] Created backup of originali sshd_config file at ${CONFFILE}.orig \n"


CONFIG=$(cat <<EOF > $CONFFILE
# \$OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tj Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

# Include /etc/ssh/sshd_config.d/*.conf

Port 22
Protocol 2
AddressFamily inet
ListenAddress 0.0.0.0
#ListenAddress ::


# Ciphers and keying
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
# File locations to save the servers private host keys

RekeyLimit default none
# Specifies the number of times a users SSH private key can be different when signing in. If you are good about never rekeying SSH certificates this is a strong security setting to have
# This limit also refers to the rotation of sessoin keys. The more often a session key is rotated can help prevent any kind of decryption from being performed

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
# Specifies the ciphers allowed for SSH protocol version 2. CBC has a flaw in its algorithm and can be decrypted. Do not use the CBC block chain.

KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
# Specifies the encryptions to use for key exchange.
# A symmetric key is required in order to start a key exchange. Keys are not actually exchanged. Public variables are combined with Private variables to create a key and begin initial secure communication

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
# What SSH algorithms should be used for integrity checks

# Logging
SyslogFacility ${SYSLOGFACIL}
LogLevel INFO

# Authentication:
LoginGraceTime 20
# How long in seconds after a connection request the server waits before disconnecting if a user has not successfully logged in

PermitRootLogin no
# This settings allows or prevents the root user from using SSH to sign into a machine via password or public key. Sudo users can still elevate privilege

StrictModes yes
# Specifies whether SSH should check file modes and ownership of the user's files and home directory before accepting login. This is normally desirable because novices sometimes accidentally leave their directory or files world-writable. The default is ''yes''.
# You may have experienced this setting before when you have needed to do chmod 600 id_rsa in order to sign into a remote machine over SSH

MaxAuthTries 3
# Specifies the maximum number of authentication attempts permitted per connection. Once the number of failures reaches half this value, additional failures are logged. The default is 6

MaxSessions 6
# Specifies the maximum number of open sessions permitted per network connection. The default is 10.

PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys.%u # RHEL

#AuthorizedPrincipalsFile none
#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

#=================================
# HOST BASED AUTHENTICATION
#=================================
# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
# This can be done with the command 'ssh-keyscan toborMINT | tee -a /etc/ssh/ssh_known_hosts'
HostbasedAuthentication no
# A setting of ''yes'' means that sshd uses the name supplied by the client rather than attempting to resolve the name from the TCP connection itself. The default is ''no''.
# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
# Change to yes if you don't trust ~/.ssh/known_hosts for
# If you use a proxy this setting is not helpful because the host keys will be the same for all connections

# THE CLIENT CONFIGURATION SHOULD LIKE THIS (ssh_config)
#Host *.pool.example.org
#	HostbasedAuthentication yes
#	EnableSSHKeysign yes
#       ServerAliveCountMax 3
#	ServerAliveInterval 60



#HostbasedUsesNameFromPacketOnly yes
# Specifies whether or not the server will attempt to perform a reverse name lookup when matching the name in the ~/.shosts, ~/.rhosts, and /etc/hosts.equiv files during HostbasedAuthentication

IgnoreUserKnownHosts yes
# Specifies whether sshd should ignore the user's ~/.ssh/known_hosts during RhostsRSAAuthentication or HostbasedAuthentication. The default is ''no''

IgnoreRhosts yes
# Specifies that .rhosts and .shosts files will not be used in RhostsRSAAuthentication or HostbasedAuthentication.
# /etc/hosts.equiv and /etc/ssh/shosts.equiv are still used. The default is ''yes''.

# RhostsRSAAuthentication yes
# This specifies whether sshd can try to use rhosts based authentication. Because rhosts authentication is insecure you shouldn't use this option.

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication no
PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
#ChallengeResponseAuthentication no # Debian
ChallengeResponseAuthentication yes # RHEL, CentOS

# Kerberos options
KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes 
# Depending on your situation you may want this set to yes. When a user account has its password disabled the SSH key authentication may not work unless this is set to yes

AllowGroups sshusers
# Defines a group a user is required to be a member of in order to be allowed SSH access
# AllowUsers tobor rob chris tom
# Allow users can be used instead of Allow groups if desired

#DenyGroups
# Deny Groups and users can also be defined as well. Typically it is easier to make a whitelist by adding allowed users to a group
#DenyUsers

AllowAgentForwarding yes
AllowTcpForwarding yes

GatewayPorts no


X11Forwarding yes
# Enable this if I plan on using X11 to open applications on a remote device through SSH
X11DisplayOffset 10
X11UseLocalhost yes

PermitTTY yes

PrintMotd yes
# Great for printing a welcome message after authenticating to the server

PrintLastLog yes
# Considered more secure while the answer is yes so the person signing in can verify the last time they logged in

TCPKeepAlive no
# I turn this off and use Client Keep Alive's instead
# Specifies whether the system should send TCP keepalive messages to the other side. If they are sent, death of the connection or crash of one of the machines will be properly noticed
# However, this means that connections will die if the route is down temporarily, and some people find it annoying.
# On the other hand, if TCP keepalives are not sent, sessions may hang indefinitely on the server, leaving ''ghost'' users and consuming server resources. I use Client Keep Alives instead


PermitUserEnvironment no
# Specifies whether ~/.ssh/environment and environment= options in ~/.ssh/authorized_keys are processed by sshd.
# The default is ''no''. Enabling environment processing may enable users to bypass access restrictions in some configurations using mechanisms such as LD_PRELOAD.

Compression delayed
# Specifies whether compression is allowed, or delayed until the user has authenticated successfully. The argument must be ''yes'', ''delayed'', or ''no''. The default is ''delayed''.
# This can be helpful to enable if your connection is slow

ClientAliveInterval 15
# Sets a timeout interval in seconds after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response from the client.
# The default is 0, indicating that these messages will not be sent to the client. This option applies to protocol version 2 only.

ClientAliveCountMax 3
# Sets the number of client alive messages from setting above which may be sent without sshd receiving any messages back from the client.

UseDNS no
# Specifies whether sshd should look up the remote host name and check that the resolved host name for the remote IP address maps back to the very same IP address. The default is ''yes''.
# I change this to no because the option is basically useless

PidFile /var/run/sshd.pid

MaxStartups 10:30:100
# Specifies the maximum number of concurrent unauthenticated connections to the SSH daemon. Additional connections will be dropped until authentication succeeds
# start:rate:full
#     sshd will refuse connection attempts with a probability of ``rate/100'' (30%) if there are currently ``start'' (10) unauthenticated connections.
#     The probability increases linearly and all connection attempts are refused if the number of unauthenticated connections reaches ``full'' (60).

PermitTunnel no
# Specifies whether tun device forwarding is allowed. The argument must be ''yes'', ''point-to-point'' (layer 3), ''ethernet'' (layer 2), or ''no''. Specifying ''yes'' permits both ''point-to-point'' and ''ethernet''. The default is ''no''.

ChrootDirectory none
# Specifies a path to chroot to after authentication. This path, and all its components, must be root-owned directories that are not writable by any other user or group.
# After the chroot, sshd changes the working directory to the user's home directory.

VersionAddendum none

# no default banner path
Banner /etc/issue

${DEBIANBANNER}

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*
EOF
)


ISSUEFILE=$(cat <<EOF > /etc/issue
###############################################################
#                      ${HOSTNAME} 
#-------------------------------------------------------------#
#       All connections are monitored and recorded            #
#  Disconnect IMMEDIATELY if you are not an authorized user!  #
###############################################################
EOF
)


printf "[*] Backing up current SSH configuration file \n"
cp "${CONFFILE}" "${CONFFILE}.bak" && printf "[*] Created backup of active sshd_config file at ${CONFFILE}.bak \n"

printf "[*] Execute the below command to generate a key for your user and allow it SSH access to this server then restart the service \n"
printf "[i] NOTE: The configuration file does not allow the root user SSH access for security reasons \n"
printf "\tssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 && cat ~/.ssh/id_ed25519 >> ~/.ssh/authorized_keys \n"

printf "[*] Restarting the SSH service with latest config \n"
systemctl enable --now sshd.service && systemctl status sshd.service

