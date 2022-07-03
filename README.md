# Config Templates
This is a collection of configuration files and configuration scripts that are great starting points. I have tried to include mostly files related to securing different protocols in different ways however that is not always what is needed so I have included some insecure configuations such as in the file smb.conf.

### File Description
1. __tmux.conf__ Configuration file that can be used to start your Tmux configuration
1. __1-ConfigureWindowsFTPS-CreateFTP-UsersAndGroup.ps1__ This script is meant to be run on a Domain Controller. It creates an FTP users and administrators group
1. __2-ConfigureWindowsFTPS-ConfigureFTPoverSSLserver.ps1__ This script is meant to be run on a Windows Server 2019 FTPS server hosted through IIS
1. __Cloudflare Dynamic DNS Update.ps1__ Script from Cloudflare that allows you to update your Dynamic DNS records automatically
1. __Apache LDAPS Template for nagios.conf__ LDAP over SSL authentication configuration for Nagios Core on Apache
1. __Bastillion LDAPS Tempalte for jaas.conf__ LDAP over SSL authentication configuration for Bastillion Servers
1. __Configure-SFTP-Only.ps1__ Setup an SFTP server without SSH open on a Windows Server
1. __Harden-Windows10.ps1__ Script to harden the Windows 10 Operating System for the everyday user
1. __LAPS-Setup.ps1__ Performs all the steps required to setup LAPS and keep password backups in an environment
1. __Microsoft.PowerShell_profile.ps1__ Default PowerShell profile Template that can be used
1. __New-AOVPNClientProfile.ps1__ Create a Client AOVPN profile that uses Split Tunneling and Certificate authentication with IKEv2 failing over to SSTP
1. __Set-AOVPNServerProfile.ps1__ Configure AOVPN Server to use Secure Encrpytion algorithms
1. __Set-NTPServerUp.ps1__ Configure a Windows Server to act as an NTP server which is secure by default
1, __Set-NewLDAPSCertificate.ps1__ Run this as a task to auto replace expiring LDAP over SSL certificate automatically on Domain Controllers
1. __Set-RdpSslCertificate.ps1__ Set the SSL certificate used by RDP
1. __SetupRADIUSserver.ps1__ Script to more quickly add client Authentictors to a RADIUS Authentication NPS Windows Server
1. __StartupScriptDisableNetBIOSandLMHO__ This script is meant to be run as a startup script in a domain environment to ensure NetBIOS and LLMNR are disabled
1. __apache2-default-ssl.conf__ Apache defaut-ssl.conf template for using hardened SSL
1. __apache2-mods-enabled-ssl.conf__ Apache mods-enabled-ssl.conf template for using hardened SSL
1. __apache2-security.conf__ Apache security.conf configuration template for securing an Apache web server
1. __apache2.conf__ Apache configuration file template for hardening an Apache web server
1. __apache2file-000-default.conf__ Apache 000-default.conf configuration file templtae for hardeing the default site profile
1. __ccpd-config.yml__ Configuration file used to provide a template that allows you to use LDAP over SSL authentication with CIS-CAT Pro Dashboard (CCPD) when it is hosted on a Window Server. The [documentation on their site](https://cis-cat-pro-dashboard.readthedocs.io/en/stable/source/Dashboard%20Deployment%20Guide%20for%20Windows/) does not cover how to define this values when hosted on a Windows Server so I made the info readily available.
1. __cronjob-vsftpd-cert-expires.sh__ Script can be used as a cronjob that runs once a year to replace expired certificates used by VSFTPD or whatever service you wish to modify this too
1. __fail2ban-apacheSSH-jail.local__ Configuration file template to use fail2ban to harden open apache and SSH ports
1. __lighttpd-external.conf__ Configuration file to harden a lighttpd server hosting Pi-Hole
1. __lighttpd-rejection.conf__ Configuration file to created WAF rules for a lighttpd server hosting a Pi-Hole
1. __postfix.main.cf__ Hardened Postfix Coniguration file main.cf that uses secure methods of sending emails from your local device 
1. __smb.conf Anonymous SMB access Not Secure__ This Samba configuration file is one I used while performing offensive attacks, hosting payloads over SMB. DO NOT use this as a main configuration for any SMB servers in an enviornment as it is purposefully insecure
1. __sshd_config__ Great starting place for configuring SSH in a secure manner. I have included/centralized setting descriptors for anyone who may not be familiar with the protocol
1. __vsftpd.conf Anonymous Downloads__ FTP configuration for securely allowing anonymous users to only download files from a server
1. __vsftpd.conf Anonymous Uploads__ FTP configuration for securely allowing anonymous users to only upload files to a server
1. __vsftpd.conf for FTP over SSL__ FTP configuration for securely allowing authenticated users to upload or download files to an FTP server
