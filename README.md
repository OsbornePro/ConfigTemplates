# Config Templates
This is a collection of configuration files that are great starting points. I have tried to include mostly files related to securing different protocols in different ways however that is not always what is needed so I have included some insecure configuations such as in the file smb.conf.

### File Description
1. __tmux.conf__ Configuration file that can be used to start your Tmux configuration
2. __1-ConfigureWindowsFTPS-CreateFTP-UsersAndGroup.ps1__ This script is meant to be run on a Domain Controller. It creates an FTP users and administrators group
3. __2-ConfigureWindowsFTPS-ConfigureFTPoverSSLserver.ps1__ This script is meant to be run on a Windows Server 2019 FTPS server hosted through IIS
4. __StartupScriptDisableNetBIOSandLMHO__ This script is meant to be run as a startup script in a domain environment to ensure NetBIOS and LLMNR are disabled
5. __smb.conf Anonymous SMB access Not Secure__ This Samba configuration file is one I used while performing offensive attacks, hosting payloads over SMB. DO NOT use this as a main configuration for any SMB servers in an enviornment as it is purposefully insecure
6. __ccpd-config.yml__ This configuration file is used to provide a template that allows you to use LDAP over SSL authentication with CIS-CAT Pro Dashboard (CCPD) when it is hosted on a Window Server. The [documentation on their site](https://cis-cat-pro-dashboard.readthedocs.io/en/stable/source/Dashboard%20Deployment%20Guide%20for%20Windows/) does not cover how to define this values when hosted on a Windows Server so I made the info readily available.
7. __sshd_config__ Great starting place for configuring SSH in a secure manner. I have included/centralized setting descriptors for anyone who may not be familiar with the protocol
8. __vsftpd.conf Anonymous Downloads__ FTP configuration for securely allowing anonymous users to only download files from a server
9. __vsftpd.conf Anonymous Uploads__ FTP configuration for securely allowing anonymous users to only upload files to a server
10. __vsftpd.conf for FTP over SSL__ FTP configuration for securely allowing authenticated users to upload or download files to an FTP server
11. __Harden-Windows10.ps1__ Script that can be used to harden a Windows 10 operating system on a single computer. Not recommended for domain environments as the settings should be applied differently in a domain situation.
