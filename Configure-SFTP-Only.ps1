# This script is used to set up an SFTP server on a Windows Server using OpenSSH
Function Test-Admin {

    $CurrentUser = New-Object -TypeName Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    
}  # End Function Test-Admin

If ((Test-Admin) -eq $False) {

    If ($Elevated) {
        Write-Output "[*] Tried to elevate, did not work, aborting"
        
    } Else {
    
        Start-Process -FilePath "C:\Windows\System32\powershell.exe" -Verb RunAs -ArgumentList ('-NoProfile -NoExit -File "{0}" -Elevated' -f ($myinvocation.MyCommand.Definition))
        
    }  # End Else
    
    Exit
    
}  # End If


$Logo = @"
╔═══╗░░╔╗░░░░░░░░░░░░╔═══╗░░░░░
║╔═╗║░░║║░░░░░░░░░░░░║╔═╗║░░░░░
║║░║╠══╣╚═╦══╦═╦═╗╔══╣╚═╝╠═╦══╗
║║░║║══╣╔╗║╔╗║╔╣╔╗╣║═╣╔══╣╔╣╔╗║
║╚═╝╠══║╚╝║╚╝║║║║║║║═╣║░░║║║╚╝║
╚═══╩══╩══╩══╩╝╚╝╚╩══╩╝░░╚╝╚══╝
===============================
If you can't beat `em tech `em!
===============================
https://osbornepro.com
EMAIL: info@osbornepro.com
"@
Write-Output "$Logo"

$Domain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
$SFTPGroup = Read-Host -Prompt "Enter the name of the SFTP Security Group Allowing access to the SFTP Server. Do not include the domain. EXAMPLE: SFTP-Users"
Write-Output "[*] Creating the local group $SFTPGroup"
If (!(Get-LocalGroup -Name $SFTPGroup -ErrorAction SilentlyContinue)) {

    New-LocalGroup -Description "Members of this group can access the SFTP server" -Name $SFTPGroup

} Else {

    Write-Output "[!] Group $SFTPGroup already exists. Skipping its creation"

}  # End Else

[array]$AddToGroup = Read-Host -Prompt "Define any users and groups you want to be able to access the SFTP server: EXAMPLE: domain.com\rosborne,administrator"
$AddToGroup = $AddToGroup.Split(",").Replace(" ","")
Add-LocalGroupMember -Group $SFTPGroup -Member $AddToGroup


$SFTPRootDir = Read-Host -Prompt "Where should your SFTP directory be created or exist at? EXAMPLE: C:\SFTP"
Write-Output "[*] Creating $SFTPRootDir if it does not already exist"
New-Item -Path $SFTPRootDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
$SFTPRootDir = $SFTPRootDir.Replace("\","\\")


Write-Output "[*] Setting the permissions on $SFTPRootDir"
$LocalAccount = New-Object -TypeName System.Security.Principal.NTAccount("$SFTPGroup")
$SystemAccount = New-Object -TypeName System.Security.Principal.NTAccount("SYSTEM")
$AdminAccount = New-Object -TypeName System.Security.Principal.NTAccount("Administrators")
$Rights = [System.Security.AccessControl.FileSystemRights]"FullControl,Modify,ReadAndExecute,ListDirectory,Read,Write"
$InheritanceFlag = @([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
$ObjType = [System.Security.AccessControl.AccessControlType]::Allow


Write-Output "[*] Defining the owner as the built-in Administrators group"
$ObjAce1 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($LocalAccount, $Rights, $InheritanceFlag, $PropagationFlag, $ObjType)
$ACL = Get-Acl -Path $SFTPRootDir
$Acl.SetOwner($AdminAccount)
$Acl.AddAccessRule($ObjAce1)
$Acl.SetAccessRuleProtection($True, $False)
Set-Acl -Path $SFTPRootDir -AclObject $ACL
$ACL.SetAccessRule($ObjAce1)

Write-Output "[*] Adding SYSTEM privileges to $($SFTPRootDir)"
$ObjAce2 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($SystemAccount, $Rights, $InheritanceFlag, $PropagationFlag, $ObjType)
$ACL.SetAccessRule($ObjAce2)
Set-Acl -Path $SFTPRootDir -AclObject $ACL

Write-Output "[*] Adding $($SFTPGroup) group privileges to $($SFTPRootDir)"
$ObjAce3 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($AdminAccount, $Rights, $InheritanceFlag, $PropagationFlag, $ObjType)
$ACL.SetAccessRule($ObjAce3)
Set-Acl -Path $SFTPRootDir -AclObject $ACL


Write-Output "[*] Installing OpenSSH client and server"
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0


Write-Output "[*] Enabling sshd service to start automatically"
Set-Service -Name sshd -StartupType Automatic
Set-Service -Name ssh-agent -StartupType Automatic
Start-Service -Name sshd,ssh-agent


Write-Output "[*] Creating firewall rule Allow SFTP Connections"
New-NetFirewallRule -Name sshd -DisplayName 'Allow SFTP Connections' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -Program "C:\Windows\System32\OpenSSH\sshd.exe"


Write-Output "[*] Host keys are below"
Get-ChildItem -Path "$env:ProgramData\ssh\ssh_host_*_key" | ForEach-Object { . "$env:WINDIR\System32\OpenSSH\ssh-keygen.exe" -l -f $_ }


Write-Output "[*] Backing up original config file"
Move-Item -Path "C:\ProgramData\ssh\sshd_config" -Destination "C:\ProgramData\ssh\sshd_config.orig" -Force


Write-Output "[*] Creating the SFTP Configuration file"
$Contents = @"
# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Port 22
Protocol 2
AddressFamily inet 
ListenAddress 0.0.0.0
#ListenAddress ::

# Ciphers and keying
HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_dsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_ecdsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key
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
SyslogFacility USER # Debian
#SyslogFacility AUTHPRIV # RHEL, CentOS
LogLevel INFO

# Authentication:
LoginGraceTime 20
# How long in seconds after a connection request the server waits before disconnecting if a user has not successfully logged in

PermitRootLogin no
# This settings allows or prevents the root user from using SSH to sign into a machine via password or public key. Sudo users can still elevate privilege

MaxAuthTries 3 
# Specifies the maximum number of authentication attempts permitted per connection. Once the number of failures reaches half this value, additional failures are logged. The default is 6

MaxSessions 6
# Specifies the maximum number of open sessions permitted per network connection. The default is 10. 

#============================================================
# PREFERRED METHOD HOWEVER WINDOWS DOES NOT SEEM TO LIKE IT
#============================================================
#PubkeyAuthentication yes
PubkeyAuthentication no

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
AuthorizedKeysFile	.ssh/authorized_keys # Debian
#AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys.%u # RHEL

# To disable tunneled clear text passwords, change to no here!
#=====================================================
# USE KEY AUTHENTICATION INSTEAD WHEN POSSIBLE
#=====================================================
#PasswordAuthentication no
PasswordAuthentication yes
PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with some PAM modules and threads)
ChallengeResponseAuthentication no # Debian
#ChallengeResponseAuthentication yes # RHEL, CentOS

AllowGroups $($SFTPGroup)
# Defines a group a user is required to be a member of in order to be allowed SSH access
# AllowUsers tobor rob chris tom 
# Allow users can be used instead of Allow groups if desired

#DenyGroups
# Deny Groups and users can also be defined as well. Typically it is easier to make a whitelist by adding allowed users to a group
#DenyUsers

AllowAgentForwarding no
AllowTcpForwarding no

GatewayPorts no

PermitTTY yes

PrintMotd yes
# Great for printing a welcome message after authenticating to the server

TCPKeepAlive no
# I turn this off and use Client Keep Alive's instead
# Specifies whether the system should send TCP keepalive messages to the other side. If they are sent, death of the connection or crash of one of the machines will be properly noticed
# However, this means that connections will die if the route is down temporarily, and some people find it annoying. 
# On the other hand, if TCP keepalives are not sent, sessions may hang indefinitely on the server, leaving ''ghost'' users and consuming server resources. I use Client Keep Alives instead

ClientAliveInterval 15
# Sets a timeout interval in seconds after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response from the client. 
# The default is 0, indicating that these messages will not be sent to the client. This option applies to protocol version 2 only. 

ClientAliveCountMax 3
# Sets the number of client alive messages from setting above which may be sent without sshd receiving any messages back from the client.

UseDNS no
# Specifies whether sshd should look up the remote host name and check that the resolved host name for the remote IP address maps back to the very same IP address. The default is ''yes''. 
# I change this to no because the option is basically useless

MaxStartups 10:30:100
# Specifies the maximum number of concurrent unauthenticated connections to the SSH daemon. Additional connections will be dropped until authentication succeeds
# start:rate:full 
#     sshd will refuse connection attempts with a probability of `rate/100'' (30%) if there are currently `start'' (10) unauthenticated connections.  
#     The probability increases linearly and all connection attempts are refused if the number of unauthenticated connections reaches `full'' (60).

ChrootDirectory $($SFTPRootDir)
# Specifies a path to chroot to after authentication. This path, and all its components, must be root-owned directories that are not writable by any other user or group. 
# After the chroot, sshd changes the working directory to the user's home directory. 

VersionAddendum none

# no default banner path
#Banner /etc/issue 

ForceCommand internal-sftp 
# override default of no subsystems
#Subsystem	sftp	sftp-server.exe # Original value
Subsystem	sftp	internal-sftp
Match group $($SFTPGroup)
     ChrootDirectory $($SFTPRootDir)
     AllowTcpForwarding no
     ForceCommand internal-sftp

Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys

############################################################################################################
# Unapplicable Settings for Windows
############################################################################################################
#AcceptEnv
#AllowStreamLocalForwarding
#AuthorizedKeysCommand
#AuthorizedKeysCommandUser
#AuthorizedPrincipalsCommand
#AuthorizedPrincipalsCommandUser
#Compression
#ExposeAuthInfo
#GSSAPIAuthentication
#GSSAPICleanupCredentials
#GSSAPIStrictAcceptorCheck
#HostbasedAcceptedKeyTypes
#HostbasedAuthentication
#HostbasedUsesNameFromPacketOnly
#IgnoreRhosts
#IgnoreUserKnownHosts
#KbdInteractiveAuthentication
#KerberosAuthentication
#KerberosGetAFSToken
#KerberosOrLocalPasswd
#KerberosTicketCleanup
#PermitTunnel
#PermitUserEnvironment
#PermitUserRC
#idFile
#PrintLastLog
#RDomain
#StreamLocalBindMask
#StreamLocalBindUnlink
#StrictModes
#X11DisplayOffset
#X11Forwarding
#X11UseLocalhost
#XAuthLocation
"@
New-Item -Path "C:\ProgramData\ssh" -Name "sshd_config" -ItemType File -Force -Value $Contents | Out-Null

Write-Output "[*] Backing up the newly set configuration file"
Copy-Item -Path "C:\ProgramData\ssh\sshd_config" -Destination  "C:\ProgramData\ssh\sshd_config.bak" -Force

Write-Output "[*] Restarting the sshd service to apply changes"
Restart-Service -Name sshd
