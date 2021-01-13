# This script is meant to be run on Windows Server 2019 where you want to set up an FTP over SSL Server
#
# This script is used to install the FTP and IIS management tools on a Windows Server. Itf you grant consent it will create a local FTP user and group after you confirm it to do so.
# This script will modify permissions on the FTP folder you define as well as create the folder if it does not exist.
# This script will select the SSL cert to use if it has a friendly name containing FTP and enable 128-bit encryption. It als oenables basic auth for users to sign in
# This script confiures isolation mode with Active Directory and allows you to set the IP address and passive ports for the firewall

Write-Warning "The execution of this script assumes your server is a member of a domain and you are signed in with a member of the Domain Admins group"
Read-Host -Prompt "Press ENTER to continue when ready"

Write-Output "[*] Installing the Windows feature for FTP"
Install-WindowsFeature -Name Web-FTP-Server -IncludeAllSubFeature
Install-WindowsFeature -Name Web-Server -IncludeAllSubFeature -IncludeManagementTools
Import-Module -Name WebAdministration -Global


$ADFTPUser = Read-Host -Prompt "What is the name of the Active Directory group you created for FTP Users? EXAMPLE: FTP-Users"
$ADFTPAdmin = Read-Host -Prompt "What is the name of the Active Directory group you created for FTP Admins? EXAMPLE: FTP-Admins"
$Server = "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
$FTPSiteName = Read-Host -Prompt "Enter a name for the FTP site that will appear in IIS Manager. EXAMPLE: OsbornePro FTPS"
$FTPRootDir = Read-Host -Prompt "Enter the absoulte path to your FTP directory. Note that the directory you define will be created for you. EXAMPLE: C:\inetpub\FTP-Root"
$Port = Read-Host -Prompt "Enter a port for the FTP Server to listen on EXAMPLE: 21"
$FTPSitePath = "IIS:\Sites\$FTPSiteName"


Write-Output "[*] Creating the FTP directory at $FTPRootDir"
New-Item -Path $FTPRootDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

Write-Output "[*] Creating FTP Site based on the info you provided"
New-WebFtpSite -Name $FTPSiteName -Port $Port -PhysicalPath $FTPRootDir


$Answer = Read-Host -Prompt "Would you like to create a local FTP user and FTP group to access the FTP server? [y/N]"
If ($Answer -like "y*")
{

    $FTPUsername = Read-Host -Prompt " What should the local FTP username be EXAMPLE: FTPUser"
    $FTPGroupName = Read-Host -Prompt "What should the local FTP Users group name be? EXAMPLE: FTP-Users"


    Write-Output "[*] Creating the local FTP Group $FTPGroupName"
    If (!(Get-LocalGroup -Name $FTPGroupName -ErrorAction SilentlyContinue))
    {

        New-LocalGroup -Name $FTPGroupName -Description "Members of this group can access the FTP server"

    }  # End If


    Write-Output "[*] Creating the local FTP User $FTPUsername"
    $FTPPassword = ConvertTo-SecureString -String (Read-Host -Prompt "Enter a password for the local FTP user" -AsSecureString) -AsPlainText -Force
    If (!(Get-LocalUser -Name $FTPUserName -ErrorAction SilentlyContinue)) 
    {

        New-LocalUser -Name $FTPUserName -Password $FTPPassword -Description "Local user account with permisssions to the FTP server" -UserMayNotChangePassword

    }  # End If


    Write-Output "[*] Adding $FTPUsername to the $FTPGroupName group"
    Add-LocalGroupMember -Group $FTPGroupName -Member $FTPUsername


    Write-Output "[*] Adding authorization read rule to the FTP site for $FTPGroupName"
    Add-WebConfiguration -Filter "/system.ftpServer/security/authorization" -Value @{accessType="Allow"; roles="$FTPGroupName";permissions=1} -PSPath 'IIS:\' -Location $FTPSiteName

}  # End If


Write-Output "[*] Enabling Basic Authentication on FTP Site"
Set-ItemProperty -Path $FTPSitePath -Name 'ftpServer.security.authentication.basicAuthentication.enabled' -Value $True


$SSLPolicy = 'ftpServer.security.ssl.controlChannelPolicy','ftpServer.security.ssl.dataChannelPolicy'
If ((Get-ItemProperty -Path $FTPSitePath -Name $SSLPolicy[0]) -notlike 'SslRequire')
{

    Write-Output "[*] Configuring SSL to be required"
    Set-ItemProperty -Path $FTPSitePath -Name $SSLPolicy[0] -Value $True

}  # End If

If ((Get-ItemProperty -Path $FTPSitePath -Name $SSLPolicy[1]) -notlike 'SslRequire')
{

    Write-Output "[*] Configuring SSL to be required"
    Set-ItemProperty -Path $FTPSitePath -Name $SSLPolicy[0] -Value $True

}  # End If


Write-Output "[*] Setting permissions on $FTPRootDir"
$LocalAccount = New-Object -TypeName System.Security.Principal.NTAccount("$FTPGroupName")
$ADAdmin = New-Object -TypeName System.Security.Principal.NTAccount "$env:USERDNSDOMAIN\$ADFTPAdmin"
$ADUser = New-Object -TypeName System.Security.Principal.NTAccount "$env:USERDNSDOMAIN\$ADFTPUser"

$AdminRights = [System.Security.AccessControl.FileSystemRights]"FullControl,Modify,ReadAndExecute,ListDirectory,Read,Write"
$UserRights = [System.Security.AccessControl.FileSystemRights]"Modify,ReadAndExecute,ListDirectory,Read,Write"
$InheritanceFlag = @([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
$ObjType = [System.Security.AccessControl.AccessControlType]::Allow

$ObjAce1 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($ADAdmin, $AdminRights, $InheritanceFlag, $PropagationFlag, $ObjType)
$ACL = Get-Acl -Path $FTPRootDir
$Acl.SetOwner($ADAdmin)
$Acl.AddAccessRule($ObjAce1)
$Acl.SetAccessRuleProtection($True, $False)
Set-Acl -Path $FTPRootDir -AclObject $ACL
$ACL.SetAccessRule($ObjAce1)

$ObjAce2 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($ADUser, $UserRights, $InheritanceFlag, $PropagationFlag, $ObjType)
$ACL.SetAccessRule($ObjAce2)
Set-Acl -Path $FTPRootDir -AclObject $ACL

$ObjAce = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($LocalAccount, $UserRights, $InheritanceFlag, $PropagationFlag, $ObjType)
$ACL.SetAccessRule($ObjAce2)
Set-Acl -Path $FTPRootDir -AclObject $ACL


Write-Output "[*] Adding authorization read rule to the FTP site for FTP domain groups"

Add-WebConfiguration -Filter "/system.ftpServer/security/authorization" -Value @{accessType="Allow"; roles="$env:USERDOMAIN\$ADFTPAdmin";permissions="Read,Write";Users="*"} -PSPath 'IIS:\' -Location $FTPSiteName
Add-WebConfiguration -Filter "/system.ftpServer/security/authorization" -Value @{accessType="Allow"; roles="$env:USERDOMAIN\$ADFTPUser";permissions=1} -PSPath 'IIS:\' -Location $FTPSiteName


Write-Output "[*] Setting User Isolation mode"
$BindUser = Read-Host -Prompt "Enter a username that can authenticate to AD"
$BindPass = Read-Host -Prompt "Enter that users password" -AsSecureString
Set-ItemProperty -Path $FTPSitePath -Name ftpServer.userIsolation.activeDirectory.adUserName -Value $BindUser
Set-ItemProperty -Path $FTPSitePath -Name ftpServer.userIsolation.activeDirectory.adPassword -Value $BindPass
Set-ItemProperty -Path $FTPSitePath -Name ftpserver.userisolation.mode -Value ActiveDirectory


Write-Output "[*] Setting SSL certificate to be used with FTP over SSL"
Set-ItemProperty -Path $FTPSiteName -Name ftpServer.security.ssl.serverCertHash -Value (Get-ChildItem -Path Cert:\ -Recurse | Where-Object -Property FriendlyName -like "*FTP*") # Replace my sample thumbprint with the value from your certificate
# Data channel ports are a per server configuration
#Set-WebConfigurationProperty -PSPath IIS:\ -Filter system.ftpServer/firewallSupport -Name lowDataChannelPort -Value 5000
#Set-WebConfigurationProperty -PSPath IIS:\ -Filter system.ftpServer/firewallSupport -Name highDataChannelPort -Value 6000

Write-Output "[*] Enabling 128-bit encryption"
$ConfigPath = 'ftpServer.security.ssl'
$SiteConfig = Get-ItemProperty -Path $FTPSitePath -Name $ConfigPath
If ($SiteConfig.ssl128 -eq $False)
{

    Set-ItemProperty -Path $FTPSitePath -Name "$ConfigPath.ssl128" -Value $True

}  # End If


Write-Output "[*] Setting IP Address for firewall to allow passive FTP connections from remote locations"
$IPAddress = (Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -PrefixOrigin Dhcp).IPAddress
Set-ItemProperty -Path $FTPSitePath -Name ftpServer.firewallSupport.externalIp4Address -Value $IPAddress


#Write-Output "[*] Add a custom web binding hostname if desired"
#New-WebBinding -Name $FTPSiteName -Protocol ftp  -HostHeader "$env:COMPUTERNAME.$env:USERDNSDOMAIN" -Port 21 -SslFlags 1


Write-Output "[*] Restarting the FTP Site to load changes"
Restart-WebItem -PSPath $FTPSitePath


Test-NetConnection -ComputerName "$env:COMPUTERNAME.$env:USERDNSDOMAIN" -Port $Port
