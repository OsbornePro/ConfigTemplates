# This script is meant to be run on Windows Server 2019 where you want to set up an FTP over SSL Server
# This script creates a directory for the FTPS Server that will be accessible for downloads by local users and uploads for admin users.
# This does not create directories for the Active Directory users to use via FTP because this assumes that you have home drives in AD assigned for them to upload and download files. 
# The Home Drive directory values should be assigned in the CSV file for msIIS-FTPDir and msIIS-FTPRoot AD attribute values
#
# This script is used to install the FTP and IIS management tools on a Windows Server. Itf you grant consent it will create a local FTP user and group after you confirm it to do so.
# This script will modify permissions on the FTP folder you define as well as create the folder if it does not exist.
# This script will select the SSL cert to use if it has a friendly name containing FTP and enable 128-bit encryption. It also enables basic auth for users to sign in
# This script confiures isolation mode with Active Directory and allows you to set the IP address and passive ports for the firewall

# REFERENCE : https://docs.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/ftpserver/security/ssl

$Logo = @"
╔═══╗░░╔╗░░░░░░░░░░░░╔═══╗░░░░░
║╔═╗║░░║║░░░░░░░░░░░░║╔═╗║░░░░░
║║░║╠══╣╚═╦══╦═╦═╗╔══╣╚═╝╠═╦══╗
║║░║║══╣╔╗║╔╗║╔╣╔╗╣║═╣╔══╣╔╣╔╗║
║╚═╝╠══║╚╝║╚╝║║║║║║║═╣║░░║║║╚╝║
╚═══╩══╩══╩══╩╝╚╝╚╩══╩╝░░╚╝╚══╝
"@

Function Test-Admin {

    $CurrentUser = New-Object -TypeName Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    
}  # End Function Test-Admin

If ((Test-Admin) -eq $False)  
{

    If ($Elevated) 
    {
        Write-Output "[*] Tried to elevate, did not work, aborting"
        
    }  # End Else 
    Else 
    {
    
        Start-Process -FilePath "C:\Windows\System32\powershell.exe" -Verb RunAs -ArgumentList ('-NoProfile -NoExit -File "{0}" -Elevated' -f ($myinvocation.MyCommand.Definition))
        
    }  # End Else
    
    Exit
    
}  # End If

Write-Output $Logo

Write-Warning "The execution of this script assumes your server is a member of a domain and you are signed in with a member of the Domain Admins group"
Read-Host -Prompt "Press ENTER to continue when ready"

Write-Output "[*] Installing the Windows features for FTP"
Install-WindowsFeature -Name Web-FTP-Server -IncludeManagementTools
Install-WindowsFeature -Name Web-Server -IncludeAllSubFeature -IncludeManagementTools

Write-Output "[*] Importing commands"
Import-Module -Name WebAdministration -Global


$ADFTPUser = Read-Host -Prompt "What is the name of the Active Directory group you created for FTP Users? EXAMPLE: FTP-Users"
$ADFTPAdmin = Read-Host -Prompt "What is the name of the Active Directory group you created for FTP Admins? EXAMPLE: FTP-Admins"
$Server = "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
$FTPSiteName = Read-Host -Prompt "Enter a name for the FTP site that will appear in IIS Manager. EXAMPLE: OsbornePro FTPS"
$FTPRootDir = Read-Host -Prompt "Enter the absoulte path to your FTP directory. Note that the directory you define will be created for you. EXAMPLE: C:\inetpub\FTP-Root"
$Port = Read-Host -Prompt "Enter a port for the FTP Server to listen on EXAMPLE: 21"
$FTPSitePath = "IIS:\Sites\$FTPSiteName"


Write-Output "[*] Creating an allow firewall rule using the port you defined"
New-NetFirewallRule -Name "Allow FTP Communication" -DisplayName "Allow FTP Communication" -Description 'Allows FTP Communication on port 21' -Profile Any -Direction Inbound -Action Allow -Protocol TCP -Program Any -LocalAddress Any -LocalPort $Port


Write-Output "[*] Creating the FTP directory at $FTPRootDir"
New-Item -Path $FTPRootDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

Write-Output "[*] Creating FTP Site based on the info you provided"
New-WebFtpSite -Name $FTPSiteName -Port $Port -PhysicalPath $FTPRootDir -Force


$FTPGroupName = Read-Host -Prompt "What should the local FTP Users group name be? EXAMPLE: FTP-Users"
Write-Output "[*] Creating the local FTP Group $FTPGroupName"

If (!(Get-LocalGroup -Name $FTPGroupName -ErrorAction SilentlyContinue))
{

    New-LocalGroup -Name $FTPGroupName -Description "Members of this group can access the FTP server"

}  # End If
Else
{

    Write-Output "[!] Group $FTPGroupName already exists. Skipping its creation"

}  # End Else


Write-Output "[*] Adding Active Directory FTP Users to the $FTPGroupName group"
Add-LocalGroupMember -Group $FTPGroupName -Member $ADFTPUser
Add-LocalGroupMember -Group $FTPGroupName -Member $ADFTPAdmin

Write-Output "[*] Adding authorization read rule to the FTP site for $FTPGroupName"
Add-WebConfiguration -Filter "/system.ftpServer/security/authorization" -Value @{accessType="Allow"; roles="$FTPGroupName";permissions="Read,Write";Users="*"} -PSPath 'IIS:\' -Location $FTPSiteName


Write-Output "[*] Enabling Basic Authentication on FTP Site"
Set-ItemProperty -Path $FTPSitePath -Name 'ftpServer.security.authentication.basicAuthentication.enabled' -Value $True


If ((Get-ItemProperty -Path $FTPSitePath -Name 'ftpServer.security.ssl.controlChannelPolicy') -notlike 'SslRequire')
{

    Write-Output "[*] Configuring SSL to be required"
    Set-ItemProperty -Path $FTPSitePath -Name 'ftpServer.security.ssl.controlChannelPolicy' -Value $True

}  # End If

If ((Get-ItemProperty -Path $FTPSitePath -Name 'ftpServer.security.ssl.dataChannelPolicy') -notlike 'SslRequire')
{

    Write-Output "[*] Configuring SSL to be required"
    Set-ItemProperty -Path $FTPSitePath -Name 'ftpServer.security.ssl.dataChannelPolicy' -Value $True

}  # End If

If (Get-LocalGroup -Name $FTPGroupName)
{

    Write-Output "[*] Setting permissions on $FTPRootDir"
    # USERS
    $LocalAccount = New-Object -TypeName System.Security.Principal.NTAccount("$FTPGroupName")

    # PERMISSIONS
    $Rights = [System.Security.AccessControl.FileSystemRights]"FullControl,Modify,ReadAndExecute,ListDirectory,Read,Write"
    $InheritanceFlag = @([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $ObjType = [System.Security.AccessControl.AccessControlType]::Allow

    # SET OWNER AND ACCESS
    $ObjAce1 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($LocalAccount, $Rights, $InheritanceFlag, $PropagationFlag, $ObjType)
    $ACL = Get-Acl -Path $FTPRootDir
    $Acl.SetOwner($LocalAccount)
    $Acl.AddAccessRule($ObjAce1)
    $Acl.SetAccessRuleProtection($True, $False)
    Set-Acl -Path $FTPRootDir -AclObject $ACL
    $ACL.SetAccessRule($ObjAce1)

}  # End If

Write-Output "[*] Setting User Isolation mode to Active Directory assigned"
$BindUser = Read-Host -Prompt "Enter a username that can authenticate to AD"
$BindPass = Read-Host -Prompt "Enter that users password" -AsSecureString

Set-ItemProperty -Path $FTPSitePath -Name ftpServer.userIsolation.activeDirectory.adUserName -Value $BindUser
Set-ItemProperty -Path $FTPSitePath -Name ftpServer.userIsolation.activeDirectory.adPassword -Value $BindPass
Set-ItemProperty -Path $FTPSitePath -Name ftpserver.userisolation.mode -Value ActiveDirectory


Write-Output "[*] Setting SSL certificate to be used with FTP over SSL. This obtains a certificate containing FTP in the FriendlyName"

$Thumbprint = Read-Host -Prompt "Enter the certificate thumbprint you want to use for the FTP over SSL instance. Leave blank and press ENTER if you wish to have this script find the certificate automatically by discovering a Local Machine cert in the Personal Store that has a friendly name containing `"*FTP*`"."
If ($Thumbprint -eq "")
{

    $Thumbprint = (Get-ChildItem -Path Cert:\LocalMachine -Recurse | Where-Object -Property FriendlyName -like "*FTP*")[0].Thumbprint.ToString()

}  # End If

Set-ItemProperty -Path $FTPSitePath -Name ftpServer.security.ssl.serverCertHash -Value $Thumbprint

$Ansr = Read-Host -Prompt "Would you like to define the passive (PASV) ports to listen on? [y/N]"
If ($Ansr -like "y*")
{

    $V1 = Read-Host -Prompt "What should the lowest accepted port be? EXAMPLE: 40000"
    $V2 = Read-Host -Prompt "What should the highest accepted port be? EXAPMLE: 41000"
    
    Write-Output "[*] Configuring Minimum and Maximum port values for Data channel ports"
    Set-WebConfigurationProperty -PSPath IIS:\ -Filter system.ftpServer/firewallSupport -Name lowDataChannelPort -Value $V1
    Set-WebConfigurationProperty -PSPath IIS:\ -Filter system.ftpServer/firewallSupport -Name highDataChannelPort -Value $V2
    
    Write-Output "[*] Creating an allow firewall rule using the passive ports you defined"
    New-NetFirewallRule -Name "Allow FTP Passive Communication" -DisplayName "Allow FTP Passive Communication" -Description 'Allows FTP Passive Communication' -Profile Any -Direction Inbound -Action Allow -Protocol TCP -Program Any -LocalAddress Any -LocalPort $V1-$V2 
    
    Write-Output "[*] Setting IP Address for firewall to allow passive FTP connections from remote locations"
    $IPAddress = Read-Host -Prompt "What is the IP address you would like to for Passive connections allowing clients on the other side of a router to reach you? Leave blank to obtain the DHCP assigned private IP address automatically."
    If ($IPAddress -eq "")
    {

        $IPAddress = (Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -PrefixOrigin Dhcp).IPAddress
        Set-ItemProperty -Path $FTPSitePath -Name ftpServer.firewallSupport.externalIp4Address -Value $IPAddress

    }  # End If

}  # End If


Write-Output "[*] Enabling 128-bit encryption"
$ConfigPath = 'ftpServer.security.ssl'

$SiteConfig = Get-ItemProperty -Path $FTPSitePath -Name $ConfigPath
If ($SiteConfig.ssl128 -eq $False)
{

    Set-ItemProperty -Path $FTPSitePath -Name "$ConfigPath.ssl128" -Value $True

}  # End If

$A = Read-Host -Prompt "Would you like to add a virtual host name for your ftp site? [y/N]"
If ($A -like "y*")
{

    $VHost = Read-Host -Prompt "What should the virtual hostname be? EXAMPLE: ftp.domain.com"

    Write-Output "[*] Adding a custom web binding hostname"
    New-WebBinding -Name $FTPSiteName -Protocol ftp  -HostHeader $VHost -Port $Port -SslFlags 1

    Write-Output "[*] Adding entry for $Vhost to your C:\Windows\System32\drivers\etc\hosts file"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "`n$IPAddress        $VHost $Server $env:COMPUTERNAME`n" -Force

}  # End If


Write-Output "[*] Restarting the FTP Site to load changes"
Restart-WebItem -PSPath $FTPSitePath


Write-Output "[*] Testing FTP port is open"
Test-NetConnection -ComputerName "$env:COMPUTERNAME.$env:USERDNSDOMAIN" -Port $Port
