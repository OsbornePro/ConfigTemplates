Function Test-Admin {

    $CurrentUser = New-Object -TypeName Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

}  # End Function Test-Admin

If ((Test-Admin) -eq $False) {

    If ($Elevated) {
        Write-Output "[*] Tried to elevate, did not work, aborting"

    }  # End Else
    Else {

        Start-Process -FilePath "C:\Windows\System32\powershell.exe" -Verb RunAs -ArgumentList ('-NoProfile -NoExit -File "{0}" -Elevated' -f ($myinvocation.MyCommand.Definition))

    }  # End Else

    Exit

}  # End If

$Logo = @"
________         ___.                             __________
\_____  \   _____\_ |__   ___________  ____   ____\______   \_______  ____
 /   |   \ /  ___/| __ \ /  _ \_  __ \/    \_/ __ \|     ___/\_  __ \/  _ \
/    |    \\___ \ | \_\ (  <_> )  | \/   |  \  ___/|    |     |  | \(  <_> )
\_______  /____  >|___  /\____/|__|  |___|  /\___  >____|     |__|   \____/
        \/     \/     \/                  \/     \/
https://roberthosborne.com
info@osbornepro.com
"@
$Logo

Write-Output "BEGINING EXECUTION OF SCRIPT TO HARDEN A WINDOWS 10 MACHINE NOT JOINED TO A DOMAIN"

# WDIGEST CACHE
Write-Output "[*] Disabling WDigest credentials caching. More info here: https://www.stigviewer.com/stig/windows_10/2017-02-21/finding/V-71763"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" -Name UseLogonCredential -Value 0 -Force


# AUTOLOGIN PASSWORD
$AutoLoginPassword = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | Select-Object -Property "DefaultUserName","DefaultPassword"
If (($AutoLoginPassword).DefaultPassword) {

    Write-Output "[!] Auto Login Credentials Found: "
    Write-Output " $AutoLoginPassword"

    Write-Output "[*] Sometimes it is required to allow a computer to auto logon. To secure the above password use this tool to ensure the password is hashed/obfuscated and not stored in clear text:  `nhttps://docs.microsoft.com/en-us/sysinternals/downloads/autologon"
    $Remediate = Read-Host -Prompt "Would you like to disable auto-logon? [y/N]"
    If ($Remediate -like "y*") {

        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

        Set-ItemProperty -Path $RegPath -Name AutoAdminLogon -Value 0
        Set-ItemProperty -Path $RegPath -Name DefaultUserName -Value $Null
        Set-ItemProperty -Path $RegPath -Name DefaultPassword -Value $Null

    }  # End If

}  # End If
Else {

    Write-Output "[*] Great work! You are not using auto-logon"

}  # End Else

# ALWAYS INSTALL ELEVATED
If (((Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Installer").AlwaysInstallElevated) -eq 1) {

    Write-Output "[*] Device is vulnerable to AlwaysInstallElevated priviliege escalation. Mitigating threat. Read more here if desired: https://docs.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated"
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0

}  # End If
Else {

    Write-Output "[*] EXCELLENT: Target is not vulnerable to AlwaysInstallElevated PrivEsc method "

}  # End Else


# WSUS
Write-Output "[*] Checking for WSUS updates allowed over HTTP for PrivEsc"
If (((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -ErrorAction "SilentlyContinue") -eq 1) -and (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction "SilentlyContinue" -Contains "http://")) {

    Write-Output "[!] Target is vulnerable to HTTP WSUS updates. Configure your update server to use HTTPS only if you must have it custom defined. `n EXPLOIT: https://github.com/pimps/wsuxploit"

}  # End If
Else {

    Write-Output "[*] $env:COMPUTERNAME is not vulnerable to WSUS using HTTP."

}  # End Else

# SSDP
Write-Output "[*] Disabling the SSDP Service"
Stop-Service -Name "SSDPSRV" -Force -ErrorAction SilentlyContinue
Set-Service -Name "SSDPSRV" -StartupType Disabled
Disable-NetFirewallRule -DisplayName "Network Discovery*"

# SMB
Write-Output '[*] Disabling SMB version 1'
Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force

Write-Output '[*] Enabling SMBv2 and SMBv3'
Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force

Write-Output '[*] Enabling SMB Signing'
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkStation\Parameters" -Name RequireSecuritySignature -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" -Name EnableSecuritySignature -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name RequireSecuritySignature -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name EnableSecuritySignature -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null

Write-Output "[*] Blocking a few common ports attackers may use with reverse shells."
New-NetFirewallRule -DisplayName "Disallow Common Ports That Attackers Use" -Direction "Outbound" -LocalPort 1336,1337,1338,1339,4444,4445,4446,4447,4448,4449 -Protocol "TCP" -Action Block
New-NetFirewallRule -DisplayName "Disallow Common Ports That Attackers Use" -Direction "Outbound" -LocalPort 1336,1337,1338,1339,4444,4445,4446,4447,4448,4449 -Protocol "UDP" -Action Block


# DNS
Write-Output "[*] Enabling DNS over HTTPS for all Windows applications"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableAutoDOH -PropertyType DWORD -Value 2 -Force

Write-Output "[*] Disable the use of the LMHOSTS File"
Invoke-CimMethod -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments @{ DNSEnabledForWINSResolution = $False; WINSEnableLMHostsLookup = $False }

Write-Output "[*] Disabling the use of NetBIOS"
$CIMInstance = Get-CimInstance -Namespace "root/CIMV2" -ClassName "Win32_NetworkAdapterConfiguration"
$CIMInstance | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} | Out-Null

# RDP
Write-Output "[*] Disabling Remote Assistance"
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0

$Answer3 = Read-Host -Prompt "Would you like to allow remote access to your computer? [y/N]"
    If ($Answer3 -like "y*") {

        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

        Write-Output "Enabling NLA on $env:COMPUTERNAME. This setting can be seen under 'View Advanced System Settings' under the 'Remote' Tab"
        $NLAinfo = Get-CimInstance -ClassName Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
        $NLAinfo | Invoke-CimMethod -MethodName SetUserAuthenticationRequired -Arguments @{ UserAuthenticationRequired = $True }

        $TSSetting = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TerminalServiceSetting
        $TSGeneralSetting = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting
        $TSSetting | Invoke-CimMethod -MethodName SetAllowTSConnections -Arguments @{AllowTSConnections=1;ModifyFirewallException=1}
        $TSGeneralSetting | Invoke-CimMethod -MethodName SetUserAuthenticationRequired -Arguments @{UserAuthenticationRequired=1}

    }  # End If
    ElseIf ($Answer3 -like "n*") {

        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 1
        Disable-NetFirewallRule -DisplayGroup "Remote Desktop"

    }  # End ElseIf


# SSL
Write-Output "[*] Disabling outdated SSL ciphers. I was leniant to still allow for possible legacy applications"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA"

Write-Output "[*] Disabling weak outdated protocols"
# NULL Ciphers
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
# DES Ciphers
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('DES 56/56')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('Triple DES 168/168')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
# RC4 Ciphers
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 40/128')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 56/128')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 64/128')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 128/128')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
# ENABLING AES
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('AES 128/128')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('AES 256/256')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
# SSL2
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
# SSL3
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
# TLS 1.0
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
# ENABLING TLS 1.1 and 1.2
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null


# POWERSHELL DOWNGRADE
Write-Output "[*] Removing outdated PowerShell version 2"
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -Remove


# UNQUOTED SERVICE PATHS
$UnquotedServicePaths = Get-CimInstance -ClassName "Win32_Service" -Property "Name","DisplayName","PathName","StartMode" | Where-Object { $_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*' } | Select-Object -Property "PathName","DisplayName","Name"

If ($UnquotedServicePaths) {

    Write-Output "Unquoted Service Path(s) have been found"

    $UnquotedServicePaths | Select-Object -Property PathName,DisplayName,Name | Format-List -GroupBy Name
    Write-Output "[*] Modify the above registry values so double or single quotes surround the defined file path locations"

}  # End If
Else {

    Write-Output "[*] $env:COMPUTERNAME does not contain any unquoted service paths"

}  # End Else

# EXTRANEOUS SERVICES
Write-Output "[*] Disabling receommended unused services"
$Services = "WMPNetworkSvc","sshd","WMPNetworkSvc","icssvc","RpcLocator","RemoteAccess","XblAuthManager","XblGameSave","XboxNetApiSvc","XboxGipSvc"
Stop-Service -Name $Services
$Services | ForEach-Object { Set-Service -Name $_ -StartupType Disabled }


# FIREWALL LOG FILES
Write-Output "[*] Defining log file locations for Public, Domain, and Private firewall connections"
$FirewallLogFiles = "C:\Windows\System32\LogFiles\Firewall\domainfw.log","C:\Windows\System32\LogFiles\Firewall\domainfw.log.old","C:\Windows\System32\LogFiles\Firewall\privatefw.log","C:\Windows\System32\LogFiles\Firewall"
New-Item -Path $Path -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

$Acl = Get-Acl -Path $FirewallLogFiles
$Acl.SetAccessRuleProtection($True, $False)
$PermittedUsers = @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\Network Configuration Operators', 'NT SERVICE\MpsSvc')
ForEach ($User in $PermittedUsers) {

  $Permission = $User, 'FullControl', 'Allow'
  $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission
  $Acl.AddAccessRule($AccessRule)

}  # End ForEach

$Acl.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount('BUILTIN\Administrators')))
$Acl | Set-Acl -Path $FirewallLogFiles

# GROUP MEMBERSHIP
Write-Output "[*] Enabling UAC on all processes that require elevation"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2

Write-Output "[*] Checking if current user is a member of the local Administrators group"
If ((Get-LocalGroupMember -Group "Administrators").Name -Contains "$env:COMPUTERNAME\$env:USERNAME") {

    Write-Output "[*] It is considered best practice to log into Windows using a user account that does not have Administrative priviledge. If you wish to continue doing what you are doing it is not critical to adapt to this suggestion"

    $Answer1 = Read-Host -Prompt "Would you like to create a user account to sign into Windows with from now on and use the $env:USERNAME account and password whenever you need to elevate privilege? [y/N]"
    If ($Answer1 -like "y*") {

        $FullName = Read-Host -Prompt "What is the full name of the user who will use this account"
        $Name = Read-Host -Prompt "What should the account Name be? EXAMPLE: John Smith"
        $Description = Read-Host -Prompt "Add a description for this user account if you like. Feel free to leave blank"

        Write-Output "[*] Creating the $Name user account"
        New-LocalUser -FullName $FullName -Name $Name -Description $Description -Password (Read-Host -Prompt "Set the password for the account" -AsSecureString)

        Write-Output "[*] Adding $Name to the local Users group"
        Add-LocalGroupMember -Group "Users" -Member "$Name"

    }  # End If

}  # End If


# PASSWORD VAULT
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$Vault = New-Object -TypeName Windows.Security.Credentials.PasswordVault
$Vault.RetrieveAll()

$Answer2 = Read-Host -Prompt "[*] If you see any saved passwords in the output above it is because they credentials are most likely saved by Internet Explorer. Would you like to clear these clear text passwords? This only affects the Internet Explorer browser [y/N]"
If ($Answer2 -like "y*") {

    Write-Output "[*] Deleting clear text credentials from the Windows Password Vault"
    ForEach ($V in $Vault) {

        $Cred = New-Object -TypeName Windows.Security.Credentials.PasswordCredential
        $Cred.Resource = $V.RetrieveAll().Resource
        $Cred.UserName = $V.RetrieveAll().UserName
        $V.Remove($Cred)

    }  # End ForEach

}  # End If


# LOGGING
If ($PSVersionTable.PSVersion.Major -lt 5) {

    $PSProfile = "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
    New-Item -Path $PSProfile -ItemType File -Force
    Add-Content -Path $PSProfile -Value '$LogCommandHealthEvent = $true'
    Add-Content -Path $PSProfile -Value '$LogCommandLifecycleEvent = $true'
    Add-Content -Path $PSProfile -Valuie '$LogPipelineExecutionDetails= $true'

}  # End If

Write-Output "[*] Enabling Command Line Logging"
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

Write-Output "[*] Ensure PowerShell versions 4 and 5 are collecting logs"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force

Write-Output "[*] Defining the max log file sizes"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Value 524288000 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Windows PowerShell" -Name "MaxSize" -Value 262144000 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational" -Name "MaxSize" -Value 524288000 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" -Name "MaxSize" -Value 262144000 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" -Name "MaxSize" -Value 262144000 -Force

Write-Output "[*] Enable applying the Advanced Audit Policies"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1

Write-Output "[*] Enable Task Scheduler Logging"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" -Name "Enabled" -Value 1 -Force

Write-Output "[*] Enabling DNS Logging"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNS-Client/Operational" -Name "Enabled" -Value 1 -Force

Write-Output "[*] Enabling USB logging"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DriverFrameworks-UserMode/Operational" -Name "Enabled" -Value 1 -Force

# ENABLE DATA EXECUTION PREVENTION (DEP)
Write-Output "[*] Enabling Data Execution Prevention (DEP)"
Set-Processmitigation -System -Enable DEP

# WINDOWS AUTO UPDATES
$WUSettings = (New-Object -ComObject Microsoft.Update.AutoUpdate).Settings
$WUSettings.NotificationLevel= 3
$WUSettings.Save()

# WINDOWS DEFENDER
Write-Output "Enabling Windows Defender to check archive file types"
Set-MpPreference -DisableArchiveScanning 0

Write-Output "Enabling Windows Defender Potentially Unwanted Program (PUP) protection which prevents applications you do not tell Windows to install from installing"
Set-MpPreference -PUAProtection 1

Set-MpPreference -DisableBehaviorMonitoring $False
Enable-WindowsOptionalFeature -FeatureName "Windows-Defender-ApplicationGuard" -Online

Write-Output "[*] Enabling the sanbox of Windows Defender"
setx /m mp_force_use_sandbox 1

Write-Output "[*] Enabling Structured Exception Handling Overwrite Protection (SEHOP)"
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name DisableExceptionChainValidation -Value 0 -PropertyType Dword

Write-Output "[*] Applying UAC restrictions to local accounts on network logons"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 0 -PropertyType Dword

Write-Output "[*] Configure SMB v1 client driver so it is set to 'Disable driver (recommended)"
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10" -Name Start -Value 4 -PropertyType Dword

Write-Output "[*] Securing Against NetBIOS Name Service (NBT-NS) Poisoning Attacks"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -Name NodeType -Value 2 -PropertyType Dword

Write-Output "[*] Disabling IPv4 Source Routing"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name DisableIPSourceRouting -Value 2 -PropertyType Dword

Write-Output "[*] Disabling IPv6 source routing"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters" -Name DisableIPSourceRouting -Value 2 -PropertyType Dword

Write-Output "[*] Disabling ICMP redirects"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name  EnableICMPRedirect -Value 0 -PropertyType Dword

Write-Output "[*] Preventing a WINS DoS attack avenue"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters" -Name   NoNameReleaseOnDemand -Value 1 -PropertyType Dword

Write-Output "[*] Ensuring the use of Safe DLL Search mode"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name SafeDllSearchMode -Value 1 -PropertyType Dword

Write-Output "[*] Generate an event when security event log reaches 90% capacity"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Eventlog\Security" -Name WarningLevel -Value 90 -PropertyType Dword

Write-Output "[*] Verifing that Windows is configured to have password protection take effect within a limited time frame when the screen saver becomes active."
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ScreenSaverGracePeriod -Value 0 -PropertyType String

Write-Output "[*] Enabling Windows Defender AV to prevent user and apps from accessing dangerous websites"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name EnableNetworkProtection -Value 1 -PropertyType Dword

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU73fEMXqVz89nDE4UfguCVV77
# iT+gggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
# BhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAY
# BgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTExMDUwMzA3MDAwMFoXDTMx
# MDUwMzA3MDAwMFowgbQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMw
# EQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEt
# MCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMw
# MQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0g
# RzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC54MsQ1K92vdSTYusw
# ZLiBCGzDBNliF44v/z5lz4/OYuY8UhzaFkVLVat4a2ODYpDOD2lsmcgaFItMzEUz
# 6ojcnqOvK/6AYZ15V8TPLvQ/MDxdR/yaFrzDN5ZBUY4RS1T4KL7QjL7wMDge87Am
# +GZHY23ecSZHjzhHU9FGHbTj3ADqRay9vHHZqm8A29vNMDp5T19MR/gd71vCxJ1g
# O7GyQ5HYpDNO6rPWJ0+tJYqlxvTV0KaudAVkV4i1RFXULSo6Pvi4vekyCgKUZMQW
# OlDxSq7neTOvDCAHf+jfBDnCaQJsY1L6d8EbyHSHyLmTGFBUNUtpTrw700kuH9zB
# 0lL7AgMBAAGjggEaMIIBFjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
# BjAdBgNVHQ4EFgQUQMK9J47MNIMwojPX+2yz8LQsgM4wHwYDVR0jBBgwFoAUOpqF
# BxBnKLbv9r0FQW4gwZTaD94wNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wNQYDVR0fBC4wLDAqoCigJoYkaHR0cDov
# L2NybC5nb2RhZGR5LmNvbS9nZHJvb3QtZzIuY3JsMEYGA1UdIAQ/MD0wOwYEVR0g
# ADAzMDEGCCsGAQUFBwIBFiVodHRwczovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9z
# aXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAIfmyTEMg4uJapkEv/oV9PBO9sPpyI
# BslQj6Zz91cxG7685C/b+LrTW+C05+Z5Yg4MotdqY3MxtfWoSKQ7CC2iXZDXtHwl
# TxFWMMS2RJ17LJ3lXubvDGGqv+QqG+6EnriDfcFDzkSnE3ANkR/0yBOtg2DZ2HKo
# cyQetawiDsoXiWJYRBuriSUBAA/NxBti21G00w9RKpv0vHP8ds42pM3Z2Czqrpv1
# KrKQ0U11GIo/ikGQI31bS/6kA1ibRrLDYGCD+H1QQc7CoZDDu+8CL9IVVO5EFdkK
# rqeKM+2xLXY2JtwE65/3YR8V3Idv7kaWKK2hJn0KCacuBKONvPi8BDABMIIFIzCC
# BAugAwIBAgIIXIhNoAmmSAYwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNVBAYTAlVT
# MRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQK
# ExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFk
# ZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2Vy
# dGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMjAxMTE1MjMyMDI5WhcNMjExMTA0
# MTkzNjM2WjBlMQswCQYDVQQGEwJVUzERMA8GA1UECBMIQ29sb3JhZG8xGTAXBgNV
# BAcTEENvbG9yYWRvIFNwcmluZ3MxEzARBgNVBAoTCk9zYm9ybmVQcm8xEzARBgNV
# BAMTCk9zYm9ybmVQcm8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ
# V6Cvuf47D4iFITUSNj0ucZk+BfmrRG7XVOOiY9o7qJgaAN88SBSY45rpZtGnEVAY
# Avj6coNuAqLa8k7+Im72TkMpoLAK0FZtrg6PTfJgi2pFWP+UrTaorLZnG3oIhzNG
# Bt5oqBEy+BsVoUfA8/aFey3FedKuD1CeTKrghedqvGB+wGefMyT/+jaC99ezqGqs
# SoXXCBeH6wJahstM5WAddUOylTkTEfyfsqWfMsgWbVn3VokIqpL6rE6YCtNROkZq
# fCLZ7MJb5hQEl191qYc5VlMKuWlQWGrgVvEIE/8lgJAMwVPDwLNcFnB+zyKb+ULu
# rWG3gGaKUk1Z5fK6YQ+BAgMBAAGjggGFMIIBgTAMBgNVHRMBAf8EAjAAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDA1BgNVHR8ELjAsMCqgKKAm
# hiRodHRwOi8vY3JsLmdvZGFkZHkuY29tL2dkaWcyczUtNi5jcmwwXQYDVR0gBFYw
# VDBIBgtghkgBhv1tAQcXAjA5MDcGCCsGAQUFBwIBFitodHRwOi8vY2VydGlmaWNh
# dGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMAgGBmeBDAEEATB2BggrBgEFBQcB
# AQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmdvZGFkZHkuY29tLzBABggr
# BgEFBQcwAoY0aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0
# b3J5L2dkaWcyLmNydDAfBgNVHSMEGDAWgBRAwr0njsw0gzCiM9f7bLPwtCyAzjAd
# BgNVHQ4EFgQUkWYB7pDl3xX+PlMK1XO7rUHjbrwwDQYJKoZIhvcNAQELBQADggEB
# AFSsN3fgaGGCi6m8GuaIrJayKZeEpeIK1VHJyoa33eFUY+0vHaASnH3J/jVHW4BF
# U3bgFR/H/4B0XbYPlB1f4TYrYh0Ig9goYHK30LiWf+qXaX3WY9mOV3rM6Q/JfPpf
# x55uU9T4yeY8g3KyA7Y7PmH+ZRgcQqDOZ5IAwKgknYoH25mCZwoZ7z/oJESAstPL
# vImVrSkCPHKQxZy/tdM9liOYB5R2o/EgOD5OH3B/GzwmyFG3CqrqI2L4btQKKhm+
# CPrue5oXv2theaUOd+IYJW9LA3gvP/zVQhlOQ/IbDRt7BibQp0uWjYaMAOaEKxZN
# IksPKEJ8AxAHIvr+3P8R17UxggJjMIICXwIBATCBwTCBtDELMAkGA1UEBhMCVVMx
# EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT
# EUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2VydHMuZ29kYWRk
# eS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3VyZSBDZXJ0
# aWZpY2F0ZSBBdXRob3JpdHkgLSBHMgIIXIhNoAmmSAYwCQYFKw4DAhoFAKB4MBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYE
# FJ54jWGl+f5CFKpgkgDLyUjNHrkiMA0GCSqGSIb3DQEBAQUABIIBAMUIAkTOaT/J
# R9hyzWClGryEM9g+gfox6vsDKC8RrWmsi3j4TciItD8cPSiWaCBoxKAQl7EgmT76
# WoUevOeluyajqL/aipRH0Vu7nAdrhFi0u05nb8Mp/BS+Prmkweium4HXRdolYDVM
# hu+6BY+bIjZ7rsrC746d0+zyoAu1Eto1itdWMJpRkARxNrQLd5OUUBHlBvnKHxNA
# +i0FfDRblH+dVYVQ6KzW1C/Mr5dv1PH1dwWOH/cD8F+lAwK8p/gogNUjNU3+rI8F
# fobKS3H7sg+k81tOJccU+o7tmjllHXmdgldzZ4RMTJL/2gIEv0qqDtSSwsJ1JTgu
# nKGxtM01reM=
# SIG # End signature block
