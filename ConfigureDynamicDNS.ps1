# OsbornePro LLC.
# This script is meant to be executed in sections. It performs the following actions
#
# 1.) Sets IP address of your DHCP server
# 2.) Renames your DHCP server and restarts it
# 3.) Joins your DHCP server to AD Domain and restarts it
# 4.) Installs the DHCP service
# 5.) Creates DHCP admin and user security groups in Active Directory on locally on DHCP server
# 6.) Creates a Dynamic DNS user
# 7.) Adds DHCP server to DnsUpdateProxy Group
# 8.) Authorizes DHCP server in Active Directory
# 9.) Configures the DHCP service
# 10.) Sets the Dynamic DNS user credentials to use when DHCP server registers DNS records
# 11.) Creates a single DHCP scope and defines Dynamic DNS options for it

#===============================================
# EXECUTE BELOW COMMANDS LOCALLY ON DHCP SERVER
#===============================================
# Set Static IP address for DHCP server
$Domain = Read-Host -Prompt "Enter the domain name to join EXAMPLE: domain.com "
$DnsServer = Read-Host -Prompt "Enter the IP Address of your primary DNS Server "
$PrimaryDC = Read-Host -Prompt "Enter the IP Address of your primary Active Directory Server "
$NTPServer = Read-Host -Prompt "Enter the IP Address of your NTP Server (Typicaly your DC) "
$DhcpIpAddress = Read-Host -Prompt "Enter the DHCP servers IP Address "
$DefaultGateway = Read-Host -Prompt "Enter the default gateway Address for the DHCP scope "
$NewHostname = Read-Host -Prompt "Enter the new hostname for your DHCP server "
$InterfaceAlias = (Get-NetAdapter)[0].InterfaceAlias

Write-Output "[*] Setting IP address on your DHCP server"
New-NetIPAddress -IPAddress $DhcpIpAddress -InterfaceAlias $InterfaceAlias -DefaultGateway $DefaultGateway -AddressFamily IPv4 -PrefixLength 24 -Type Unicast -Confirm:$False
Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $DnsServers

Write-Output "[*] Renaming newly created DHCP server to match your naming convention "
Rename-Computer -ComputerName $NewHostname -DomainCredential (Get-Credential -Message "Enter your Domain Admin credentials") -Force -Restart

#===================================================
# After DHCP Server restarts execute these commands
#===================================================
Write-Output "[*] Adding server to your domain"
$Domain = Read-Host -Prompt "Enter the domain name to join EXAMPLE: domain.com "
Add-Computer -ComputerName "$($env:COMPUTERNAME).$($Domain)" -Server $PrimaryDC -OUPath "CN=Computers,DC=$env:USERDOMAIN,DC=com" -DomainName $Domain -Credential (Get-Credential -Message "Enter your Domain Admin credentials") -Restart -Force

#===================================================
# After DHCP Server restarts execute these commands
#===================================================
Write-Output "[*] Installing the DHCP service"
Install-WindowsFeature -Name DHCP -IncludeManagementTools

$Domain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
$FQDN = "$($NewHostname).$($Domain)"

# Create local DHCP security groups on DHCP server
Add-DhcpServerSecurityGroup -ComputerName $FQDN
Restart-Service -Name DHCPServer -Force

#====================================================
# EXECUTE BELOW COMMANDS ON ACTIVE DIRECTORY SERVER
#====================================================
# Create the Dynamic DNS user with normal user permissions
$DHCPServer = Read-Host -Prompt "What is the hostname of your DHCP server? EXMAPLE: dhcp01"
New-ADUser -Name "Dynamic DNS" -GivenName "Dynamic" -Surname "DNS" -SamAccountName "dyndns" -AccountPassword (Read-Host -AsSecureString "Enter strong password for accont. This password should be very long") -ChangePasswordAtLogon $False -Description "This account is used by the DHCP servers to register Dynamic DNS updates" -DisplayName "Dynamic DNS" -Enabled $True
Get-ADUser -Filter 'SamAccountName -like "dyndns"' -SearchBase "CN=Users,DC=$env:USERDOMAIN,DC=com" | Set-ADUser -PasswordNeverExpires:$True -CanNotChangePassword:$True
# Create the required DHCP groups in Active Directory
New-ADGroup -Name "DHCP Administrators" -DsiplayName "DHCP Administrators" -SamAccountName "DHCP Administrators" -GroupCategory Security -GroupScope Global -Path "CN=Users,DC=$env:USERDOMAIN,DC=com" -Description "Members of this group have DHCP administrative permissions"
New-ADGroup -Name "DHCP Users" -DsiplayName "DHCP Users" -SamAccountName "DHCP Users" -GroupCategory Security -GroupScope Global -Path "CN=Users,DC=$env:USERDOMAIN,DC=com" -Description "Members of this group have limited DHCP permissions"
Write-Output "[*] Adding DHCP server to DNSUpdateProxy group which is required for Dynamic DNS"
Add-ADGroupMember -Identity DnsUpdateProxy -Members "$($DHCPServer)$"


#===================================================
# Execute these commands on the DHCP server
#===================================================
# Authorize the DHCP server in Active Directory
Add-DhcpServerInDC -DnsName $FQDN -IPAddress $DhcpIpAddress
$CheckAuthorizedDhcpServer = Get-DhcpServerInDC
If ($CheckAuthorizedDhcpServer.DnsName -contains $FQDN) {

    Write-Output "[*] Successfully authorized DHCP server $FQDN in Active Directory"
    Write-Output "[*] Notifying 'Server Manager' application of the update"
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12 -Name ConfigurationState -Value 2

} Else {

    Throw "Make sure you are a member of the 'Enterprise Admins' Security Group. DHCP server is not authorized in Active Directory. "

}  # End If Else

$Domain = Read-Host -Prompt "Enter the domain name to join EXAMPLE: domain.com "
$DnsServer = Read-Host -Prompt "Enter the IP Address of your primary DNS Server "
$PrimaryDC = Read-Host -Prompt "Enter the IP Address of your primary Active Directory Server "
$NTPServer = Read-Host -Prompt "Enter the IP Address of your NTP Server (Typicaly your DC) "
$DhcpIpAddress = Read-Host -Prompt "Enter the DHCP servers IP Address "
$DefaultGateway = Read-Host -Prompt "Enter the default gateway Address for the DHCP scope "
$NewHostname = Read-Host -Prompt "Enter the hostname for your DHCP server "
$InterfaceAlias = (Get-NetAdapter)[0].InterfaceAlias
$ScopeName = Read-Host -Prompt "Enter an identifying name for your new DHCP Scope EXAMPLE: Servers :"
$ScopeID = Read-Host -Prompt "Enter your Scope ID EXAMPLE: 192.168.137.0 :" 
$StartRange = Read-Host -Prompt "Enter the starting range for DHCP scope EXAMPLE: 192.168.137.1 :"
$EndRange = Read-Host -Prompt "Enter the ending rnage for the DHCP scope EXMAMPLE: 192.168.137.254 :"
$FQDN = "$($NewHostname).$($Domain)"
Write-Output "[*] Setting the server level DNS Dynamic Update configuration settings"
Set-DhcpServerv4DnsSetting -ComputerName $FQDN -DynamicUpdates Always -NameProtection $True
Set-DhcpServerDnsCredential -Credential (Get-Credential -Message "Enter credentials for the normal user account used to update Dynamic DNS records through the DHCP server") -ComputerName $FQDN

Write-Output "[*] Enabling the ability to deny assigning IP addresses to MAC addresses"
Set-DhcpServerv4FilterList -ComputerName $FQDN -Allow $False -Deny $True

Write-Output "[*] Creating an initial scope on the DHCP server and setting options"
Add-DhcpServerv4Scope -Name $ScopeName -StartRange $StartRange -EndRange $EndRange -Description "Default $ScopeName subnet" -SubnetMask 255.255.255.0 -State Active
Add-DhcpServerv4ExclusionRange -ScopeId $ScopeID -StartRange $StartRange -EndRange $EndRange -ComputerName $FQDN
Set-DhcpServerv4OptionValue -ComputerName $FQDN -ScopeId $ScopeID -DnsServer $DnsServer -DnsDomain $Domain -Router $DefaultGateway -Force
Set-DhcpServerv4OptionValue -OptionId 42 -Value $NTPServer -ScopeId $ScopeID -ComputerName $FQDN

Write-Output "[*] Disabling NetBIOS in DHCP assignments"
Set-DhcpServerv4OptionValue -ComputerName $FQDN -VendorClass "Microsoft Options" -OptionId 1 -Value 1
Set-DhcpServerv4OptionValue -ComputerName $FQDN -VendorClass "Microsoft Windows 2000 Options" -OptionId 1 -Value 1
