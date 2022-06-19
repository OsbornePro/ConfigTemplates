# Easily Invoke DC Replication to access newly created certificate tempaltes right away
# LINK : https://github.com/tobor88/PowerShell/blob/master/Invoke-DCReplication.ps1

# This script is used to help set up the RADIUS configuration on Windows Server 2019
Write-Output "[*] Installing Network Policy Authentication Server and management tools on $env:COMPUTERNAME"
Install-WindowsFeature -Name "NPAS" -IncludeManagementTools

Write-Output "[*] Creating a firewall rule to allow RADIUS authentication"
New-NetFirewallRule -DisplayName "Allow RADIUS Authentication" -Direction Inbound -LocalPort 1812,1645 -Protocol UDP -Action Allow -Name "Allow RADIUS Authentication" -Description "Allows communication over RADIUS authentication ports"

Write-Output "[*] Creating a firewall rule to allow RADIUS accounting"
New-NetFirewallRule -DisplayName "Allow RADIUS Accounting" -Direction Inbound -LocalPort 1813,1646 -Protocol UDP -Action Allow -Name "Allow RADIUS Accounting" -Description "Allows communication over RADIUS accounting ports"

Write-Output "[*] Creating a randomly generated string to use as your secure shared secret. Save this value in your Documentation somewhere so it can be retrieved at a later date if needed"
$SharedSecret = ( -Join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count 36  | ForEach-Object {[Char]$_}) )

Write-Output "`n`t[-] SHARED SECRET : $SharedSecret`n"

Write-Output "[*] Creating RADIUS client groups. This can be a subnet or single IP for RADIUS clients allowed to authenticate to the RADIUS server. (Not computers, an example would be RADIUS proxies, Network Access Servers, and Access Points)"
$Loop = 'y'
While ($Loop -like "y*")
{

    $Address = Read-Host -Prompt "Define a single IP address or subnet range used EXAMPLE: 10.0.0.0/24"
    $Name = Read-Host -Prompt "Define a name for this client/subnet to make it identifiable to you. EXAMPLE: NJ Wireless APs"

    New-NpsRadiusClient -Address $Address -Name $Name -SharedSecret $SharedSecret

    $Loop = Read-Host -Prompt "Would you like to add another IP or subnet? [y/N]"

}  # End While

Write-Warning "Save the Shared Secret value $SharedSecret for later use if you have not already done so"

Write-Output "[*] If you would like to ensure TLSv1.2 is used by the Supplicants you can issue the below PowerShell command to force TLSv1.2 in the EAPOL communication"
Write-Output "New-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\RasMan\PPP\EAP\13' -Name TlsVersion -Value 3072"

Pause
