$NTPReg = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time"

Write-Output "[*] Enabling UDP port 123 on firewall for NTP connections"
New-NetFirewallRule -DisplayName "Allow NTP" -Profile @('Domain','Private','Public') -Direction Inbound -Action Allow -Protocol UDP -LocalPort 123 -Description "Allow UPD port 123 traffic for NTP connections"

Write-Output "[*] Enabling NTP Server"
Set-ItemProperty -Path "$NTPReg\TimeProviders\NTPServer" -Name "Enabled" -Value 1 -Force -ErrorAction SilentlyContinue

Write-Output "[*] Enabling NTP announcements"
Set-ItemProperty -Path "$NTPReg\Config" -Name "AnnounceFlags" -Value 5 -Force -ErrorAction SilentlyContinue

Restart-Service -Name W32Time -Force
