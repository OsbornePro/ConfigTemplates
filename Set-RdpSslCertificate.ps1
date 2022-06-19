Import-Module ActiveDirectory
[datetime]$Today = Get-Date
[datetime]$CutOffDate = $Today.AddDays(-60)
[array]$ComputerNames = Get-ADComputer  -Properties * -Filter { LastLogonDate -gt $CutOffDate -and Enabled -eq $True } | Select-Object -ExpandProperty Name

Invoke-Command -HideComputerName $ComputerName -UseSSL -ScriptBlock {

  $CurrentCertificate = Get-CimInstance -Class "Win32_TSGeneralSetting" -Namespace "Root/CimV2/TerminalServices" -Filter "TerminalName='RDP-tcp'"
  $NewCertificate = Get-ChildItem -Path "Cert:/LocalMachine/My" | Where-Object -Property "EnhancedKeyUsageList" -like "*Remote Desktop Authentication*" | Sort-Object -Property "Thumbprint" | Select-Object -First 1
  $NewCertificatesThumbprint = $NewCertificate.Thumbprint   

  If (($CurrentCertificate.SSLCertificateSHA1Hash -notlike $NewCertificate.Thumbprint) -and ($NewCertificate) ) {

      $Path = (Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace "Root\CimV2\TerminalServices" -Filter "TerminalName='RDP-tcp'").__Path
      Set-WmiInstance -Path $Path -Argument @{SSLCertificateSHA1Hash="$NewCertificatesThumbprint"}
      Write-Output "[*] Set RDP Certificate on $env:COMPUTERNAME" -ForegroundColor Green

  } # End If
  Else {

    Write-Output "[*] Correct certificate is already set or no RDP Cert exists yet on $env:COMPUTERNAME"

  } # End Else

} # End ScriptBlock
