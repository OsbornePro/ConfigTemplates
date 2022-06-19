# This script is used to install an LDAPS certificate in the NTDS Personal and AD LDS service name stores to update the LDAPS certificate 

# https://github.com/tobor88/PowerShell/blob/master/Hide-PowerShellScriptPassword.ps1
$KeyPassword = "LDAPS-S3cr3t-Pa55w0rd" # I have a script at the above link you can use to encrypt this value so it does not show in clear text
$SecurePassword = ConvertTo-SecureString -String $KeyPassword -Force –AsPlainText
#$CertPath = "$env:USERPROFILE\Downloads\LDAPS.pfx"
$LDAPSTemplateName = "LDAP over SSL"
$ServiceNames = "NTDS",((Get-CimInstance -ClassName Win32_Service -Filter 'Name LIKE "%ADAM%"').Name)
# NTDS is the default LDAP service. 
# AD LDS if installed will have a custom service name you set 
# I try to discover that automatically for you using a search for a process with ADAM in the name


Write-Output "[*] Obtaining LDAP over SSL certificate by Template Name from the local machine certificate store"
$LDAPSCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object -FilterScript { $_.Extensions | Where-Object -FilterScript { ($_.Oid.FriendlyName -eq "Certificate Template Information") -and ($_.Format(0) -Match $LDAPSTemplateName) }}
$ExpiringCert = Get-ChildItem -Path Cert:\LocalMachine\My -ExpiringInDays 30 | Where-Object -FilterScript { $_.Extensions | Where-Object -FilterScript { ($_.Oid.FriendlyName -eq "Certificate Template Information") -and ($_.Format(0) -Match $LDAPSTemplateName) }}

If (($LDAPSCert -Contains $ExpiringCert) -and ($Null -ne $LDAPSCert[1])) {

    $LDAPSCert = $LDAPSCert | Where-Object -Property Thumbprint -ne $ExpiringCert.Thumbprint

}  # End If
ElseIf ($LDAPSCert -eq $ExpiringCert) {

    Write-Output "[*] Renewing LDAPS certificate with the same keys"
    Start-Process -WorkingDirectory "C:\Windows\System32" -FilePath certreq.exe -ArgumentList @('-Enroll', '-machine', '-q', '-cert', $LDAPSCert.SerialNumber, 'Renew', 'ReuseKeys') -Wait

    $LDAPSCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object -FilterScript { $_.Extensions | Where-Object -FilterScript { ($_.Oid.FriendlyName -eq "Certificate Template Information") -and ($_.Format(0) -Match $LDAPSTemplateName) }}
    $ExpiringCert = Get-ChildItem -Path Cert:\LocalMachine\My -ExpiringInDays 90 | Where-Object -FilterScript { $_.Extensions | Where-Object -FilterScript { ($_.Oid.FriendlyName -eq "Certificate Template Information") -and ($_.Format(0) -Match $LDAPSTemplateName) }}
    If (($LDAPSCert -ne $ExpiringCert) -and ($Null -ne $ExpiringCert)) {

        Write-Output "[*] Deleting the old certificate from the LocalMachine Certificate store. New certificate has a different thumbprint"
        Get-ChildItem -Path "Cert:\LocalMachine\My\$($ExpiringCert.Thubprint)" | Remove-Item -Force

    }  # End If

}  # End ElseIf
ElseIf ($LDAPSCert -ne $ExpiringCert) {

        Throw "LDAPS Certificate is not ready to be renewed"

}  # End Else

# The commented area below is just in case we need to export or import a PFX certificate into the localmachine store
#
#Write-Output "[*] Exporting LDAPS certificate from LocalMachine store"
#Export-PfxCertificate -FilePath $CertPath -Password $SecurePassword

#Write-Output "[*] Importing new PFX LDAPS Certificate into store"
#Import-PfxCertificate -FilePath $CertPath -CertStoreLocation "Cert:\LocalMachine\My" -Confirm:$False -Password $SecurePassword -Exportable

$Path = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\$($LDAPSCert.Thumbprint)"

Write-Output "[*] Telling LDAPS services to use the new LDAPS Certificate"
ForEach ($ServiceName in $ServiceNames) {

    If ($ServiceName.Length -gt 0) {

        If (Test-Path -Path $Path) {
        
            Write-Output "[*] Moving PFX certificate into the NTDS\Personal Certificate Store"
            Copy-Item -Path $Path -Destination "HKLM:\SOFTWARE\Microsoft\Cryptography\Services\$ServiceName\SystemCertificates\MY\Certificates\"

            Write-Output "[*] Restarting the $ServiceName service"
            Restart-Service -Name $ServiceName -Force

        }  # End If
        Else {

            Write-Warning "Expected registry path defining LDAPS certificate does not exist"

        }  # End Else

    }  # End If

}  # End ForEach
