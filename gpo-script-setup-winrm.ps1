#Requires -Version 5.1
# This script is meant to be used as a start up script via Group Policy.
# GPO can configure settings for WinRM over HTTPS but it does not create the
# HTTPS listener and attach the certificate to the service. That is what this
# script means to achieve.
$ErrorActionPreference = 'Stop'
$WinRMCertTemplateName = 'WinRM over HTTPS'
$LogDirectory = Join-Path -Path $env:TEMP -ChildPath 'Script\Logs'
$TranscriptStarted = $false
try {
    New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Start-Transcript -Path (Join-Path -Path $LogDirectory -ChildPath 'PSTranscript_WinRM_Config.txt') -Append -ErrorAction Stop | Out-Null
    $TranscriptStarted = $true

    Write-Output -InputObject '[*] Beginning WinRM HTTPS configuration'
    $FQDN = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    $Certificates = @(Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop | Where-Object -FilterScript {
        $Certificate = $_
        $TemplateMatch = @($Certificate.Extensions | Where-Object -FilterScript {
            $_.Oid.Value -in @('1.3.6.1.4.1.311.21.7', '1.3.6.1.4.1.311.20.2') -and
            $_.Format($false) -match [regex]::Escape($WinRMCertTemplateName)
        }).Count -gt 0

        $ServerAuth = @($Certificate.EnhancedKeyUsageList | Where-Object -FilterScript {
            $_.ObjectId -eq '1.3.6.1.5.5.7.3.1'
        }).Count -gt 0

        $DnsMatch = @($Certificate.DnsNameList | Where-Object -FilterScript {
            $_.Unicode -eq $FQDN
        }).Count -gt 0

        $TemplateMatch -and $ServerAuth -and $DnsMatch -and
        $Certificate.HasPrivateKey -and
        $Certificate.NotBefore -le (Get-Date) -and
        $Certificate.NotAfter -gt (Get-Date) -and
        $Certificate.Subject -ne $Certificate.Issuer
    } | Sort-Object -Property NotAfter -Descending)

    if ($Certificates.Count -eq 0) {
        throw "No suitable certificate found from template '$WinRMCertTemplateName' for '$FQDN'. Verify certificate enrollment, DNS name, private key, and Server Authentication EKU."
    }  # End if

    $WinRMCertificate = $Certificates[0]
    $Thumbprint = $WinRMCertificate.Thumbprint

    Write-Output "[PASS] Certificate selected: $Thumbprint"
    Write-Output "[PASS] Certificate expires: $($WinRMCertificate.NotAfter)"

    $CurrentListener = Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop | Where-Object {
        $_.Keys -contains 'Transport=HTTPS' -and $_.Keys -contains 'Address=*'
    }

    if ($CurrentListener) {
    
        $CurrentThumbprint = (Get-Item -Path "WSMan:\localhost\Listener\$($CurrentListener.Name)\CertificateThumbprint" -ErrorAction Stop).Value
        $CurrentHostname = (Get-Item -Path "WSMan:\localhost\Listener\$($CurrentListener.Name)\Hostname" -ErrorAction Stop).Value
        if ($CurrentThumbprint -eq $Thumbprint -and $CurrentHostname -eq $FQDN) {
            Write-Output -InputObject '[UNCHANGED] WinRM HTTPS listener already uses the correct certificate.'
        } else {
            Set-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{Address='*'; Transport='HTTPS'} -ValueSet @{Hostname=$FQDN; CertificateThumbprint=$Thumbprint} -ErrorAction Stop | Out-Null
            Write-Output -InputObject '[UPDATED] WinRM HTTPS listener certificate updated.'
        }  # End if else
    } else {
        New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{Address='*'; Transport='HTTPS'} -ValueSet @{Hostname=$FQDN; CertificateThumbprint=$Thumbprint} -ErrorAction Stop | Out-Null
        Write-Output -InputObject '[CREATED] WinRM HTTPS listener created.'
    }  # End if else

    $Listener = Get-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{Address='*'; Transport='HTTPS'} -ErrorAction Stop
    if ($Listener.CertificateThumbprint -ne $Thumbprint -or $Listener.Hostname -ne $FQDN -or $Listener.Enabled -eq 'false') {
        throw 'WinRM HTTPS listener validation failed.'
    }  # End if

    Test-WSMan -ComputerName $FQDN -UseSSL -ErrorAction Stop | Out-Null
    Write-Output -InputObject "[PASS] WinRM HTTPS connection validated on $FQDN port 5986."
    Write-Output -InputObject '[PASS] WinRM HTTPS configuration completed successfully.'
} catch {
    throw "[FAIL] WinRM HTTPS configuration failed: $($_.Exception.Message)"
} finally {
    if ($TranscriptStarted) {
        Stop-Transcript | Out-Null
    }  # End if
}  # End Try Catch Finally
