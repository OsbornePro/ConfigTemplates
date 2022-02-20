# I built this script because the Always on VPN client profile creation script Microsoft provided is garbage. Mine is better. 
# They use WMI objects which has created issues with Windows 11 and returns Access Denied errors in Windows 10
$ServerAddress = Read-Host -Prompt "Enter the public DNS name of your AOVPN Server EXAMPLE: aovpn.domain.com"
$NPSServer = Read-Host -Prompt "Enter the FQDN of your NPS server that will be authenticating the RADIUS requests EXAMPLE: nps-server.domain.com"
$Connection = Read-Host -Prompt "Enter the connection name as you would like it to appear to your users EXAMPLE: Contoso Network"
$RootCAThumbprint = Read-Host -Prompt "Enter your Root Certificate Authorities Serial number/Thumbprint EXAMPLE: aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 a0 a1 a2 c2"

Write-Output "[*] Modifying the EAP XML Configuration file to contain the values you defined"
$InnerXML1 = ((New-EapConfiguration -Tls -VerifyServerIdentity).EapConfigXmlStream | Select-Object -ExpandProperty InnerXML).Replace("<DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>","<DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>").Replace("<ServerNames></ServerNames>","<ServerNames>$NPSServer</ServerNames><TrustedRootCA>$RootCAThumbprint </TrustedRootCA>")
$TunnledEapAuthMethod = (New-EapConfiguration -Tls -VerifyServerIdentity).EapConfigXmlStream 
$TunnledEapAuthMethod.InnerXml = $InnerXML1

$InnerXML2 = ((New-EapConfiguration -Peap -VerifyServerIdentity -TunnledEapAuthMethod $TunnledEapAuthMethod -FastReconnect $True).EapConfigXmlStream | Select-Object -ExpandProperty InnerXml).Replace("<DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>","<DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>").Replace("<ServerNames></ServerNames>","<ServerNames>$NPSServer</ServerNames><TrustedRootCA>$RootCAThumbprint </TrustedRootCA>").Replace("<GroupSmartCardCerts>true</GroupSmartCardCerts>","<FilteringInfo xmlns=`"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV3`"><CAHashList Enabled=`"true`"><IssuerHash>$RootCAThumbprint </IssuerHash><IssuerHash>$RootCAThumbprint </IssuerHash></CAHashList></FilteringInfo>").Replace("<CredentialsSource><SmartCard /></CredentialsSource>","<CredentialsSource><CertificateStore><SimpleCertSelection>true</SimpleCertSelection></CertificateStore></CredentialsSource>")
$EapConfigXmlStream = (New-EapConfiguration -Peap -VerifyServerIdentity -TunnledEapAuthMethod $TunnledEapAuthMethod -FastReconnect $True).EapConfigXmlStream
$EapConfigXmlStream.InnerXml = $InnerXML2

Write-Output "[*] Creating the VPN Connection"
Add-VPNConnection -Name $Connection -ServerAddress $ServerAddress -TunnelType Ikev2 -RememberCredential -SplitTunneling -Force -EncryptionLevel Maximum -PassThru -AllUserConnection -DnsSuffix "usav.org" -AuthenticationMethod Eap -EapConfigXmlStream $EapConfigXmlStream 

Write-Output "[*] Defining strong encryption protocols. These must match the server"
Set-VpnConnectionIPsecConfiguration -ConnectionName $Connection -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES128 -DHGroup Group14 -EncryptionMethod AES128 -IntegrityCheckMethod SHA256 -PFSgroup PFS2048 -Force

Write-Warning "The below commands now need to be issued on your AOVPN server to improve encryption and use Certificate revocation checks"
Write-Output '

Set-VpnServerConfiguration -CustomPolicy -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES128 -DHGroup Group14 -EncryptionMethod AES128 -IntegrityCheckMethod SHA256 -PFSgroup PFS2048 -SALifeTimeSeconds 28800 -MMSALifeTimeSeconds 86400 -SADataSizeForRenegotiationKilobytes 1024000
$RootCACert = (Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object -FilterScript {$_.Thumbprint -eq $RootCAThumbprint})
Set-VpnAuthProtocol -RootCertificateNameToAccept $RootCACert -PassThru
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\Ikev2\ -Name CertAuthFlags -PropertyTYpe DWORD -Value 4 -Force
Restart-Service -Name RemoteAccess -PassThru
'
