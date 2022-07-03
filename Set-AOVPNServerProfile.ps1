# The below commands are used to enable modern encryption algorithms on a Windows Server with Always On VPN
# Be sure to issue the matching commands on the client side which I have in my New-AOVPNClientProfile.ps1 script in this same GitHub repository

$Logo = @"
╔═══╗░░╔╗░░░░░░░░░░░░╔═══╗░░░░░
║╔═╗║░░║║░░░░░░░░░░░░║╔═╗║░░░░░
║║░║╠══╣╚═╦══╦═╦═╗╔══╣╚═╝╠═╦══╗
║║░║║══╣╔╗║╔╗║╔╣╔╗╣║═╣╔══╣╔╣╔╗║
║╚═╝╠══║╚╝║╚╝║║║║║║║═╣║░░║║║╚╝║
╚═══╩══╩══╩══╩╝╚╝╚╩══╩╝░░╚╝╚══╝
===============================
If you can't beat `em tech `em!
===============================
https://osbornepro.com
EMAIL: info@osbornepro.com
"@
Write-Output "$Logo"

Set-VpnServerConfiguration -CustomPolicy -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES128 -DHGroup Group14 -EncryptionMethod AES128 -IntegrityCheckMethod SHA256 -PFSgroup PFS2048 -SALifeTimeSeconds 28800 -MMSALifeTimeSeconds 86400 -SADataSizeForRenegotiationKilobytes 1024000

$Thumbprint = 'Root CA Certificate Thumbprint'
$RootCACert = (Get-ChildItem -Path Cert:\LocalMachine\root | Where-Object {$_.Thumbprint -eq $Thumbprint})

Set-VpnAuthProtocol -RootCertificateNameToAccept $RootCACert -PassThru

New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\Ikev2\' -Name CertAuthFlags -PropertyTYpe DWORD -Value 4 -Force

Restart-Service -Name RemoteAccess -PassThru
