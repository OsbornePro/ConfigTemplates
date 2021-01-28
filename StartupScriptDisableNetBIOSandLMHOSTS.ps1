Write-Verbose "Disabling NetBIOS and mDNS"
$CIMInstance = Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration
$CIMInstance | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2}

Write-Verbose "Disabling the use of the LMHOSTS file"
Invoke-CimMethod -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments @{ DNSEnabledForWINSResolution = $False; WINSEnableLMHostsLookup = $False }
