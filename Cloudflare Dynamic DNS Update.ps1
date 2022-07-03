# PURPOSE: Automatically update your Dynamic DNS records if Cloudflare hosts your Domains DNS settings
#
# HOW: This script is meant to be run with Task Scheduler whenever you login or start up your computer. 
# 
$Email = 'cloudflare-email-account@domain.com' 
$Token = 'ur_TokenFromCLoudflareGoesHere' 
$Domain = 'domain.com' 
$Record = 'myvpn.domain.com'

# Build the request headers once. These headers will be used throughout the script.
$Headers = @{
    "X-Auth-Email"  = $($Email)
    "Authorization" = "Bearer $($Token)"
    "Content-Type"  = "application/json"
}  # End Headers

#Region Token Test
## This block verifies that your API key is valid.
## If not, the script will terminate.

$Uri = "https://api.cloudflare.com/client/v4/user/tokens/verify"

$Auth_result = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers
If (!($Auth_result.result)) {

    Write-Output "API token validation failed. Error: $($Auth_result.errors.message). Terminating script."
    # Exit script
    Return
    
}  # End If
Write-Output "API token validation [$($Token)] success. $($Auth_result.messages.message)."
#EndRegion

#Region Get Zone ID
## Retrieves the domain's zone identifier based on the zone name. If the identifier is not found, the script will terminate.
$Uri = "https://api.cloudflare.com/client/v4/zones?name=$($Domain)"
$DnsZone = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers
If (!($DnsZone.result)) {

    Write-Output "Search for the DNS domain [$($Domain)] return zero results. Terminating script."
    # Exit script
    Return
    
}  # End If
## Store the DNS zone ID
$Zone_id = $DnsZone.result.id
Write-Output "Domain zone [$($Domain)]: ID=$($Zone_id)"
#End Region

#Region Get DNS Record
## Retrieve the existing DNS record details from Cloudflare.
$Uri = "https://api.cloudflare.com/client/v4/zones/$($zone_id)/dns_records?name=$($Record)"
$DnsRecord = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers
If (!($DnsRecord.result)) {

    Write-Output "Search for the DNS record [$($Record)] return zero results. Terminating script."
    # Exit script
    Return
    
}
## Store the existing IP address in the DNS record
$Old_ip = $DnsRecord.result.content
## Store the DNS record type value
$Record_type = $DnsRecord.result.type
## Store the DNS record id value
$Record_id = $DnsRecord.result.id
## Store the DNS record ttl value
$Record_ttl = $DnsRecord.result.ttl
## Store the DNS record proxied value
$Record_proxied = $DnsRecord.result.proxied
Write-Output "DNS record [$($Record)]: Type=$($Record_type), IP=$($Old_ip)"
#EndRegion

#Region Get Current Public IP Address
$New_ip = Invoke-RestMethod -Uri 'https://v4.ident.me'
Write-Output "Public IP Address: OLD=$($Old_ip), NEW=$($New_ip)"
#EndRegion

#Region update Dynamic DNS Record
## Compare current IP address with the DNS record
## If the current IP address does not match the DNS record IP address, update the DNS record.
If ($New_ip -ne $Old_ip) {

    Write-Output "The current IP address does not match the DNS record IP address. Attempt to update."
    ## Update the DNS record with the new IP address
    $Uri = "https://api.cloudflare.com/client/v4/zones/$($zone_id)/dns_records/$($record_id)"
    $Body = @{
        type    = $Record_type
        name    = $Record
        content = $New_ip
        ttl     = $Record_ttl
        proxied = $Record_proxied
    } | ConvertTo-Json

    $Update = Invoke-RestMethod -Method PUT -Uri $Uri -Headers $Headers -Body $Body
    If (($Update.errors)) {
    
        Write-Output "DNS record update failed. Error: $($Update[0].errors.message)"
        ## Exit script
        Return
        
    }  # End If

    Write-Output "DNS record update successful."
    Return ($Update.result)
    
} Else {

    Write-Output "The current IP address and DNS record IP address are the same. There's no need to update."
    
}  # End If Else
