#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
Creates a managed Active Directory OU hierarchy for new setups.


.DESCRIPTION
Creates a standardized organizational unit (OU) hierarchy under OU=Managed
in the specified Active Directory domain.

The script is idempotent:
- Existing OUs are left unchanged.
- Missing OUs are created.
- Newly created OUs are protected from accidental deletion.
- Each OU is validated after creation or discovery.
- Existing OU accidental deletion protection is reported but not modified.
- Structured results are returned for reporting and automation.

The script does not move, modify, or delete existing users, groups,
computers, or organizational units.


.PARAMETER DomainName
Specifies the fully qualified DNS name of the Active Directory domain
where the OU hierarchy will be created.

The executing account must have permission to create organizational
units in the target domain.


.EXAMPLE
PS> .\Initialize-ActiveDirectoryOuStructure.ps1 -DomainName 'osbornepro.org'

Creates the managed OU hierarchy in the osbornepro.org domain.
Existing OUs are left unchanged.

.EXAMPLE
PS> $Results = .\Initialize-ActiveDirectoryOuStructure.ps1 -DomainName 'osbornepro.org'
PS> $Results | Format-Table -AutoSize

Creates or validates the OU hierarchy and displays the structured
deployment results.


.OUTPUTS
System.Management.Automation.PSCustomObject

Returns one object per processed OU with the following properties:
- Name
- Path
- DistinguishedName
- ProtectedFromAccidentalDeletion
- Status

Possible Status values:
- CREATED
- UNCHANGED


.NOTES
Last Modified: 10/11/2026
Author: Robert H. Osborne

Target Platform: Windows Server 2025
Required Module: ActiveDirectory
Required Permissions: Create organizational units
Compatible: Windows PowerShell 5.1 and PowerShell 7.x

The ActiveDirectory module must be available in the execution
environment. PowerShell 7 may load the module through Windows
PowerShell compatibility, depending on the host configuration.

This script does not require local administrator elevation when
the executing account already has the necessary AD permissions.
#>

[CmdletBinding()]
  param(
      [Parameter(
          Position=0
          Mandatory=$True,
          HelpMessage="Enter your domain `nEXAMPLE: osbornepro.org `nINPUT: "
      )]  # End Parameter
      [ValidateNotNullOrEmpty()]
      [String]$DomainName
  )  # End param

$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

Try {

    Import-Module -Name ActiveDirectory -ErrorAction Stop
    $Domain = Get-ADDomain -Identity $DomainName -ErrorAction Stop
    $DomainDN = $Domain.DistinguishedName
    Write-Information -MessageData "[PASS] Connected to $DomainDN"

    # Define the organizational unit hierarchy.
    # Parent paths are relative to the domain root.
    # Parent OUs must appear before their children.
    $OUs = @(
        @{ Name = 'Managed';         Parent = '' }

        @{ Name = 'Users';           Parent = 'Managed' }
        @{ Name = 'Standard';        Parent = 'Managed/Users' }
        @{ Name = 'Admins';          Parent = 'Managed/Users' }
        @{ Name = 'Tier0';           Parent = 'Managed/Users/Admins' }
        @{ Name = 'Tier1';           Parent = 'Managed/Users/Admins' }
        @{ Name = 'Tier2';           Parent = 'Managed/Users/Admins' }
        @{ Name = 'Shared';          Parent = 'Managed/Users' }

        @{ Name = 'Groups';          Parent = 'Managed' }
        @{ Name = 'Security';        Parent = 'Managed/Groups' }
        @{ Name = 'Distribution';    Parent = 'Managed/Groups' }

        @{ Name = 'Devices';         Parent = 'Managed' }
        @{ Name = 'Servers';         Parent = 'Managed/Devices' }
        @{ Name = 'Physical';        Parent = 'Managed/Devices/Servers' }
        @{ Name = 'Virtual';         Parent = 'Managed/Devices/Servers' }
        @{ Name = 'Cloud';           Parent = 'Managed/Devices/Servers' }
        @{ Name = 'Workstations';    Parent = 'Managed/Devices' }
        @{ Name = 'Laptops';         Parent = 'Managed/Devices' }

        @{ Name = 'ServiceAccounts'; Parent = 'Managed' }
        @{ Name = 'gMSA';            Parent = 'Managed/ServiceAccounts' }
        @{ Name = 'Standard';        Parent = 'Managed/ServiceAccounts' }

        @{ Name = 'Disabled';        Parent = 'Managed' }
        @{ Name = 'Users';           Parent = 'Managed/Disabled' }
        @{ Name = 'Computers';       Parent = 'Managed/Disabled' }
    )

    $OUPaths = @{
        '' = $DomainDN
    }
    $Results = [System.Collections.Generic.List[Object]]::new()
    ForEach ($OU in $OUs) {

        $Name = $OU.Name
        $ParentKey = $OU.Parent
        If (-not $OUPaths.ContainsKey($ParentKey)) {
            Throw "Parent OU path '$ParentKey' was not resolved."
        }

        $ParentDN = $OUPaths[$ParentKey]
        $Key = If ([String]::IsNullOrEmpty($ParentKey)) {
            $Name
        } Else {
            "$ParentKey/$Name"
        }

        Try {

            $ExistingOU = Get-ADOrganizationalUnit -LDAPFilter "(ou=$Name)" -SearchBase $ParentDN -SearchScope OneLevel -ErrorAction Stop
            If ($ExistingOU) {

                $TargetOU = $ExistingOU
                $Status = 'UNCHANGED'
                Write-Information -MessageData "[UNCHANGED] $Key"

            } Else {

                $TargetOU = New-ADOrganizationalUnit -Name $Name -Path $ParentDN -ProtectedFromAccidentalDeletion $True -PassThru -ErrorAction Stop
                $Status = 'CREATED'
                Write-Information -MessageData "[CREATED] $Key"

            }  # End If Else

            $ValidatedOU = Get-ADOrganizationalUnit -Identity $TargetOU.DistinguishedName -Properties ProtectedFromAccidentalDeletion -ErrorAction Stop
            If ($ValidatedOU.DistinguishedName -ne $TargetOU.DistinguishedName) {
                Throw "OU validation failed for '$Key'."
            }
            $OUPaths[$Key] = $ValidatedOU.DistinguishedName
            If ($Status -eq 'UNCHANGED' -and -not $ValidatedOU.ProtectedFromAccidentalDeletion) {
                Write-Warning -Message "Existing OU '$Key' is not protected from accidental deletion."
            }  # End If

            $Results.Add([PSCustomObject]@{
                Name                            = $Name
                Path                            = $Key
                DistinguishedName               = $ValidatedOU.DistinguishedName
                ProtectedFromAccidentalDeletion = $ValidatedOU.ProtectedFromAccidentalDeletion
                Status                          = $Status
            })

        } Catch {
            Throw "Failed processing OU '$Key': $($_.Exception.Message)"
        }  # End Try Catch

    }  # End ForEach

    $CreatedCount = @($Results | Where-Object -FilterScript {$_.Status -eq 'CREATED'}).Count
    $UnchangedCount = @($Results | Where-Object -FilterScript {$_.Status -eq 'UNCHANGED'}).Count
    $UnprotectedCount = @($Results | Where-Object -FilterScript {-not $_.ProtectedFromAccidentalDeletion}).Count

    Write-Information -MessageData ""
    Write-Information -MessageData "[PASS] OU deployment completed successfully."
    Write-Information -MessageData "[PASS] Domain: $DomainDN"
    Write-Information -MessageData "[PASS] Total OUs: $($Results.Count)"
    Write-Information -MessageData "[CREATED] $CreatedCount"
    Write-Information -MessageData "[UNCHANGED] $UnchangedCount"

    If ($UnprotectedCount -gt 0) {
        Write-Warning -Message "$UnprotectedCount existing OUs are not protected from accidental deletion."
    }  # End If
    $Results

} Catch {
    Throw "Active Directory OU deployment failed: $($_.Exception.Message)"
}  # End Try Catch
