
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
Write-Output -InputObject "$Logo"
Write-Output -InputObject "[*] This script is used to set up LAPS in your domain"
$LapsShareDirectory = "$((Get-CimInstance -Class Win32_Share -Filter "Type=0 and Name LIKE 'NETLOGON'").Path)\LAPS"

$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
If ("$Env:COMPUTERNAME.$env:USERDNSDOMAIN".ToLower() -ne $PDC.ToLower()) {

    Throw "[x] You need to do this on the primary domain controller in your environment : $PDC"

}  # End If


Write-Output -InputObject "[*] Creating $LapsShareDirectory directory to share on network and setting local folder permissions"
New-Item -Path $LapsShareDirectory –ItemType Directory -Force -ErrorAction Stop | Out-Null
New-SMBShare -Name "LAPS" -Path $LapsShareDirectory -FullAccess "Administrators" -ChangeAccess "$env:USERDNSDOMAIN\Domain Admins" -ReadAccess "$env:USERDNSDOMAIN\Domain Users" | Out-Null


If (!(Test-Path -Path C:\Windows\PolicyDefinitions\AdmPwd.admx)) {

    Write-Output -InputObject "[x] You will need to run the install file LAPS.x64.msi which can be downloaded from the below link `n  - https://www.microsoft.com/en-us/download/confirmation.aspx?id=46899"
    Read-Host -Prompt "[!] Press ENTER to continue after you have downloaded and installed the LAPS.x64.msi file from the above link"
    Read-Host -Prompt "[!] Press ENTER after saving the LAPS files like LAPS.x64.msi you downloaded to $LapsShareDirectory"

}  # End If


$Member = Get-ADPrincipalGroupMembership -Identity $env:USERNAME | Where-Object -FilterScript { $_.Name -eq "Schema Admins" }
If (!($Member)) {

    $Answer = Read-Host -Prompt "[?] Would you like to add your current user to the 'Schema Admins' Active Directory group. This is required to update the AD Schema for LAPS usage? [y/N]"
    If ($Answer -like "y*") {

        Write-Output -InputObject "[*] Adding $env:USERNAME to the 'Schema Admins' AD Security Group"
        Add-ADGroupMember -Identity "Schema Admins" -Members $env:USERNAME -Verbose:$False
        Write-Warning -Message "[!] Please log out and log back in to obtain your new permissions!"
        Throw "[x] Log back in to obtain your new Schema Admin permissions"

    }  Else {

        Throw "[x] Schema can not be updated with the current user"

    }  # End Else

}  # End If

Write-Output -InputObject "[*] Updating AD Schema. You may need to restart before this works for the new permissions to apply to your current user"
Update-AdmPwdADSchema


Write-Output -InputObject "[*] Below is a list of current LAPS extended rights permissions"
Try { Find-AdmPwdExtendedRights -Identity "*" } Catch { Write-Verbose -Message "This is here to prevent the error message expected from showing up"}

Do {

    $OU = Read-Host -Prompt "[?] What is the name of the OU that contains your LAPS computers This is required for LAPS to work? EXAMPLE: Computers"
    If ($OU.Length -gt 1) {

        $DN = Get-ADObject -Filter {Name -like $OU} | Select-Object -ExpandProperty DistinguishedName

    }  # End If

    Write-Output -InputObject "[*] Updating the Active Directory Schema for LAPS"
    Set-AdmPwdComputerSelfPermission -Identity $DN

    $Done = Read-Host -Prompt "[?] Would you like to add another OU for LAPS devices? [y/N]"

} Until ($Done -like "N*")


$Answer2 = Read-Host -Prompt "[?] Would you like to set up backups of LAPS password history? This will not exist otherwise [y/N]"
If ($Answer2 -like "y*") {

    Function Set-SecureFilePermission {
        [CmdletBinding()]
            param(
                [Parameter(
                    Mandatory=$True,
                    ValueFromPipeline=$False,
                    HelpMessage="`n[H] Add a user or list of users who should have permisssions to an NTFS file`n[E] EXAMPLE: 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\Network Configuration Operators', 'NT SERVICE\MpsSvc'")]  # End Parameter
                [Alias('User')]
                [String[]]$Username,

                [Parameter(
                    Mandatory=$True,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$False,
                    HelpMessage="`n[H] Define the path to the NTFS item you want to modify the entire permissions on `n[E] EXAMPLE: C:\Temp\file.txt")]  # End Parameter
                [String[]]$Path,

                [Parameter(
                    Mandatory=$False,
                    ValueFromPipeline=$False)]
                [String]$Owner = 'BUILTIN\Administrators',

                [Parameter(
                    Mandatory=$False,
                    ValueFromPipeline=$False)]  # End Parameter
                [Alias('cn')]
                [String[]]$ComputerName = $env:COMPUTERNAME)  # End param


        If ($ComputerName -eq $env:COMPUTERNAME) {

            Write-Verbose -Message "[v] Modifying access rule proteciton"

            $Acl = Get-Acl -Path "$Path" -Verbose:$False
            $Acl.SetAccessRuleProtection($True, $False)

            ForEach ($U in $Username) {

                Write-Verbose "Adding $U permissions for $Path"

                $Permission = $U, 'FullControl', 'Allow'
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission

                $Acl.AddAccessRule($AccessRule)

            }  # End ForEach

            Write-Verbose -Message "[v] Changing the owner of $Path to $Owner"

            $Acl.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount("$Owner")))
            $Acl | Set-Acl -Path "$Path"

        } Else {

            ForEach ($C in $ComputerName) {

                Invoke-Command -ArgumentList $Username,$Path,$Owner -HideComputerName "$C.$env:USERDNSDOMAIN" -UseSSL -Port 5986 -ScriptBlock {

                    $Username = $Args[0]
                    $Path = $Args[1]
                    $Owner = $Args[2]

                    Write-Verbose -Message "[v] Modifying access rule proteciton"

                    $Acl = Get-Acl -Path "$Path" -Verbose:$False
                    $Acl.SetAccessRuleProtection($True, $False)

                    ForEach ($U in $Username) {

                        Write-Verbose "Adding $U permissions for $Path"

                        $Permission = $U, 'FullControl', 'Allow'
                        $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission

                        $Acl.AddAccessRule($AccessRule)

                    }  # End ForEach

                    Write-Verbose "Changing the owner of $Path to $Owner"

                    $Acl.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount("$Owner")))
                    $Acl | Set-Acl -Path "$Path" -Verbose:$False -WhatIf:$False

                }  # End Invoke-Command

            }  # End ForEach

        }  # End Else

    }  # End Function Set-SecureFilePermission

    Write-Output -InputObject "[*] Downloading LAPS backup script and task file"
    (New-Object -TypeName System.Net.WebClient).downloadFile("https://raw.githubusercontent.com/OsbornePro/BackupScripts/main/BackupLAPS.ps1", "C:\Windows\Tasks\BackupLAPS.ps1")
    (New-Object -TypeName System.Net.WebClient).downloadFile("https://raw.githubusercontent.com/OsbornePro/BackupScripts/main/BackupLAPS.xml", "C:\Windows\Tasks\BackupLAPS.xml")

    Write-Output -InputObject "[*] Importing scheduled task to run as SYSTEM which backs up the LAPS password database on the last day of every month"
    $Xml = Get-Content -Path "C:\Windows\Tasks\BackupLAPS.xml" | Out-String
    Register-ScheduledTask -Xml $Xml -TaskName "Backup LAPS" -TaskPath "\" -User "SYSTEM" –Force

    Set-SecureFilePermission -Username 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators' -Path $LapsShareDirectory -Owner 'SYSTEM'

}  # End If

Write-Output -InputObject "[*] You have now updated the Active Directory Schema for LAPS and allowed devices to set their own AD Attribute 'ms-Mcs-AdmPwd' for updating passwords."
