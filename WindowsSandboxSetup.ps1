#Requires -Version 3.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
This script is used to setup common security tools in the Windows Sanbox environment


.DESCRIPTION
Quickly setup your Windows Sandbox for security investigations


.PARAMETER DownloadDirectory
Specify the directory to download the tools and applications into


.EXAMPLE
PS> .\WindowsSandboxSetup.ps1
# This example downloads security tools into your Downloads directory

.EXAMPLE
PS> .\WindowsSandboxSetup.ps1 -DownloadDirectory "$env:USERPROFILE\Downloads"
# This example downloads security tools into your Downloads directory

.EXAMPLE
Invoke-Expression -Command (New-Object -TypeName System.Net.WebClient).downloadString('https://raw.githubusercontent.com/OsbornePro/ConfigTemplates/main/WindowsSandboxSetup.ps1')
# This example downloads security tools into your Downloads directory by executing the script existing in GitHub


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: info@osbornepro.com


.INPUTS
None


.OUTPUTS
None
#>
[CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [System.IO.FileInfo]$DownloadDirectory = "$env:USERPROFILE\Downloads"
    )  # End param

    $ContentType = "application/octet-stream"
    $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox

    $SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
    $AutoRunsUrl = "https://download.sysinternals.com/files/Autoruns.zip"
    $ProcMonUrl = "https://download.sysinternals.com/files/ProcessMonitor.zip"
    $SysmonConfigTemplateUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

    $AllLinks = @($ProcMonUrl, $AutoRunsUrl, $SysmonUrl, $SysmonConfigTemplateUrl)
    ForEach ($Uri in $AllLinks) {

        $OutFile = "$($DownloadDirectory.FullName)\$($Uri.Split('/')[-1])"
        Try {

            Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method GET -UserAgent $UserAgent -ContentType $ContentType -OutFile $OutFile -Verbose:$False

        } Catch {

            $WebClient = New-Object -TypeName System.Net.WebClient
            $WebClient.DownloadFile($Uri, $OutFile)

        }  # End Try Catch

        If (!(Test-Path -Path $OutFile)) {

            Write-Warning -Message "[!] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Failed to download $OutFile from $Uri"

        } Else {

            Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Successfully downloaded $OutFile from $Uri"
            
            
            $ProgramName = ($Uri.Split('/')[-1]).Split('.')[0]
            If ($ProgramName -like 'sysmonconfig-export') {

                Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Moving $ProgramName to sysmon destination"
                Move-Item -Path $OutFile -Destination "$env:ProgramFiles\Sysmon\sysmon-config.xml" -Force -Verbose:$False | Out-Null

            } Else {
        
                Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Extracting $ProgramName from $OutFile into $env:ProgramFiles\$ProgramName"
                New-Item -Path $env:ProgramFiles -Name $ProgramName -ItemType Directory -Verbose:$False -WhatIf:$False -ErrorAction SilentlyContinue | Out-Null
                Expand-Archive -Path $OutFile -DestinationPath "$env:ProgramFiles\$ProgramName" -Force -WhatIf:$False -Verbose:$False | Out-Null

            }  # End If Else

        }  # End If Else

    }  # End ForEach

    Set-Location -Path "$env:ProgramFiles\Sysmon" -Verbose:$False
    .\sysmon.exe /accepteula /i .\sysmon-config.xml
