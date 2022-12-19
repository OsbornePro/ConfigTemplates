# This script can be run locally as a task to auto-update Gitea on a Windows Server
# Author: Robert Osborne
# Contact: info@osbornepro.com

$NewVersion = (Invoke-WebRequest -Uri https://github.com/go-gitea/gitea/releases/latest -UseBasicParsing).BaseResponse.ResponseUri.OriginalString.Split("/")[-1].Replace("v","")
$GiteaParentPath = "C:\gitea"
$CurrentVersion = (."C:\gitea\gitea.exe" --version).ToString().Split(" ")[2]
$GiteaServiceName = "gitea"

If ($CurrentVersion -ne $NewVersionUrl) {

    Write-Verbose -Message "Gitea not running the latest version"

    $DownloadLink = "https://dl.gitea.io/gitea/$NewVersion/gitea-$NewVersion-gogit-windows-4.0-386.exe"
    $Hash = Invoke-WebRequest -Uri "https://dl.gitea.io/gitea/$NewVersion/gitea-$NewVersion-gogit-windows-4.0-386.exe.sha256" -UseBasicParsing -OutFile "$env:TEMP\gitea-$NewVersion-sha256.txt"
    $Hash = (Get-Content -Path "$env:TEMP\gitea-$NewVersion-sha256.txt").Split(" ")[0]
    $DownloadFile = Invoke-WebRequest -Uri $DownloadLink -UseBasicParsing -OutFile "$env:TEMP\gitea.exe"
    $DLFileHash = (Get-FileHash -Path "$env:TEMP\gitea.exe" -Algorithm SHA256).Hash.ToLower()
    If ($DLFileHash -eq $Hash) {

        Write-Output -InputObject "[*] Successfully verified SHA256 hash values match"

        Write-Output -InputObject "[*] Stopping the running Gitea service - $GiteaServiceName"
        Stop-Service -Name $GiteaServiceName -Force -Confirm:$False

        If (Test-Path -Path "$GiteaParentPath\gitea.exe.old") {

            Write-Output -InputObject "[*] Deleting old Gitea backup executable"
            Remove-Item -Path "$GiteaParentPath\gitea.exe.old" -Force -Confirm:$False

        }  # End If

        Write-Output -InputObject "[*] Backing up the current Gitea executable"
        Rename-Item -Path "$GiteaParentPath\gitea.exe" -NewName "$GiteaParentPath\gitea.exe.old" -Force -Confirm:$False

        Write-Output -InputObject "[*] Using latest version of Gitea executable"
        Move-Item -Path "$env:TEMP\gitea.exe" -Destination "$GiteaParentPath\gitea.exe" -Force -Confirm:$False

        Write-Output -InputObject "[*] Starting up the Gitea service"
        Start-Service -Name $GiteaServiceName

    } Else {

        Throw "Hash values do not match"

    }  # End If Else

} Else {

    Write-Output -InputObject "[*] Gitea is running the latest version"

}  # End If Else
  
