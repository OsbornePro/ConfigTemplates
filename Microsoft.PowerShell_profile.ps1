#----------------------------------------------------#
#  OsbornePro Template : Windows PowerShell Profile  #
#----------------------------------------------------#
# Edit this file in your PowerShell session using the below command
# notepad $PROFILE

Write-Verbose "Setting start directory location."
    Set-Location $env:USERPROFILE

Write-Verbose "Setting Window's Title Header"
    $Shell = $Host.UI.RawUI
    $Shell.WindowTitle = "OsbornePro: $env:USERNAME"

Write-Verbose "Setting Window default color combinations"
    $Shell.ForegroundColor = 'Gray'
    $Shell.BackgroundColor = 'Black'
    $TextColors = $Host.PrivateData
    $TextColors.DebugForegroundColor = 'Cyan'
    $TextColors.VerboseForegroundColor = 'Cyan'
    $TextColors.ErrorForegroundColor = 'DarkYellow'
    $TextColors.WarningForegroundColor = 'Yellow'
    $TextColors.ProgressForegroundColor = 'DarkGreen'

Write-Verbose "Create a directory to save your PowerShell transcript logs"
    New-Item -Path $env:TEMP -Name Transcripts -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

Write-Verbose "Delete saved PowerShell transcripts that are older than 7 days"
    Get-ChildItem -Path "$env:TEMP\Transcripts" -Force -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.CreationTime -ge (Get-Date).AddDays(7) } | Remove-Item -Force -Confirm:$False -ErrorAction SilentlyContinue

Write-Verbose "Save a transcript of your PowerShell sessions. Exiting a powershell session will stop transcription"
    $Transcript = "$env:TEMP\Transcripts\$(Get-Date -Format yyyy-MM-dd_hh-mm-ss).txt"
    Start-Transcript -Path $Transcript -Force | Out-Null
    
Write-Verbose "Clearing output to only show transcript log file location"
    Clear-Host

Write-Output "Path to transript log file saved in `$Transcript"
Write-Host "Welcome back $env:USERNAME!" -ForegroundColor Green

#Write-Verbose 'Setting the Window Buffer Size'
#    $BufferSize = $Shell.BufferSize
#    $BufferSize.Width = 120
#    $BufferSize.Height = 9001
#    $Shell.BufferSize = $BufferSize

#Write-Verbose "Setting Max Window Size. I don't usually do these becuase it messes with the buffer."
#    $MaxWindowSize = $Shell.MaxWindowSize
#    $MaxWindowSize.Width = 237
#    $MaxWindowSize.Height = 63
#    $Shell.BufferSize = $MaxWindowSize

#Write-Verbose "Setting the Window Size"
#    $WindowSize = $Shell.WindowSize
#    $WindowSize.Width = 120
#    $WindowSize.Height = 30
#    $Shell.BufferSize = $WindowSize
