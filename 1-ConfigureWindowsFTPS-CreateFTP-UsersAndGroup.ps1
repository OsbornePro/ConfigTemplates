# This script is meant to be executed on a Primary Domain Controller. This will create an FTP Users group and FTP Admins group using a name you define.
# This script will then use the contents of a CSV file to add users to their respective groups and define their FTP home directories in Active Directory
#
# This script will need a CSV file with contents similar to those below
#
# CONTENTS OF UserList.csv ----------------------------
#SamAccountName,Directory,Root,Permission
#rosborne,\\ftp.osbornepro.com\FTPS,\,Admin
#legion,\\ftp.osbornepro.com\FTPS\ShadowKing,\,User
#theshadowking,\\ftp.osbornepro.com\FTPS\Legion,\,User
# END CONTENTS OF UsersList.csv -----------------------
#
If (Test-Path -Path $env:USERPROFILE\Documents\UserList.csv) {

    Write-Output "[*] UserList.csv file has been found to exist"

} Else {

    New-Item -Path $env:USERPROFILE\Documents\UserList.csv -ItemType File -Value "SamAccountName,Directory,Root,Permission`nrosborne,\\ca.osbornepro.com\C$\inetpub\ftproot,\FTPS,Admin"
    Read-Host -Prompt "[!] The $env:USERPROFILE\Documents\UserList.csv file did not exist. It has now been created. Add values to the files and press ENTER when you are ready. Read the comments of this script to obtain the correct Header values to use"

}  # End If Else

Import-Module -Name ActiveDirectory -Global

$AdminGroup = Read-Host -Prompt "Enter a name for the FTP admins group. EXAMPLE: FTP-Admins"
$UserGroup = Read-Host -Prompt "Enter a name for the FTP Users group. EXAMPLE: FTP-Users"

Write-Output "[*] Creating AD FTP users group $UserGroup"
New-ADGroup -Name $UserGroup -GroupScope Global -GroupCategory Security -Confirm:$False

Write-Output "[*] Creating AD FTP admin group $AdminGroup"
New-ADGroup -Name $AdminGroup -GroupScope Global -GroupCategory Security -Confirm:$False


Write-Output "[*] Importing users from CSV file"
$Users = Import-Csv -Path "$env:USERPROFILE\Documents\UserList.csv" -Delimiter ","

ForEach ($User In $Users) {

    $SamAccountName = $User.SamAccountName
    $MSiisFTPdir = $User.Directory
    $MSiisFTPRoot = $User.Root
    $Permission = $User.Permission

    If ($Permission -eq 'User') {

        Write-Output "[*] Adding $SamAccountName to $UserGroup"
        Add-ADGroupMember -Identity $UserGroup -Members $SamAccountName

    } ElseIf ($Permission -eq 'Admin') {

        Write-Output "[*] Adding $SamAccountName to $AdminGroup"
        Add-ADGroupMember -Identity $AdminGroup -Members $SamAccountName

    }  # End If ElseIf

    Write-Output "[*] Setting $SamAccountName FTP root dir attributes"
    Set-ADUser -Identity $SamAccountName -Replace @{'msIIS-FTPDir'=$MSiisFTPdir; 'msIIS-FTPRoot'=$MSiisFTPRoot}

}  # End ForEach
