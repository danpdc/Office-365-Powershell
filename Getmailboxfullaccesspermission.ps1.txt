# .SYNOPSIS
# getmailboxpermissions.ps1
#    This script gets all mailboxes FullAccess permission level
#
# The script needs to be run from Exchange Online. 
# Please run the script from Windows Azure Active Directory Module for Windows PowerShell
#
# .DESCRIPTION
#
# Copyright (c) 2015 Microsoft Corporation. All rights reserved.
#
# THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
# OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.




$path = Read-Host "Please enter the path and name to save the CVS file"

Write-Host "Filtering letter A"

$filter = "a*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


Start-Sleep -m 2000

$filter = "b*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "c*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path

Start-Sleep -m 2000

Write-Host "Filtering letter D"

$filter = "d*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "e*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path

Start-Sleep -m 2000

$filter = "f*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "g*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path

Start-Sleep -m 2000

Write-Host "Filtering letter H"

$filter = "h*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "i*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path

Start-Sleep -m 2000

$filter = "j*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


Write-Host "Filtering letter K"

$filter = "k*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path

Start-Sleep -m 2000

$filter = "l*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "m*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path

Start-Sleep -m 2000

$filter = "n*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path



Write-Host "Filtering letter O"

$filter = "o*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path

Start-Sleep -m 2000

$filter = "p*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "q*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path

Start-Sleep -m 2000


Write-Host "Filtering letter R"

$filter = "r*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "s*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path

Start-Sleep -m 2000

$filter = "t*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "u*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path

Start-Sleep -m 2000

$filter = "v*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path

Write-Host "Filtering letter W"

$filter = "w*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path

Start-Sleep -m 2000

$filter = "x*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "y*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path

Start-Sleep -m 2000

$filter = "z*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


Write-Host "Filtering numeric from 0 to 9"

$filter = "0*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "1*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path
$filter = "2*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "3*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path
$filter = "4*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "5*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path
$filter = "6*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "7*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path
$filter = "8*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


$filter = "9*"

Get-Mailbox -Filter "Alias -like '$filter'" | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Export-Csv -Append $path


Import-CSV $path | select Identity, User, AccessRights, InheritanceType, IsInherited | Out-GridView -Title "Mailbox fullaccess permissions"