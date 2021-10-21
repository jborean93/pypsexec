[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [String]
    $UserName,

    [Parameter(Mandatory)]
    [String]
    $Password
)

Write-Information -MessageData "Allow local admins over network auth"
$regInfo = @{
    Path         = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Name         = "LocalAccountTokenFilterPolicy"
    Value        = 1
    PropertyType = "DWord"
    Force        = $true
}
New-ItemProperty @regInfo

Write-Information -MessageData "Create local admin user"
$userParams = @{
    Name                 = $UserName
    Password             = (ConvertTo-SecureString -AsPlainText -Force -String $Password)
    AccountNeverExpires  = $true
    PasswordNeverExpires = $true
}
$null = New-LocalUser @userParams
Add-LocalGroupMember -Group Administrators -Member $userParams.Name
