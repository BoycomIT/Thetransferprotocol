$TargetOU    = "OU=HQ-Lestlania,DC=cvpl4,DC=local"

$ExcludedOUs = @(
    "OU=IT,OU=HQ-Lestlania,DC=cvpl4,DC=local",
    "OU=CTF-Users,OU=CTF,OU=STAB,OU=HQ-Lestlania,DC=cvpl4,DC=local",
    "OU=CO-Users,OU=CO,OU=STAB,OU=HQ-Lestlania,DC=cvpl4,DC=local",
    "OU=Ressources,OU=HQ-Lestlania,DC=cvpl4,DC=local"
)

$OutputCsv   = "C:\Report.csv"
#-------------------------------------------------------------------------

function Test-InExcludedOU {
    param([string]$DistinguishedName)

    foreach ($ou in $ExcludedOUs) {
        if ($DistinguishedName -like "*$ou") {
            return $true
        }
    }
    return $false
}

function New-RandomPassword {
    param([int]$Length = 12)

    $upper   = 65..90  | ForEach-Object {[char]$_}
    $lower   = 97..122 | ForEach-Object {[char]$_}
    $digits  = 48..57  | ForEach-Object {[char]$_}
    $special = '!@#$%^&*'.ToCharArray()
    $all     = $upper + $lower + $digits + $special

    # guarantee at least one of each category, then fill the rest randomly
    $password = @(
        $upper   | Get-Random
        $lower   | Get-Random
        $digits  | Get-Random
        $special | Get-Random
    )
    $password += 1..($Length - 4) | ForEach-Object { $all | Get-Random }

    -join ($password | Sort-Object { Get-Random })
}

# Get every user under the target OU
$allUsers = Get-ADUser -Filter * -SearchBase $TargetOU -Properties DistinguishedName

# Filter out anyone in an excluded sub-OU
$usersToReset = $allUsers | Where-Object { -not (Test-InExcludedOU $_.DistinguishedName) }

Write-Host "Found $($allUsers.Count) total users under $TargetOU"
Write-Host "Excluding $($allUsers.Count - $usersToReset.Count) users in excluded OUs"
Write-Host "Resetting passwords for $($usersToReset.Count) users..."

$results = foreach ($user in $usersToReset) {
    $plainPassword  = New-RandomPassword -Length 12
    $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force

    try {
        Set-ADAccountPassword -Identity $user.DistinguishedName -NewPassword $securePassword -Reset -ErrorAction Stop
        Set-ADUser -Identity $user.DistinguishedName -ChangePasswordAtLogon $true -ErrorAction Stop

        [PSCustomObject]@{
            SamAccountName = $user.SamAccountName
            Name           = $user.Name
            NewPassword    = $plainPassword
            Status         = "Success"
        }
    }
    catch {
        [PSCustomObject]@{
            SamAccountName = $user.SamAccountName
            Name           = $user.Name
            NewPassword    = ""
            Status         = "FAILED: $($_.Exception.Message)"
        }
    }
}

$results | Export-Csv -Path $OutputCsv -NoTypeInformation
Write-Host "`nDone. Results written to $OutputCsv"
Write-Host "Remember to securely distribute these passwords and delete the CSV afterward."