<#
.SYNOPSIS
    Azure Entra ID Stale User Audit
    CIS Benchmark Control: 1.23

.DESCRIPTION
    Finds user accounts inactive for 90+ days based on last
    sign-in activity. Exports to CSV for access review.

    Common use case: quarterly access reviews, offboarding
    verification, license reclamation.

.REQUIREMENTS
    Az PowerShell module: Install-Module Az
    Microsoft.Graph module: Install-Module Microsoft.Graph
    User.Read.All permission in Entra ID
#>

Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All"

$threshold   = (Get-Date).AddDays(-90)
$staleUsers  = @()
$allUsers    = Get-MgUser -All -Property "DisplayName,UserPrincipalName,SignInActivity,AccountEnabled,Department,JobTitle"

foreach ($user in $allUsers) {

    # skip disabled accounts — already handled
    if (-not $user.AccountEnabled) { continue }

    $lastSignIn = $user.SignInActivity?.LastSignInDateTime

    # no sign-in record at all — flag it
    if (-not $lastSignIn) {
        $staleUsers += [PSCustomObject]@{
            DisplayName        = $user.DisplayName
            UPN                = $user.UserPrincipalName
            Department         = $user.Department
            JobTitle           = $user.JobTitle
            LastSignIn         = "Never recorded"
            DaysInactive       = "Unknown"
            AccountEnabled     = $user.AccountEnabled
            Risk               = "MEDIUM"
            CISControl         = "CIS 1.23"
            Recommendation     = "Verify with manager — disable if no business need"
        }
        continue
    }

    $daysInactive = (New-TimeSpan -Start $lastSignIn -End (Get-Date)).Days

    if ($lastSignIn -lt $threshold) {
        $risk = if ($daysInactive -gt 180) { "HIGH" } else { "MEDIUM" }

        $staleUsers += [PSCustomObject]@{
            DisplayName        = $user.DisplayName
            UPN                = $user.UserPrincipalName
            Department         = $user.Department
            JobTitle           = $user.JobTitle
            LastSignIn         = $lastSignIn
            DaysInactive       = $daysInactive
            AccountEnabled     = $user.AccountEnabled
            Risk               = $risk
            CISControl         = "CIS 1.23"
            Recommendation     = "Disable account — inactive $daysInactive days"
        }
    }
}

Write-Host "`nFound $($staleUsers.Count) stale active accounts" -ForegroundColor Yellow
$staleUsers | Format-Table DisplayName, UPN, DaysInactive, Risk -AutoSize

$date = Get-Date -Format "yyyyMMdd"
$staleUsers | Export-Csv -Path "entra-stale-users-$date.csv" -NoTypeInformation
Write-Host "Exported to entra-stale-users-$date.csv" -ForegroundColor Green
