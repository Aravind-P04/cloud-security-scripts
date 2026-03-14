<#
.SYNOPSIS
    Azure NSG Security Audit
    CIS Benchmark Controls: 6.1, 6.2

.DESCRIPTION
    Flags NSG rules allowing unrestricted inbound traffic from
    0.0.0.0/0, *, or Internet. Exports findings to CSV.

.REQUIREMENTS
    Az PowerShell module: Install-Module Az
    Reader role on target subscription
#>

Connect-AzAccount

$findings = @()
$nsgs = Get-AzNetworkSecurityGroup

foreach ($nsg in $nsgs) {
    foreach ($rule in $nsg.SecurityRules) {

        if ($rule.Direction -ne "Inbound") { continue }
        if ($rule.Access -ne "Allow") { continue }

        $openSources = @("*", "0.0.0.0/0", "Internet", "Any")
        if ($rule.SourceAddressPrefix -notin $openSources) { continue }

        $risk = "HIGH"
        $cis  = "CIS 6.1"

        # escalate to critical for admin ports
        $adminPorts = @("22", "3389", "1433", "3306", "*")
        if ($rule.DestinationPortRange -in $adminPorts) {
            $risk = "CRITICAL"
            $cis  = "CIS 6.1, 6.2"
        }

        $findings += [PSCustomObject]@{
            NSG           = $nsg.Name
            ResourceGroup = $nsg.ResourceGroupName
            Location      = $nsg.Location
            RuleName      = $rule.Name
            Port          = $rule.DestinationPortRange
            Source        = $rule.SourceAddressPrefix
            Risk          = $risk
            CISControl    = $cis
            Remediation   = "Restrict source to known IPs or remove rule"
        }
    }
}

if ($findings.Count -eq 0) {
    Write-Host "No unrestricted inbound NSG rules found." -ForegroundColor Green
} else {
    Write-Host "Found $($findings.Count) unrestricted inbound rules:" -ForegroundColor Red
    $findings | Format-Table -AutoSize

    $date = Get-Date -Format "yyyyMMdd"
    $findings | Export-Csv -Path "nsg-audit-$date.csv" -NoTypeInformation
    Write-Host "Results saved to nsg-audit-$date.csv" -ForegroundColor Yellow
}
