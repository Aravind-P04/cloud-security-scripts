# Cloud Security Automation Scripts

Python and PowerShell scripts for auditing AWS and Azure environments.
Built to surface misconfigurations fast — IAM hygiene, open security groups,
stale accounts, and NSG exposure. Based on CIS Benchmark controls.

Not a full security platform — just practical scripts I use and reuse.

## Scripts

### AWS
| Script | What it checks | CIS Control |
|---|---|---|
| iam-audit.py | Users without MFA, access keys older than 90 days | CIS 1.4, 1.14 |
| sg-checker.py | Security groups with 0.0.0.0/0 inbound rules | CIS 5.2, 5.3 |
| cloudtrail-parser.py | Root account usage, failed API calls | CIS 3.1, 3.3 |

### Azure
| Script | What it checks | CIS Control |
|---|---|---|
| nsg-audit.ps1 | NSGs allowing unrestricted inbound traffic | CIS 6.1, 6.2 |
| entra-stale-users.ps1 | Accounts inactive for 90+ days | CIS 1.23 |

## Setup
```bash
pip install boto3 pandas
aws configure  # needs ReadOnlyAccess or SecurityAudit IAM policy
```

## Sample output
See /samples/ for example JSON and CSV outputs with sanitized test data.
