"""
AWS IAM Security Audit
CIS Benchmark Controls: 1.4, 1.10, 1.14

Checks for:
- IAM users without MFA enabled
- Access keys older than 90 days
- Users with no activity in 90+ days

Requirements:
    pip install boto3
    AWS credentials with ReadOnlyAccess or SecurityAudit policy
"""

import boto3
import json
from datetime import datetime, timezone, timedelta


def audit_iam():
    iam = boto3.client('iam')
    findings = []
    threshold = datetime.now(timezone.utc) - timedelta(days=90)

    users = iam.list_users()['Users']

    for user in users:
        username = user['UserName']
        result = {"user": username, "findings": []}

        # CIS 1.10 — check MFA
        mfa = iam.list_mfa_devices(UserName=username)['MFADevices']
        if not mfa:
            result["findings"].append("NO_MFA — CIS 1.10")

        # CIS 1.14 — check access key age
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in keys:
            if key['CreateDate'] < threshold:
                age = (datetime.now(timezone.utc) - key['CreateDate']).days
                result["findings"].append(f"STALE_KEY_{age}d — CIS 1.14")

        # CIS 1.4 — check last activity
        try:
            login = iam.get_login_profile(UserName=username)
            last_used = user.get('PasswordLastUsed')
            if last_used and last_used < threshold:
                days_inactive = (datetime.now(timezone.utc) - last_used).days
                result["findings"].append(f"INACTIVE_{days_inactive}d — CIS 1.4")
        except iam.exceptions.NoSuchEntityException:
            pass  # no console access, skip

        if result["findings"]:
            findings.append(result)

    print(json.dumps(findings, indent=2, default=str))
    return findings


if __name__ == "__main__":
    audit_iam()
