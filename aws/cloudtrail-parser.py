"""
AWS CloudTrail Security Parser
CIS Benchmark Controls: 3.1, 3.3

Checks for:
- Root account usage (CIS 3.3)
- Failed API calls — possible recon or brute force
- Console logins without MFA

Requirements:
    pip install boto3
    AWS credentials with ReadOnlyAccess or SecurityAudit policy
"""

import boto3
import json
from datetime import datetime, timezone, timedelta


def parse_cloudtrail(hours=24):
    client = boto3.client('cloudtrail')
    findings = []
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)

    paginator = client.get_paginator('lookup_events')
    pages = paginator.paginate(
        StartTime=start_time,
        EndTime=datetime.now(timezone.utc)
    )

    for page in pages:
        for event in page['Events']:
            detail = json.loads(event.get('CloudTrailEvent', '{}'))
            user = detail.get('userIdentity', {})
            error = detail.get('errorCode', '')

            # CIS 3.3 — root account usage
            if user.get('type') == 'Root':
                findings.append({
                    'type': 'ROOT_USAGE',
                    'time': str(event.get('EventTime')),
                    'event': event.get('EventName'),
                    'source_ip': detail.get('sourceIPAddress'),
                    'risk': 'CRITICAL',
                    'cis': '3.3'
                })

            # Failed API calls — recon pattern
            if error in ('AccessDenied', 'UnauthorizedAccess', 'InvalidClientTokenId'):
                findings.append({
                    'type': 'FAILED_API_CALL',
                    'time': str(event.get('EventTime')),
                    'event': event.get('EventName'),
                    'error': error,
                    'user': user.get('arn', 'unknown'),
                    'source_ip': detail.get('sourceIPAddress'),
                    'risk': 'MEDIUM',
                    'cis': '3.1'
                })

            # Console login without MFA
            if event.get('EventName') == 'ConsoleLogin':
                mfa = detail.get('additionalEventData', {}).get('MFAUsed', 'No')
                if mfa == 'No':
                    findings.append({
                        'type': 'CONSOLE_LOGIN_NO_MFA',
                        'time': str(event.get('EventTime')),
                        'user': user.get('arn', 'unknown'),
                        'source_ip': detail.get('sourceIPAddress'),
                        'risk': 'HIGH',
                        'cis': '3.1'
                    })

    print(json.dumps(findings, indent=2, default=str))
    return findings


if __name__ == '__main__':
    parse_cloudtrail(hours=24)
