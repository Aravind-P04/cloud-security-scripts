"""
AWS Security Group Auditor
CIS Benchmark Controls: 5.2, 5.3

Checks for security groups with unrestricted inbound access:
- 0.0.0.0/0 (all IPv4)
- ::/0 (all IPv6)

Flags high-risk ports specifically: 22 (SSH), 3389 (RDP),
3306 (MySQL), 5432 (Postgres), 27017 (MongoDB)

Requirements:
    pip install boto3
    AWS credentials with ReadOnlyAccess or SecurityAudit policy
"""

import boto3
import json

HIGH_RISK_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch"
}

OPEN_CIDRS = ["0.0.0.0/0", "::/0"]


def check_security_groups(region="us-east-1"):
    ec2 = boto3.client('ec2', region_name=region)
    findings = []

    sgs = ec2.describe_security_groups()['SecurityGroups']

    for sg in sgs:
        sg_findings = []

        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 65535)

            open_ranges = (
                [r['CidrIp'] for r in rule.get('IpRanges', [])
                 if r['CidrIp'] in OPEN_CIDRS] +
                [r['CidrIpv6'] for r in rule.get('Ipv6Ranges', [])
                 if r['CidrIpv6'] in OPEN_CIDRS]
            )

            if not open_ranges:
                continue

            # check if any high risk port falls in the range
            for port, service in HIGH_RISK_PORTS.items():
                if from_port <= port <= to_port:
                    sg_findings.append({
                        "port": port,
                        "service": service,
                        "cidr": open_ranges,
                        "risk": "CRITICAL",
                        "cis": "5.2" if port == 22 else "5.3"
                    })

            # catch all-traffic rules
            if rule.get('IpProtocol') == '-1':
                sg_findings.append({
                    "port": "ALL",
                    "service": "All traffic",
                    "cidr": open_ranges,
                    "risk": "CRITICAL",
                    "cis": "5.2, 5.3"
                })

        if sg_findings:
            findings.append({
                "sg_id": sg['GroupId'],
                "sg_name": sg['GroupName'],
                "vpc_id": sg.get('VpcId', 'N/A'),
                "findings": sg_findings
            })

    print(json.dumps(findings, indent=2))
    return findings


if __name__ == "__main__":
    check_security_groups()
