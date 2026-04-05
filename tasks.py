import json
from typing import Dict, List, Tuple

TASKS = {
    "easy_security_group": {
        "name": "easy_security_group",
        "difficulty": "easy",
        "max_steps": 3,
        "description": (
            "You are reviewing an AWS Security Group for a production web server "
            "in ap-south-1. Identify ALL inbound rules that expose the instance "
            "to the internet insecurely, state their severity, and recommend "
            "specific remediations. Pay attention to management ports."
        ),
        "config": json.dumps({
            "StackName": "ProdWebTier-v3",
            "SecurityGroup": {
                "GroupId": "sg-0fa312cc9a8b1e720",
                "GroupName": "prod-web-tier-sg",
                "Region": "ap-south-1",
                "Description": "Auto-created by Terraform for web layer",
                "InboundRules": [
                    {"IpProtocol": "tcp", "FromPort": 80,   "ToPort": 80,   "CidrIpv4": "0.0.0.0/0", "Description": "HTTP public"},
                    {"IpProtocol": "tcp", "FromPort": 443,  "ToPort": 443,  "CidrIpv4": "0.0.0.0/0", "Description": "HTTPS public"},
                    {"IpProtocol": "tcp", "FromPort": 22,   "ToPort": 22,   "CidrIpv4": "0.0.0.0/0", "Description": "SSH TODO restrict"},
                    {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "CidrIpv6": "::/0",       "Description": "RDP legacy"},
                    {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "CidrIpv4": "10.0.0.0/8","Description": "Postgres internal"}
                ],
                "OutboundRules": [{"IpProtocol": "-1", "CidrIpv4": "0.0.0.0/0"}]
            }
        }, indent=2),
        "issues": {
            "ssh_open":    ["port 22", "ssh", ":22"],
            "rdp_open":    ["port 3389", "rdp", ":3389", "3389"],
            "internet":    ["0.0.0.0/0", "internet", "anywhere", "public", "::/0"],
            "remediation": ["restrict", "vpn", "bastion", "specific ip", "cidr", "whitelist", "/32"]
        }
    },
    "medium_s3_policy": {
        "name": "medium_s3_policy",
        "difficulty": "medium",
        "max_steps": 5,
        "description": (
            "Audit this S3 bucket configuration used in a production data pipeline "
            "in ap-south-1. Identify ALL misconfigurations across access controls, "
            "encryption, versioning, and bucket policy."
        ),
        "config": json.dumps({
            "AccountId": "123456789012",
            "Region": "ap-south-1",
            "S3Bucket": {
                "BucketName": "techstack-prod-customer-data-2024",
                "PublicAccessBlock": {
                    "BlockPublicAcls": False, "BlockPublicPolicy": False,
                    "IgnorePublicAcls": False, "RestrictPublicBuckets": False
                },
                "Versioning": {"Status": "Suspended"},
                "ServerSideEncryption": None,
                "ObjectLockEnabled": False,
                "MFADelete": "Disabled",
                "BucketPolicy": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "LegacyPublicRead", "Effect": "Allow", "Principal": "*",
                        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                        "Resource": "arn:aws:s3:::techstack-prod-customer-data-2024/*"
                    }]
                }
            }
        }, indent=2),
        "issues": {
            "public_access":    ["public access", "block public", "blockpublic", "publicly accessible"],
            "versioning":       ["versioning", "version", "suspended"],
            "encryption":       ["encrypt", "kms", "aes", "sse", "server-side", "server side"],
            "wildcard_princ":   ['"principal": "*"', "principal *", "anonymous", "all users", '"*"', "wildcard principal"],
            "write_delete_pub": ["putobject", "deleteobject", "s3:put", "s3:delete", "write", "delete"]
        }
    },
    "hard_iam_vpc": {
        "name": "hard_iam_vpc",
        "difficulty": "hard",
        "max_steps": 8,
        "description": (
            "Perform a comprehensive security review of this ECS production environment "
            "in ap-south-1. Includes IAM Role, inline policy, password policy, and VPC."
        ),
        "config": json.dumps({
            "AccountId": "123456789012",
            "Environment": "production",
            "Region": "ap-south-1",
            "IAMRole": {
                "RoleName": "ECSTaskExecutionRole-prod",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Principal": {"Service": "*"}, "Action": "sts:AssumeRole"}]
                },
                "InlinePolicies": [{"PolicyName": "AllAccess-temp", "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                }}],
                "MFAEnabled": False,
                "PasswordPolicy": {
                    "MinimumPasswordLength": 6, "RequireUppercaseCharacters": False,
                    "RequireNumbers": False, "RequireSymbols": False,
                    "MaxPasswordAge": 0, "PasswordReusePrevention": 0
                }
            },
            "VPC": {
                "VpcId": "vpc-0d1f3c7a8e4b2f910",
                "FlowLogsEnabled": False,
                "CloudTrailEnabled": False,
                "GuardDutyEnabled": False,
                "NetworkACL": {"Rules": [
                    {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0", "Egress": False},
                    {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0", "Egress": True}
                ]},
                "Subnets": [{"SubnetId": "subnet-0abc123", "MapPublicIpOnLaunch": True}]
            }
        }, indent=2)
    }
}

TASK_SEQUENCE = ["easy_security_group", "medium_s3_policy", "hard_iam_vpc"]

def _contains(text, keywords):
    t = text.lower()
    return any(k.lower() in t for k in keywords)

def grade_easy(findings, severity, recommendations, config_patch):
    combined = " ".join(findings).lower()
    rec_text = " ".join(recommendations).lower()
    issues   = TASKS["easy_security_group"]["issues"]
    bd = {}
    bd["ssh_identified"]      = 0.30 if _contains(combined, issues["ssh_open"]) else 0.0
    bd["rdp_identified"]      = 0.25 if _contains(combined, issues["rdp_open"]) else 0.0
    bd["internet_flagged"]    = 0.25 if _contains(combined, issues["internet"]) else 0.0
    bd["remediation_quality"] = 0.15 if _contains(rec_text, issues["remediation"]) else 0.0
    bd["severity_accuracy"]   = 0.05 if "high" in " ".join(severity).lower() else 0.0
    if config_patch:
        patch_str = json.dumps(config_patch).lower()
        bd["patch_bonus"] = 0.10 if "22" not in patch_str and "3389" not in patch_str else 0.0
    else:
        bd["patch_bonus"] = 0.0
    return round(min(sum(bd.values()), 1.0), 2), bd

def grade_medium(findings, severity, recommendations, config_patch):
    combined = " ".join(findings).lower()
    rec_text = " ".join(recommendations).lower()
    sev_text = " ".join(severity).lower()
    issues   = TASKS["medium_s3_policy"]["issues"]
    bd = {}
    bd["public_access_flag"]  = 0.20 if _contains(combined, issues["public_access"]) else 0.0
    bd["versioning_flag"]     = 0.15 if _contains(combined, issues["versioning"]) else 0.0
    bd["encryption_flag"]     = 0.20 if _contains(combined, issues["encryption"]) else 0.0
    wildcard_expanded = issues["wildcard_princ"] + ["principal", "public read", "public write", "open access", "unrestricted", "allow *", "overly permissive"]
    bd["wildcard_principal"]  = 0.20 if _contains(combined, wildcard_expanded) else 0.0
    bd["public_write_delete"] = 0.10 if _contains(combined, issues["write_delete_pub"]) else 0.0
    rec_keywords = ["enable versioning", "enable encryption", "block public", "restrict", "kms", "least privilege", "mfa delete", "object lock"]
    bd["rec_quality"]   = 0.05 if _contains(rec_text, rec_keywords) else 0.0
    bd["severity_bonus"] = 0.05 if "high" in sev_text or "critical" in sev_text else 0.0
    if config_patch:
        patch_str = json.dumps(config_patch).lower()
        bd["patch_bonus"] = 0.05 if any(k in patch_str for k in ["aes256","kms"]) and '"*"' not in patch_str else 0.0
    else:
        bd["patch_bonus"] = 0.0
    return round(min(sum(bd.values()), 1.0), 2), bd

def grade_hard(findings, severity, recommendations, config_patch):
    combined = " ".join(findings).lower()
    rec_text = " ".join(recommendations).lower()
    sev_text = " ".join(severity).lower()
    bd = {}
    bd["wildcard_action"]  = 0.12 if any(k in combined for k in ["action: *","full access","action:*"]) else 0.0
    bd["wildcard_service"] = 0.10 if any(k in combined for k in ["service *","wildcard service","trust policy","assume role"]) else 0.0
    bd["mfa_disabled"]     = 0.08 if any(k in combined for k in ["mfa","multi-factor"]) else 0.0
    bd["weak_password"]    = 0.15 if any(k in combined for k in ["password","minimum length","complexity","expir"]) else 0.0
    bd["flow_logs"]        = 0.12 if any(k in combined for k in ["flow log","vpc flow","flowlog"]) else 0.0
    bd["cloudtrail"]       = 0.12 if any(k in combined for k in ["cloudtrail","cloud trail","audit log"]) else 0.0
    bd["nacl_open"]        = 0.10 if any(k in combined for k in ["nacl","network acl","allow all"]) else 0.0
    bd["guardduty"]        = 0.06 if "guardduty" in combined else 0.0
    bd["severity_used"]    = 0.08 if "high" in sev_text else 0.0
    bd["aws_native_rec"]   = 0.07 if any(k in rec_text for k in ["least privilege","enable","cloudwatch","aws config"]) else 0.0
    if config_patch:
        patch_str = json.dumps(config_patch).lower()
        bd["patch_bonus"] = 0.08 if '"flowlogsenabled": true' in patch_str and '"action": "*"' not in patch_str else 0.0
    else:
        bd["patch_bonus"] = 0.0
    return round(min(sum(bd.values()), 1.0), 2), bd
