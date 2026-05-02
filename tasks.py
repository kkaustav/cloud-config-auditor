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

# TASK_SEQUENCE defined below

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
    score = round(max(0.01, min(0.99, sum(bd.values()))), 2)
    return score, bd

def grade_medium(findings, severity, recommendations, config_patch):
    combined = " ".join(findings).lower()
    rec_text = " ".join(recommendations).lower()
    sev_text = " ".join(severity).lower()
    issues   = TASKS["medium_s3_policy"]["issues"]
    bd = {}
    bd["public_access_flag"]  = 0.20 if _contains(combined, issues["public_access"]) else 0.0
    bd["versioning_flag"]     = 0.15 if _contains(combined, issues["versioning"]) else 0.0
    bd["encryption_flag"]     = 0.20 if _contains(combined, issues["encryption"]) else 0.0
    # ORIGINAL wider wildcard list — this is key to the higher medium score
    wildcard_expanded = issues["wildcard_princ"] + [
        "principal", "public read", "public write", "open access",
        "unrestricted", "allow *", "overly permissive"
    ]
    bd["wildcard_principal"]  = 0.20 if _contains(combined, wildcard_expanded) else 0.0
    bd["public_write_delete"] = 0.10 if _contains(combined, issues["write_delete_pub"]) else 0.0
    # ORIGINAL wider rec_keywords list
    rec_keywords = ["enable versioning", "enable encryption", "block public", "restrict",
                    "kms", "least privilege", "mfa delete", "object lock"]
    bd["rec_quality"]    = 0.05 if _contains(rec_text, rec_keywords) else 0.0
    bd["severity_bonus"] = 0.05 if "high" in sev_text or "critical" in sev_text else 0.0
    if config_patch:
        patch_str = json.dumps(config_patch).lower()
        bd["patch_bonus"] = 0.05 if any(k in patch_str for k in ["aes256","kms"]) and '"*"' not in patch_str else 0.0
    else:
        bd["patch_bonus"] = 0.0
    score = round(max(0.01, min(0.99, sum(bd.values()))), 2)
    return score, bd

def grade_hard(findings, severity, recommendations, config_patch):
    combined = " ".join(findings).lower()
    rec_text = " ".join(recommendations).lower()
    sev_text = " ".join(severity).lower()
    bd = {}
    bd["wildcard_action"]  = 0.18 if any(k in combined for k in [
        "action: *", "full access", "action:*", "allow all actions",
        "admin", "administrator", 'action "*"', 'action: "*"'
    ]) else 0.0
    bd["wildcard_service"] = 0.14 if any(k in combined for k in [
        "service *", "wildcard service", "trust policy", "assume role",
        "principal *", "sts:assumerole", 'service": "*"', "service is '*'",
        "principal.service", "any service"
    ]) else 0.0
    bd["mfa_disabled"]     = 0.10 if any(k in combined for k in [
        "mfa", "multi-factor", "mfaenabled", "mfa not enabled"
    ]) else 0.0
    bd["weak_password"]    = 0.18 if any(k in combined for k in [
        "password", "minimum length", "complexity", "expir",
        "password policy", "weak password"
    ]) else 0.0
    bd["flow_logs"]        = 0.10 if any(k in combined for k in [
        "flow log", "vpc flow", "flowlog", "flowlogsenabled",
        "vpc logging", "flow logs disabled", "flowlogsenabled is false"
    ]) else 0.0
    bd["cloudtrail"]       = 0.10 if any(k in combined for k in [
        "cloudtrail", "cloud trail", "audit log", "cloudtrailenabled",
        "logging disabled", "cloudtrailenabled is false", "trail"
    ]) else 0.0
    bd["nacl_open"]        = 0.08 if any(k in combined for k in [
        "nacl", "network acl", "allow all", "0.0.0.0/0",
        "open inbound", "unrestricted", "all traffic", "ruleaction"
    ]) else 0.0
    bd["guardduty"]        = 0.04 if any(k in combined for k in [
        "guardduty", "guard duty", "threat detection",
        "guarddutyenabled", "guarddutyenabled is false"
    ]) else 0.0
    bd["severity_used"]    = 0.04 if "high" in sev_text or "critical" in sev_text else 0.0
    bd["aws_native_rec"]   = 0.04 if any(k in rec_text for k in [
        "least privilege", "enable", "cloudwatch", "aws config",
        "restrict", "rotate", "enforce"
    ]) else 0.0
    if config_patch:
        patch_str = json.dumps(config_patch).lower()
        bd["patch_bonus"] = 0.08 if any(k in patch_str for k in [
            "flowlogsenabled", "flow_logs", "action", "mfa"
        ]) else 0.0
    else:
        bd["patch_bonus"] = 0.0
    score = round(max(0.01, min(0.99, sum(bd.values()))), 2)
    return score, bd

# ── NEW TASK 1 ────────────────────────────────────────────────────────────────
TASKS["medium_lambda_iam"] = {
    "name": "medium_lambda_iam",
    "difficulty": "medium",
    "max_steps": 5,
    "description": (
        "Audit this AWS Lambda function configuration for a payment processing "
        "service in ap-south-1. Identify ALL security misconfigurations in the "
        "execution role, environment variables, and function access controls."
    ),
    "config": json.dumps({
        "AccountId": "123456789012",
        "Region": "ap-south-1",
        "LambdaFunction": {
            "FunctionName": "payment-processor-prod",
            "Runtime": "python3.9",
            "ExecutionRole": {
                "RoleName": "lambda-payment-role",
                "AttachedPolicies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
                "InlinePolicies": []
            },
            "EnvironmentVariables": {
                "DB_PASSWORD": "prod_password_123",
                "API_SECRET_KEY": "sk_live_abcdef123456",
                "STRIPE_SECRET": "sk_live_xyz789"
            },
            "FunctionUrl": {"AuthType": "NONE", "Cors": {"AllowOrigins": ["*"]}},
            "VpcConfig": None,
            "ReservedConcurrency": None,
            "Tracing": {"Mode": "PassThrough"},
            "CodeSigningConfigArn": None
        }
    }, indent=2),
    "issues": {
        "admin_role":        ["administratoraccess", "admin", "action: *", "action:*", "overly permissive", "full access", "wildcard"],
        "plaintext_secrets": ["plaintext", "environment variable", "secret", "password", "credential", "hardcoded", "env var", "db_password", "api_secret"],
        "public_url":        ["function url", "authtype", "auth type", "none", "publicly accessible", "unauthenticated", "no authentication"],
        "no_vpc":            ["vpc", "network isolation", "private subnet", "no vpc", "vpcconfig"],
        "remediation":       ["secrets manager", "parameter store", "least privilege", "iam", "restrict", "rotate", "aws_iam_auth"]
    }
}

# ── NEW TASK 2 ────────────────────────────────────────────────────────────────
TASKS["hard_rds_cloudtrail"] = {
    "name": "hard_rds_cloudtrail",
    "difficulty": "hard",
    "max_steps": 8,
    "description": (
        "Perform a comprehensive security review of this RDS MySQL production "
        "database and associated CloudTrail and AWS Config setup in ap-south-1. "
        "Identify ALL misconfigurations across network exposure, encryption, "
        "backups, high availability, and audit logging."
    ),
    "config": json.dumps({
        "AccountId": "123456789012",
        "Region": "ap-south-1",
        "RDSInstance": {
            "DBInstanceIdentifier": "prod-mysql-db",
            "DBInstanceClass": "db.t3.medium",
            "Engine": "mysql",
            "EngineVersion": "5.7.44",
            "PubliclyAccessible": True,
            "StorageEncrypted": False,
            "BackupRetentionPeriod": 0,
            "MultiAZ": False,
            "DeletionProtection": False,
            "AutoMinorVersionUpgrade": False,
            "IAMDatabaseAuthenticationEnabled": False,
            "VpcSecurityGroups": [{"GroupId": "sg-0abc123def", "InboundRules": [
                {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
                 "CidrIpv4": "0.0.0.0/0", "Description": "MySQL public"}
            ]}],
            "PerformanceInsightsEnabled": False,
            "EnhancedMonitoringEnabled": False
        },
        "CloudTrail": {
            "Enabled": False,
            "MultiRegionTrailEnabled": False,
            "LogFileValidationEnabled": False,
            "S3BucketLogging": None
        },
        "AWSConfig": {"Enabled": False, "ConfigRules": []}
    }, indent=2)
}

TASK_SEQUENCE = ["easy_security_group", "medium_s3_policy", "hard_iam_vpc",
                 "medium_lambda_iam", "hard_rds_cloudtrail"]


def grade_medium_lambda(findings, severity, recommendations, config_patch):
    combined = " ".join(findings).lower()
    rec_text = " ".join(recommendations).lower()
    sev_text = " ".join(severity).lower()
    issues   = TASKS["medium_lambda_iam"]["issues"]
    bd = {}
    bd["admin_role_flag"]    = 0.25 if _contains(combined, issues["admin_role"]) else 0.0
    bd["plaintext_secrets"]  = 0.25 if _contains(combined, issues["plaintext_secrets"]) else 0.0
    bd["public_url_flag"]    = 0.20 if _contains(combined, issues["public_url"]) else 0.0
    bd["no_vpc_flag"]        = 0.15 if _contains(combined, issues["no_vpc"]) else 0.0
    bd["rec_quality"]        = 0.10 if _contains(rec_text, issues["remediation"]) else 0.0
    bd["severity_bonus"]     = 0.05 if "high" in sev_text or "critical" in sev_text else 0.0
    score = round(max(0.01, min(0.99, sum(bd.values()))), 2)
    return score, bd


def grade_hard_rds(findings, severity, recommendations, config_patch):
    combined = " ".join(findings).lower()
    rec_text = " ".join(recommendations).lower()
    sev_text = " ".join(severity).lower()
    bd = {}
    bd["public_rds"]        = 0.15 if any(k in combined for k in ["publicly accessible","publiclyaccessible","internet","public"]) else 0.0
    bd["no_encryption"]     = 0.15 if any(k in combined for k in ["encrypt","kms","storageencrypted","unencrypt","at rest"]) else 0.0
    bd["no_backup"]         = 0.10 if any(k in combined for k in ["backup","retention","backupretention","recovery"]) else 0.0
    bd["no_multiaz"]        = 0.08 if any(k in combined for k in ["multi-az","multiaz","availability","failover","high availability"]) else 0.0
    bd["no_deletion_prot"]  = 0.08 if any(k in combined for k in ["deletion protection","deletionprotection","accidental deletion"]) else 0.0
    bd["mysql_open"]        = 0.10 if any(k in combined for k in ["3306","mysql port","security group","0.0.0.0/0"]) else 0.0
    bd["cloudtrail_off"]    = 0.12 if any(k in combined for k in ["cloudtrail","cloud trail","audit","logging disabled"]) else 0.0
    bd["config_off"]        = 0.08 if any(k in combined for k in ["aws config","config rules","compliance"]) else 0.0
    bd["no_iam_auth"]       = 0.05 if any(k in combined for k in ["iam authentication","iam database","iamdatabaseauthentication"]) else 0.0
    bd["severity_used"]     = 0.04 if "high" in sev_text or "critical" in sev_text else 0.0
    bd["aws_native_rec"]    = 0.05 if any(k in rec_text for k in ["enable","encrypt","cloudtrail","restrict","kms","multi-az","backup"]) else 0.0
    score = round(max(0.01, min(0.99, sum(bd.values()))), 2)
    return score, bd
