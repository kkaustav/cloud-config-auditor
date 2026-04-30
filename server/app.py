#!/usr/bin/env python3

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
import uvicorn
import json

app = FastAPI(title="AWS Security Auditor OpenEnv", version="1.0.0")

TASKS = {
    "easy_security_group": {
        "description": (
            "You are auditing an EC2 Security Group attached to a public-facing web server. "
            "Identify ALL security misconfigurations in the inbound and outbound rules."
        ),
        "config": json.dumps({
            "SecurityGroup": {
                "GroupId": "sg-0abc123def456789",
                "GroupName": "web-server-sg",
                "VpcId": "vpc-0123456789abcdef0",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": ""}]},
                    {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": ""}]},
                    {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"IpProtocol": "-1", "FromPort": -1, "ToPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                ],
                "IpPermissionsEgress": [
                    {"IpProtocol": "-1", "FromPort": -1, "ToPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
                "Tags": []
            }
        }, indent=2),
        "expected_findings": [
            ["port 22", "ssh", "22/tcp", "ssh access", "ssh open"],
            ["port 3389", "rdp", "3389", "remote desktop"],
            ["all traffic", "all protocol", "protocol -1", "all ports", "unrestricted inbound", "all inbound"],
            ["unrestricted egress", "unrestricted outbound", "outbound unrestricted", "all outbound", "egress allows all", "0.0.0.0/0 egress", "outbound allow all"],
            ["no tag", "missing tag", "untagged", "empty tag", "tags are empty", "no tags", "tag not configured"],
        ]
    },

    "medium_s3_policy": {
        "description": (
            "Audit this S3 bucket configuration including its bucket policy, ACL settings, "
            "and security controls. Find all misconfigurations."
        ),
        "config": json.dumps({
            "BucketName": "prod-data-backup-20240315",
            "BucketACL": "public-read",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            },
            "VersioningConfiguration": {"Status": "Suspended"},
            "ServerSideEncryptionConfiguration": {"Rules": []},
            "LoggingConfiguration": {},
            "BucketPolicy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "PublicRead",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                    "Resource": "arn:aws:s3:::prod-data-backup-20240315/*"
                }]
            },
            "MFADelete": "Disabled",
            "LifecycleConfiguration": {}
        }, indent=2),
        "expected_findings": [
            ["public-read", "public acl", "acl is public", "bucket acl", "publicly readable"],
            ["blockpublicacls", "block public acl", "public access block", "public access is not blocked", "block public access"],
            ["encryption", "sse", "server-side encryption", "no encryption", "not encrypted", "encryption not enabled"],
            ["versioning suspended", "versioning is disabled", "no versioning", "versioning not enabled", "versioning is not"],
            ["access logging", "logging is not", "no logging", "server access log", "logging not enabled", "logging disabled"],
            ["principal", "s3:putobject", "s3:deleteobject", "allows public write", "unauthenticated", "public write access"],
            ["mfa delete", "mfa-delete", "mfa is disabled", "no mfa", "mfa not enabled"],
        ]
    },

    "hard_iam_vpc": {
        "description": (
            "Audit this combined IAM policy and VPC configuration. "
            "Identify all privilege escalation risks, IAM misconfigurations, and network security issues."
        ),
        "config": json.dumps({
            "IAMPolicy": {
                "PolicyName": "DevOpsFullAccess",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {}},
                        {"Effect": "Allow", "Action": ["iam:PassRole", "iam:CreateAccessKey", "iam:AttachUserPolicy"], "Resource": "*"}
                    ]
                }
            },
            "VPC": {
                "VpcId": "vpc-0deadbeef12345678",
                "CidrBlock": "10.0.0.0/16",
                "FlowLogs": [],
                "DefaultSecurityGroup": {
                    "GroupId": "sg-default",
                    "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                    "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
                },
                "Subnets": [
                    {"SubnetId": "subnet-public-1", "MapPublicIpOnLaunch": True, "CidrBlock": "10.0.1.0/24"}
                ]
            },
            "CloudTrail": {"Enabled": False}
        }, indent=2),
        "expected_findings": [
            ["action *", "wildcard", "all actions", "full admin", "administrator", "action: \"*\"", "allows all actions"],
            ["resource *", "all resources", "resource: \"*\"", "any resource"],
            ["passrole", "iam:passrole", "privilege escalation", "pass role"],
            ["createaccesskey", "iam:createaccesskey", "create access key", "access key creation"],
            ["no mfa", "mfa not enforced", "missing mfa", "mfa condition", "without mfa", "mfa is not required"],
            ["flow log", "vpc flow", "no flow log", "flow logs not", "flow logs are not", "flow logs disabled"],
            ["default security group", "default sg", "default security group allows"],
            ["public ip", "auto-assign", "map public", "automatically assign", "public subnet", "assigns public"],
            ["cloudtrail", "no cloudtrail", "cloudtrail is not", "cloudtrail disabled", "cloudtrail not enabled"],
        ]
    },

    "medium_lambda_iam": {
        "description": (
            "Audit this AWS Lambda function configuration and its attached IAM execution role. "
            "Identify all security misconfigurations including over-privileged roles and secrets management issues."
        ),
        "config": json.dumps({
            "LambdaFunction": {
                "FunctionName": "process-payment-handler",
                "Runtime": "python3.9",
                "Timeout": 900,
                "MemorySize": 128,
                "VpcConfig": {},
                "Environment": {
                    "Variables": {
                        "DB_PASSWORD": "SuperSecret123!",
                        "API_KEY": "sk-live-abcdef1234567890",
                        "STRIPE_SECRET": "sk_live_abcdef",
                        "ENV": "production"
                    }
                },
                "DeadLetterConfig": {},
                "ReservedConcurrentExecutions": None,
                "TracingConfig": {"Mode": "PassThrough"},
                "ResourcePolicy": None
            },
            "ExecutionRole": {
                "RoleName": "lambda-execution-role",
                "AttachedPolicies": [
                    {"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
                ],
                "InlinePolicies": []
            }
        }, indent=2),
        "expected_findings": [
            ["administratoraccess", "administrator access", "admin policy", "overprivileged", "full admin"],
            ["db_password", "plaintext", "hardcoded", "plaintext secret", "environment variable secret", "secrets manager", "ssm parameter"],
            ["api_key", "api key", "plaintext api", "hardcoded api"],
            ["stripe_secret", "stripe", "payment secret", "hardcoded payment"],
            ["no vpc", "vpc config empty", "not in vpc", "lambda vpc", "no network isolation"],
            ["dead letter", "dlq", "no dlq", "dead letter queue"],
            ["timeout 900", "max timeout", "timeout too high", "900 second"],
            ["tracing", "x-ray", "passthrough", "no tracing", "tracing disabled"],
        ]
    },

    "hard_rds_cloudtrail": {
        "description": (
            "Audit this RDS database instance and CloudTrail configuration. "
            "Identify all data security, compliance, and audit logging gaps."
        ),
        "config": json.dumps({
            "RDSInstance": {
                "DBInstanceIdentifier": "prod-mysql-primary",
                "Engine": "mysql",
                "EngineVersion": "5.7.38",
                "PubliclyAccessible": True,
                "StorageEncrypted": False,
                "BackupRetentionPeriod": 0,
                "MultiAZ": False,
                "DeletionProtection": False,
                "AutoMinorVersionUpgrade": False,
                "IAMDatabaseAuthenticationEnabled": False,
                "EnabledCloudwatchLogsExports": [],
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-rds-open", "Status": "active"}],
                "StorageType": "gp2",
                "EnhancedMonitoringEnabled": False
            },
            "CloudTrail": {
                "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789:trail/main-trail",
                "IsMultiRegionTrail": False,
                "IncludeGlobalServiceEvents": False,
                "LogFileValidationEnabled": False,
                "S3BucketName": "cloudtrail-logs-public",
                "S3BucketACL": "public-read-write",
                "CloudWatchLogsLogGroupArn": None,
                "KMSKeyId": None,
                "IsOrganizationTrail": False
            }
        }, indent=2),
        "expected_findings": [
            ["publicly accessible", "rds public", "public database", "public exposure"],
            ["storage encrypted", "not encrypted", "encryption disabled", "storageencrypted false"],
            ["backup", "backupretentionperiod 0", "no backup", "retention period 0"],
            ["multiaz", "multi-az", "no multi-az", "single az", "no high availability"],
            ["deletion protection", "deletionprotection false", "no deletion protection"],
            ["auto minor version", "autominorversionupgrade", "version upgrade", "patch"],
            ["iam database auth", "iam authentication", "password authentication only"],
            ["cloudwatch log", "no log export", "logs not enabled", "audit log"],
            ["multi-region trail", "ismultiregiontrail false", "single region", "not multi-region"],
            ["log file validation", "logfilevalidation", "validation disabled"],
            ["s3 bucket public", "cloudtrail bucket public", "public-read-write", "bucket acl"],
            ["cloudwatch logs", "cloudwatchlogsloggrouparn", "no cloudwatch integration"],
            ["kms", "no kms", "kms encryption", "trail encryption"],
        ]
    }
}

state = {
    "task": None,
    "step": 0,
    "last_reward": 0.0,
    "last_feedback": None,
    "done": False,
}

def score_response(task_name, findings, severity, recommendations, config_patch):
    if task_name not in TASKS:
        return 0.10

    expected = TASKS[task_name]["expected_findings"]
    agent_text = " ".join(str(x).lower() for x in (findings + recommendations))

    matched = 0
    for keyword_group in expected:
        if any(kw.lower() in agent_text for kw in keyword_group):
            matched += 1

    coverage = matched / len(expected)

    high_count = sum(1 for s in severity if str(s).upper() == "HIGH")
    if high_count >= 2 and coverage > 0.5:
        coverage = min(1.0, coverage + 0.05)

    if isinstance(config_patch, dict) and len(config_patch) > 0:
        coverage = min(1.0, coverage + 0.03)

    if coverage <= 0:
        score = 0.10
    else:
        score = 0.10 + coverage * (0.99 - 0.10)

    return round(min(score, 0.99), 3)

def build_feedback(task_name, findings, recommendations):
    expected = TASKS[task_name]["expected_findings"]
    agent_text = " ".join(str(x).lower() for x in (findings + recommendations))
    missed = []

    for keyword_group in expected:
        if not any(kw.lower() in agent_text for kw in keyword_group):
            missed.append(keyword_group[0])

    if not missed:
        return "All key findings identified. Excellent audit."

    return (
        "Missed findings related to: "
        + ", ".join(missed[:4])
        + ". Re-examine the full configuration carefully and use more explicit AWS wording."
    )

@app.get("/health")
def health():
    return {
        "status": "ok",
        "environment": "aws-security-auditor",
        "version": "1.0.0",
    }

@app.post("/reset")
async def reset(task: str = Query(...)):
    if task not in TASKS:
        return JSONResponse(
            status_code=400,
            content={"error": f"Unknown task: {task}. Valid tasks: {list(TASKS.keys())}"},
        )

    state["task"] = task
    state["step"] = 0
    state["last_reward"] = 0.0
    state["last_feedback"] = None
    state["done"] = False

    return {
        "observation": {
            "task_description": TASKS[task]["description"],
            "config": TASKS[task]["config"],
            "feedback": None,
            "last_reward": 0.0,
            "step": 0,
        }
    }

@app.post("/step")
async def step(request: Request):
    body = await request.json()

    findings = body.get("findings", [])
    severity = body.get("severity", [])
    recommendations = body.get("recommendations", [])
    config_patch = body.get("config_patch", {})

    task_name = state.get("task")
    if not task_name:
        return JSONResponse(status_code=400, content={"error": "Call /reset first."})

    state["step"] += 1
    reward = score_response(task_name, findings, severity, recommendations, config_patch)
    feedback = build_feedback(task_name, findings, recommendations)

    state["last_reward"] = reward
    state["last_feedback"] = feedback
    done = reward >= 0.9 or state["step"] >= 5
    state["done"] = done

    return {
        "reward": reward,
        "done": done,
        "observation": {
            "task_description": TASKS[task_name]["description"],
            "config": TASKS[task_name]["config"],
            "feedback": feedback,
            "last_reward": reward,
            "step": state["step"],
        },
    }

@app.get("/state")
def get_state():
    return state

@app.get("/schema")
def schema():
    return {
        "reset": {
            "input": {"task": "string"},
            "output": {"observation": "object"},
        },
        "step": {
            "input": {
                "findings": "list[str]",
                "severity": "list[str]",
                "recommendations": "list[str]",
                "config_patch": "object",
            },
            "output": {
                "reward": "float",
                "done": "bool",
                "observation": "object",
            },
        },
    }

@app.get("/metadata")
def metadata():
    return {
        "name": "aws-security-auditor",
        "version": "1.0.0",
        "tasks": list(TASKS.keys()),
        "profile": "openenv-http/1.x",
        "success_threshold": 0.55,
        "max_steps": 5,
    }

@app.get("/mcp")
def mcp():
    return {
        "protocol": "openenv-http/1.x",
        "endpoints": ["/reset", "/step", "/state", "/health", "/schema", "/metadata"],
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=7860)