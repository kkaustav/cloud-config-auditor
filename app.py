#!/usr/bin/env python3
"""
AWS Security Auditor — OpenEnv HTTP/1.x compatible environment server
Serves on localhost:7860 | Endpoints: /health /reset /step /state /schema /metadata /mcp
"""

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
import uvicorn, json, re, textwrap

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
                    {"IpProtocol": "tcp", "FromPort": 22,   "ToPort": 22,   "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": ""}]},
                    {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": ""}]},
                    {"IpProtocol": "tcp", "FromPort": 80,   "ToPort": 80,   "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"IpProtocol": "tcp", "FromPort": 443,  "ToPort": 443,  "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"IpProtocol": "-1",  "FromPort": -1,   "ToPort": -1,   "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                ],
                "IpPermissionsEgress": [
                    {"IpProtocol": "-1", "FromPort": -1, "ToPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
                "Tags": []
            }
        }, indent=2),
        "expected_findings": [
            ["port 22", "ssh", "22/tcp", "ssh port"],
            ["port 3389", "rdp", "3389", "rdp port", "remote desktop"],
            ["all traffic", "all protocol", "protocol -1", "all ports", "unrestricted inbound", "-1 inbound"],
            ["unrestricted egress", "all egress", "egress unrestricted", "outbound unrestricted", "0.0.0.0/0 egress"],
            ["no tag", "missing tag", "untagged", "no description", "empty description"],
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
            ["public-read", "public acl", "acl public", "bucket acl"],
            ["blockpublicacls", "block public", "public access block", "publicaccessblock disabled"],
            ["encryption", "sse", "server-side encryption", "no encryption", "encryption disabled"],
            ["versioning suspended", "versioning disabled", "no versioning", "versioning not enabled"],
            ["logging", "access logging", "no logging", "server access log"],
            ["principal *", "principal: *", "public write", "s3:putobject", "s3:deleteobject", "unauthenticated write"],
            ["mfa delete", "mfa-delete", "mfa disabled", "no mfa"],
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
            ["action *", "wildcard action", "action: *", "all actions", "full admin", "administrator"],
            ["resource *", "wildcard resource", "resource: *", "all resources"],
            ["iam:passrole", "passrole", "privilege escalation", "iam passrole"],
            ["iam:createaccesskey", "createaccesskey", "access key creation"],
            ["no mfa", "mfa condition", "missing mfa", "no condition", "no mfa enforcement"],
            ["flow log", "vpc flow", "no flow log", "flow logs disabled"],
            ["default security group", "default sg", "sg-default"],
            ["mappropubliciponlaunch", "auto-assign public ip", "public ip on launch", "public subnet"],
            ["cloudtrail", "no cloudtrail", "cloudtrail disabled", "audit logging"],
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
                ]
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
            ["publicly accessible", "public", "rds public", "publicly accessible: true"],
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

state = {"task": None, "step": 0, "last_reward": 0.0, "last_feedback": None, "done": False}

def score_response(task_name, findings, severity, recommendations, config_patch):
    if task_name not in TASKS:
        return 0.0
    expected = TASKS[task_name]["expected_findings"]
    agent_text = " ".join(f.lower() for f in findings + recommendations)
    matched = sum(1 for kw_group in expected if any(kw.lower() in agent_text for kw in kw_group))
    raw_score = matched / len(expected)
    if sum(1 for s in severity if s.upper() == "HIGH") >= 2 and raw_score > 0.5:
        raw_score = min(1.0, raw_score + 0.05)
    if config_patch and len(config_patch) > 0:
        raw_score = min(1.0, raw_score + 0.03)
    return round(raw_score, 3)

def build_feedback(task_name, findings, reward):
    expected = TASKS[task_name]["expected_findings"]
    agent_text = " ".join(f.lower() for f in findings)
    missed = [g[0] for g in expected if not any(kw.lower() in agent_text for kw in g)]
    if not missed:
        return "All key findings identified. Excellent audit."
    return f"Missed findings related to: {', '.join(missed[:4])}. Re-examine the full configuration carefully."

@app.get("/health")
def health():
    return {"status": "ok", "environment": "aws-security-auditor", "version": "1.0.0"}

@app.post("/reset")
async def reset(task: str = Query(...)):
    if task not in TASKS:
        return JSONResponse(status_code=400, content={"error": f"Unknown task '{task}'. Valid: {list(TASKS.keys())}"})
    state.update({"task": task, "step": 0, "last_reward": 0.0, "last_feedback": None, "done": False})
    return {"observation": {"task_description": TASKS[task]["description"], "config": TASKS[task]["config"], "feedback": None, "last_reward": 0.0, "step": 0}}

@app.post("/step")
async def step(request: Request):
    body = await request.json()
    task_name = state.get("task")
    if not task_name:
        return JSONResponse(status_code=400, content={"error": "Call /reset first."})
    state["step"] += 1
    reward = score_response(task_name, body.get("findings", []), body.get("severity", []), body.get("recommendations", []), body.get("config_patch", {}))
    feedback = build_feedback(task_name, body.get("findings", []), reward)
    state.update({"last_reward": reward, "last_feedback": feedback, "done": reward >= 0.9 or state["step"] >= 5})
    return {"reward": reward, "done": state["done"], "observation": {"task_description": TASKS[task_name]["description"], "config": TASKS[task_name]["config"], "feedback": feedback, "last_reward": reward, "step": state["step"]}}

@app.get("/state")
def get_state():
    return state

@app.get("/schema")
def schema():
    return {"reset": {"input": {"task": "string"}}, "step": {"input": {"findings": "list[str]", "severity": "list[str]", "recommendations": "list[str]", "config_patch": "object"}}}

@app.get("/metadata")
def metadata():
    return {"name": "aws-security-auditor", "version": "1.0.0", "tasks": list(TASKS.keys()), "profile": "openenv-http/1.x"}

@app.get("/mcp")
def mcp():
    return {"protocol": "openenv-http/1.x", "endpoints": ["/reset", "/step", "/state", "/health", "/schema", "/metadata"]}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=7860)
