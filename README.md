---
title: Cloud Config Auditor
emoji: 🔐
colorFrom: blue
colorTo: green
sdk: docker
pinned: false
---

# AWS Security Auditor

An OpenEnv-compatible environment for training and evaluating AI agents that audit AWS cloud infrastructure for security misconfigurations.

## What this project does

This project simulates realistic AWS security review tasks and gives an AI agent a reward based on the quality of its findings, severity labels, remediation advice, and optional config patches.

The environment is designed for reinforcement learning and evaluation workflows where an agent must inspect cloud configuration data, identify security issues, and improve over multiple steps.

## Tasks

The environment includes three tasks with increasing difficulty:

- **easy_security_group** — reviews a production web-tier Security Group and checks for risky internet-exposed inbound rules such as SSH and RDP.
- **medium_s3_policy** — audits an S3 bucket for public access, missing encryption, suspended versioning, and overly permissive bucket policies.
- **hard_iam_vpc** — reviews IAM and VPC settings for an ECS production environment, including wildcard IAM permissions, weak password policy, disabled MFA, missing logging, and open network ACLs.

## Reward design

Each task uses a weighted reward breakdown for important security signals.

Examples include:
- SSH or RDP exposure
- Public S3 access
- Wildcard IAM permissions like `Action:*`
- Disabled VPC Flow Logs, CloudTrail, or GuardDuty
- Weak password policy and missing MFA

Scores are intentionally forced to stay strictly between **0 and 1**, which keeps the environment compatible with hackathon validation and OpenEnv evaluation rules.

## Scoring breakdown

| Component | Easy | Medium | Hard |
|---|:---:|:---:|:---:|
| SSH/RDP detection | 0.55 | — | — |
| Internet exposure | 0.25 | — | — |
| Public access | — | 0.20 | — |
| Encryption | — | 0.20 | — |
| Wildcard IAM Action | — | — | 0.18 |
| Weak password / MFA | — | — | 0.28 |
| Logging & GuardDuty | — | — | 0.24 |
| Remediation quality | 0.15 | 0.05 | 0.04 |
| Config patch bonus | 0.10 | 0.05 | 0.08 |

## API endpoints

The environment exposes standard OpenEnv-style HTTP endpoints:

- `/reset`
- `/step`
- `/state`
- `/health`
- `/schema`
- `/metadata`
- `/mcp`

## Project structure

- `environment.py` — FastAPI environment implementation
- `tasks.py` — task definitions and grader logic
- `inference.py` — baseline LLM-driven agent
- `agent.py` — runner entry point
- `openenv.yaml` — OpenEnv endpoint configuration
- `Dockerfile` — container setup for deployment

## Environment variables

| Variable | Default | Required |
|---|---|:---:|
| `HF_TOKEN` | — | ✅ |
| `MODEL_NAME` | `Qwen/Qwen2.5-72B-Instruct` | No |
| `API_BASE_URL` | `https://router.huggingface.co/v1` | No |
| `ENV_BASE_URL` | `http://localhost:7860` | No |

## How to run locally

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the environment:

```bash
uvicorn environment:app --host 0.0.0.0 --port 7860
```

In another terminal, run the agent:

```bash
export HF_TOKEN=YOUR_TOKEN
python3 inference.py
```

## Example behavior

A successful run should show the agent identifying multiple issues and receiving high rewards for each task, with final task scores strictly less than 1.0 and greater than 0.0.

## Why this environment is useful

Cloud misconfiguration is a common real-world security problem. This benchmark focuses on practical audit scenarios across Security Groups, S3, IAM, and VPC controls, making it useful for testing agent reasoning, remediation quality, and reward-driven improvement.

## Space

🚀 [https://huggingface.co/spaces/kkaustav/cloud-config-auditor](https://huggingface.co/spaces/kkaustav/cloud-config-auditor)