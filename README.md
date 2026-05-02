---
Project Title: Cloud Config Auditor
emoji: 🔐
colorFrom: blue
colorTo: green
sdk: docker
app_file: environment.py
pinned: false
---

# AWS Security Auditor
🏆 Built for the Meta PyTorch OpenEnv Hackathon x Scaler School of Technology  
In collaboration with Meta AI, PyTorch, and Hugging Face | April 2026

An OpenEnv-compatible environment for training and evaluating AI agents that audit AWS cloud infrastructure for security misconfigurations.

---

## Benchmark Results

Fine-tuned model: [`kkaustav/aws-security-auditor-lora`](https://huggingface.co/kkaustav/aws-security-auditor-lora)  
Base model: `unsloth/Qwen2.5-3B-Instruct-bnb-4bit`  
Training: SFT on curated AWS security audit traces  
Evaluation: 3 runs per task, averaged

| Task | Difficulty | Avg Score |
|------|-----------|-----------|
| easy_security_group | Easy | 0.9900 |
| medium_s3_policy | Medium | 0.9900 |
| medium_lambda_iam | Medium | 0.9900 |
| hard_rds_cloudtrail | Hard | 0.9200 |
| hard_iam_vpc | Hard | 0.8200 |
| **OVERALL AVERAGE** | | **0.9420** |

All scores within valid OpenEnv range (0.0, 1.0) ✅

---

## What this project does

This project simulates realistic AWS security review tasks and gives an AI agent a reward based on the quality of its findings, severity labels, remediation advice, and optional config patches.

The environment is designed for reinforcement learning and evaluation workflows where an agent must inspect cloud configuration data, identify security issues, and improve over multiple steps.

---

## Why this environment is unique

Unlike generic ML benchmarks, this environment is grounded in real AWS production configurations — Security Groups, S3 bucket policies, IAM roles, Lambda functions, RDS instances, and VPC network ACLs. The tasks reflect actual enterprise-grade misconfiguration patterns encountered in production cloud environments, making agent performance directly applicable to real-world cloud security auditing.

---

## Architecture
Agent (inference.py)
│
▼ HTTP (POST /reset, /step)
FastAPI Environment (environment.py)
│
▼
Task Grader (tasks.py)
│
▼
Reward Score (0.0 – 1.0)
│
▼
Agent receives reward → decides next action


The agent operates in a standard observe → act → reward loop. On each `/step`, the agent submits a structured audit response. The grader evaluates it against a weighted rubric and returns a scalar reward.

---

## Tasks

| Task | Description |
|------|-------------|
| `easy_security_group` | Reviews a production web-tier Security Group for risky internet-exposed inbound rules (SSH, RDP) |
| `medium_s3_policy` | Audits an S3 bucket for public access, missing encryption, suspended versioning, and overly permissive bucket policies |
| `medium_lambda_iam` | Audits a Lambda function for plaintext secrets, wildcard IAM, missing VPC isolation, and unauthenticated function URLs |
| `hard_rds_cloudtrail` | Reviews RDS instance and CloudTrail for public exposure, unencrypted storage, disabled backups, and missing audit logging |
| `hard_iam_vpc` | Reviews IAM roles and VPC settings for wildcard permissions, weak password policy, disabled MFA, missing Flow Logs, and open NACLs |

---

## Reward Design

Each task uses a weighted reward breakdown for important security signals. Examples include:

- SSH or RDP exposure
- Public S3 access
- Wildcard IAM permissions (`Action:*`)
- Disabled VPC Flow Logs, CloudTrail, or GuardDuty
- Weak password policy and missing MFA
- Plaintext secrets in environment variables

Scores are strictly between 0 and 1, keeping the environment compatible with OpenEnv evaluation rules.

---

## Scoring Breakdown

| Component | Easy | Medium | Hard |
|-----------|------|--------|------|
| SSH/RDP detection | 0.55 | — | — |
| Internet exposure | 0.25 | — | — |
| Public access | — | 0.20 | — |
| Encryption | — | 0.20 | — |
| Wildcard IAM Action | — | — | 0.18 |
| Weak password / MFA | — | — | 0.28 |
| Logging & GuardDuty | — | — | 0.24 |
| Remediation quality | 0.15 | 0.05 | 0.04 |
| Config patch bonus | 0.10 | 0.05 | 0.08 |

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/reset` | Initialise or reset the environment for a new episode |
| `/step` | Submit an agent action and receive a reward |
| `/state` | Retrieve the current environment state |
| `/health` | Liveness check |
| `/schema` | Action and observation schema |
| `/metadata` | Task and environment metadata |
| `/mcp` | Model context protocol endpoint |

---

## Project Structure
├── environment.py # FastAPI environment implementation
├── tasks.py # Task definitions and grader logic
├── inference.py # Baseline LLM-driven agent
├── agent.py # Runner entry point
├── openenv.yaml # OpenEnv endpoint configuration
├── Dockerfile # Container setup for deployment
└── requirements.txt # Python dependencies


---

## Environment Variables

| Variable | Default | Required |
|----------|---------|----------|
| `HF_TOKEN` | — | ✅ |
| `MODEL_NAME` | `Qwen/Qwen2.5-72B-Instruct` | No |
| `API_BASE_URL` | `https://router.huggingface.co/v1` | No |
| `ENV_BASE_URL` | `http://localhost:7860` | No |

---

## How to Run Locally

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

---

## Real Benchmark Run Output

==================================================
easy_security_group run 1: 0.9900 (3 findings)
easy_security_group run 2: 0.9900 (3 findings)
easy_security_group run 3: 0.9900 (3 findings)
>>> easy_security_group AVG: 0.9900

medium_s3_policy run 1: 0.9900 (6 findings)
medium_s3_policy run 2: 0.9900 (6 findings)
medium_s3_policy run 3: 0.9900 (6 findings)
>>> medium_s3_policy AVG: 0.9900

medium_lambda_iam run 1: 0.9900 (11 findings)
medium_lambda_iam run 2: 0.9900 (11 findings)
medium_lambda_iam run 3: 0.9900 (11 findings)
>>> medium_lambda_iam AVG: 0.9900

hard_rds_cloudtrail run 1: 0.9200 (13 findings)
hard_rds_cloudtrail run 2: 0.9200 (13 findings)
hard_rds_cloudtrail run 3: 0.9200 (13 findings)
>>> hard_rds_cloudtrail AVG: 0.9200

hard_iam_vpc run 1: 0.8200 (17 findings)
hard_iam_vpc run 2: 0.8200 (17 findings)
hard_iam_vpc run 3: 0.8200 (17 findings)
>>> hard_iam_vpc AVG: 0.8200

==================================================
FINAL SCORES
==================================================
easy_security_group 0.9900 ███████████████████
medium_s3_policy 0.9900 ███████████████████
medium_lambda_iam 0.9900 ███████████████████
hard_rds_cloudtrail 0.9200 ██████████████████
hard_iam_vpc 0.8200 ████████████████
==================================================
OVERALL AVERAGE: 0.9420


---

## Limitations and Future Work

- The current grader uses rule-based pattern matching; future versions could incorporate LLM-as-judge scoring for more nuanced remediation evaluation
- Task configurations are static; dynamic config generation with randomised misconfiguration injection would improve generalisation
- Multi-step agent memory across tasks is not yet implemented — each task resets independently
- Adding CIS Benchmark or AWS Foundational Security Best Practices alignment would make scoring auditable against industry standards
- Expanding to additional AWS services (Lambda permissions, RDS snapshots, KMS key policies) is a natural next step

---

## Links

| Resource | Link |
|----------|------|
| 🚀 Live Demo | https://huggingface.co/spaces/kkaustav/cloud-config-auditor |
| 🤗 Fine-tuned Model | https://huggingface.co/kkaustav/aws-security-auditor-lora |
| 💻 GitHub | https://github.com/kkaustav/aws-security-auditor |