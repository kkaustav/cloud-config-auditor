 
Title: Cloud Config Auditor
emoji: 🔐
colorFrom: blue
colorTo: green
sdk: docker
pinned: false
AWS Security Auditor
🏆 Built for the Meta PyTorch OpenEnv Hackathon x Scaler School of Technology
In collaboration with Meta AI, PyTorch, and Hugging Face | April 2026
 


 


 


 


 
An OpenEnv-compatible environment for training and evaluating AI agents that audit AWS cloud infrastructure for security misconfigurations.
What this project does
This project simulates realistic AWS security review tasks and gives an AI agent a reward based on the quality of its findings, severity labels, remediation advice, and optional config patches.
The environment is designed for reinforcement learning and evaluation workflows where an agent must inspect cloud configuration data, identify security issues, and improve over multiple steps.
Why this environment is unique
Unlike generic ML benchmarks, this environment is grounded in real AWS production configurations — Security Groups, S3 bucket policies, IAM roles, and VPC network ACLs. The tasks reflect actual enterprise-grade misconfiguration patterns encountered in production cloud environments, making agent performance directly applicable to real-world cloud security auditing. This specificity sets it apart from synthetic benchmarks and makes it a practical testbed for AI-driven cloud compliance tooling.
Architecture
Agent (inference.py)
       │
       ▼  HTTP (POST /reset, /step)
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

The agent operates in a standard observe → act → reward loop. On each /step, the agent submits a structured audit response. The grader evaluates it against a weighted rubric and returns a scalar reward. The agent uses this signal to improve its findings over subsequent steps.
Tasks
The environment includes three tasks with increasing difficulty:
•	easy_security_group — reviews a production web-tier Security Group and checks for risky internet-exposed inbound rules such as SSH and RDP.
•	medium_s3_policy — audits an S3 bucket for public access, missing encryption, suspended versioning, and overly permissive bucket policies.
•	hard_iam_vpc — reviews IAM and VPC settings for an ECS production environment, including wildcard IAM permissions, weak password policy, disabled MFA, missing logging, and open network ACLs.
Reward design
Each task uses a weighted reward breakdown for important security signals.
Examples include:
•	SSH or RDP exposure
•	Public S3 access
•	Wildcard IAM permissions like Action:*
•	Disabled VPC Flow Logs, CloudTrail, or GuardDuty
•	Weak password policy and missing MFA
Scores are intentionally forced to stay strictly between 0 and 1, which keeps the environment compatible with hackathon validation and OpenEnv evaluation rules.
Scoring breakdown
Component	Easy	Medium	Hard
SSH/RDP detection	0.55	—	—
Internet exposure	0.25	—	—
Public access	—	0.20	—
Encryption	—	0.20	—
Wildcard IAM Action	—	—	0.18
Weak password / MFA	—	—	0.28
Logging & GuardDuty	—	—	0.24
Remediation quality	0.15	0.05	0.04
Config patch bonus	0.10	0.05	0.08

API endpoints
The environment exposes standard OpenEnv-style HTTP endpoints:
•	/reset — initialise or reset the environment for a new episode
•	/step — submit an agent action and receive a reward
•	/state — retrieve the current environment state
•	/health — liveness check
•	/schema — action and observation schema
•	/metadata — task and environment metadata
•	/mcp — model context protocol endpoint
Project structure
.
├── environment.py       # FastAPI environment implementation
├── tasks.py             # Task definitions and grader logic
├── inference.py         # Baseline LLM-driven agent
├── agent.py             # Runner entry point
├── openenv.yaml         # OpenEnv endpoint configuration
├── Dockerfile           # Container setup for deployment
└── requirements.txt     # Python dependencies

Environment variables
Variable	Default	Required
HF_TOKEN	—	✅
MODEL_NAME	Qwen/Qwen2.5-72B-Instruct	No
API_BASE_URL	https://router.huggingface.co/v1	No
ENV_BASE_URL	http://localhost:7860	No

How to run locally
Install dependencies:
pip install -r requirements.txt

Start the environment:
uvicorn environment:app --host 0.0.0.0 --port 7860

In another terminal, run the agent:
export HF_TOKEN=YOUR_TOKEN
python3 inference.py

Example agent run output
⚠️ Replace the sample output below with actual terminal output from your own run.
[Task: easy_security_group]
→ Agent identified: SSH (port 22) open to 0.0.0.0/0 — CRITICAL
→ Agent identified: RDP (port 3389) open to 0.0.0.0/0 — CRITICAL
→ Remediation: Restrict inbound SSH/RDP to known CIDR ranges or VPN only
→ Config patch: Suggested SG rule deletion for 0.0.0.0/0 on ports 22, 3389
→ Task reward: 0.87

[Task: medium_s3_policy]
→ Agent identified: BlockPublicAcls = false — HIGH
→ Agent identified: Server-side encryption not enforced — HIGH
→ Agent identified: Versioning status = Suspended — MEDIUM
→ Remediation: Enable S3 Block Public Access, enforce AES-256 encryption, resume versioning
→ Task reward: 0.74

[Task: hard_iam_vpc]
→ Agent identified: IAM policy contains Action:* with Resource:* — CRITICAL
→ Agent identified: Password policy MinLength = 6, no MFA enforced — HIGH
→ Agent identified: VPC Flow Logs disabled — HIGH
→ Agent identified: CloudTrail logging inactive in us-east-1 — HIGH
→ Agent identified: GuardDuty not enabled — MEDIUM
→ Remediation: Apply least-privilege IAM, enforce MFA, enable Flow Logs + CloudTrail + GuardDuty
→ Task reward: 0.81

Final scores — easy: 0.87 | medium: 0.74 | hard: 0.81
All scores within valid OpenEnv range (0.0, 1.0) ✅

Limitations and future work
•	The current grader uses rule-based pattern matching; future versions could incorporate LLM-as-judge scoring for more nuanced remediation evaluation
•	Task configurations are static; dynamic config generation with randomised misconfiguration injection would improve generalisation
•	Multi-step agent memory across tasks is not yet implemented — each task resets independently
•	Adding CIS Benchmark or AWS Foundational Security Best Practices alignment would make scoring auditable against industry standards
•	Expanding to additional AWS services (Lambda permissions, RDS snapshots, KMS key policies) is a natural next step
🚀 Live Demo
https://huggingface.co/spaces/kkaustav/cloud-config-auditor
