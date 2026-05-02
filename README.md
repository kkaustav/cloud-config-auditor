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
