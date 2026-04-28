#!/usr/bin/env python3
"""
GRPO Training Script — AWS Cloud Config Auditor
Meta PyTorch OpenEnv Hackathon x Scaler School of Technology
Stack: TRL + Unsloth + GRPO
"""

import os, json, re, time, requests, torch
from datasets import Dataset
from trl import GRPOConfig, GRPOTrainer
from unsloth import FastLanguageModel

# ── Config ─────────────────────────────────────────────────────────────────────
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:7860")
HF_TOKEN     = os.getenv("HF_TOKEN", "")
MODEL_NAME   = os.getenv("MODEL_NAME", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit")
OUTPUT_DIR   = os.getenv("OUTPUT_DIR", "./grpo_output")
MAX_SEQ_LEN  = 2048
LORA_RANK    = 16
CURRICULUM   = ["easy_security_group", "medium_s3_policy", "hard_iam_vpc"]

# ── Environment Client ─────────────────────────────────────────────────────────
# /reset uses query param ?task=   (NOT json body)
# /step  uses AuditAction body     (findings, severity, recommendations, config_patch)

def env_reset(task: str) -> dict:
    r = requests.post(f"{ENV_BASE_URL}/reset?task={task}", timeout=30)
    r.raise_for_status()
    return r.json()

def env_step(findings: list, severity: list, recommendations: list, config_patch: dict) -> dict:
    body = {
        "findings":        findings,
        "severity":        severity,
        "recommendations": recommendations,
        "config_patch":    config_patch
    }
    r = requests.post(f"{ENV_BASE_URL}/step", json=body, timeout=30)
    r.raise_for_status()
    return r.json()

def env_health() -> bool:
    try:
        return requests.get(f"{ENV_BASE_URL}/health", timeout=10).status_code == 200
    except Exception:
        return False

# ── Prompt Builder ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an expert AWS cloud security auditor.
Analyse the provided AWS configuration and return your audit as valid JSON ONLY.

Output format (strict JSON, no extra text):
{
  "findings": ["finding 1", "finding 2"],
  "severity": ["CRITICAL", "HIGH"],
  "recommendations": ["fix step 1", "fix step 2"],
  "config_patch": {"key": "suggested_value"}
}

Severity levels: CRITICAL, HIGH, MEDIUM, LOW
Be specific — generic findings score zero."""

def build_prompt(config: str, task_description: str) -> str:
    return (
        f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n"
        f"<|im_start|>user\n"
        f"Task: {task_description}\n\n"
        f"Configuration to audit:\n{config}<|im_end|>\n"
        f"<|im_start|>assistant\n"
    )

# ── Response Parser ────────────────────────────────────────────────────────────
def parse_response(text: str) -> dict:
    """Parse model JSON output into AuditAction fields. Falls back gracefully."""
    try:
        # Try direct JSON parse first
        data = json.loads(text.strip())
    except Exception:
        # Try to extract JSON block from response
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
            except Exception:
                data = {}
        else:
            data = {}

    return {
        "findings":        data.get("findings", []) if isinstance(data.get("findings"), list) else [],
        "severity":        data.get("severity", []) if isinstance(data.get("severity"), list) else [],
        "recommendations": data.get("recommendations", []) if isinstance(data.get("recommendations"), list) else [],
        "config_patch":    data.get("config_patch", {}) if isinstance(data.get("config_patch"), dict) else {},
    }

# ── Reward Function ────────────────────────────────────────────────────────────
def reward_fn(completions: list, prompts: list = None, **kwargs) -> list:
    rewards = []
    dataset_ref = kwargs.get("dataset_ref", [])

    for i, completion in enumerate(completions):
        # Anti-hacking: reject empty or too-short responses
        if len(completion.strip()) < 30:
            rewards.append(0.0)
            continue

        parsed = parse_response(completion)

        # Anti-hacking: no empty findings list
        if not parsed["findings"]:
            rewards.append(0.01)
            continue

        try:
            task_name = dataset_ref[i % len(dataset_ref)]["task_name"] if dataset_ref else CURRICULUM[0]
            env_reset(task_name)
            result = env_step(
                parsed["findings"],
                parsed["severity"],
                parsed["recommendations"],
                parsed["config_patch"]
            )
            base_reward = float(result.get("reward", 0.0))

            # Format compliance bonus
            format_bonus = 0.0
            if parsed["findings"]:        format_bonus += 0.02
            if parsed["severity"]:        format_bonus += 0.02
            if parsed["recommendations"]: format_bonus += 0.02
            if parsed["config_patch"]:    format_bonus += 0.02
            valid_sev = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            if all(s in valid_sev for s in parsed["severity"]):
                format_bonus += 0.02

            # Anti-hacking penalty for vague responses
            penalty = 0.0
            vague = ["review your settings", "consult aws docs", "see documentation"]
            if any(v in " ".join(parsed["findings"]).lower() for v in vague):
                penalty = 0.05

            final = min(0.99, max(0.0, base_reward + format_bonus - penalty))
            rewards.append(final)

        except Exception as e:
            print(f"[reward] error on step {i}: {e}")
            rewards.append(0.0)

    return rewards

# ── Dataset Builder ────────────────────────────────────────────────────────────
def build_dataset(n_per_task: int = 20) -> Dataset:
    records = []
    for task in CURRICULUM:
        for _ in range(n_per_task):
            try:
                result   = env_reset(task)
                obs      = result.get("observation", {})
                config   = obs.get("config", "")
                desc     = obs.get("task_description", task)
                records.append({
                    "prompt":    build_prompt(config, desc),
                    "task_name": task,
                })
            except Exception as e:
                print(f"[dataset] skipping {task}: {e}")
    return Dataset.from_list(records)

# ── Evaluation Helper ──────────────────────────────────────────────────────────
def evaluate(model, tokenizer, label: str, n: int = 3) -> dict:
    print(f"\n{'='*60}\n{label}\n{'='*60}")
    scores = {}
    for task in CURRICULUM:
        task_scores = []
        for i in range(n):
            try:
                result  = env_reset(task)
                obs     = result.get("observation", {})
                prompt  = build_prompt(obs.get("config",""), obs.get("task_description", task))
                inputs  = tokenizer(prompt, return_tensors="pt").to("cuda")
                with torch.no_grad():
                    out = model.generate(
                        **inputs, max_new_tokens=512,
                        temperature=0.7, do_sample=True
                    )
                response = tokenizer.decode(
                    out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True
                )
                parsed = parse_response(response)
                env_reset(task)
                step_result = env_step(
                    parsed["findings"], parsed["severity"],
                    parsed["recommendations"], parsed["config_patch"]
                )
                score = float(step_result.get("reward", 0.0))
                task_scores.append(score)
                print(f"  [{task}] run {i+1}: {score:.4f}")
            except Exception as e:
                print(f"  [{task}] run {i+1}: error — {e}")
                task_scores.append(0.0)
        scores[task] = round(sum(task_scores) / len(task_scores), 4)
        print(f"  [{task}] avg = {scores[task]:.4f}")
    return scores

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Checking environment...")
    if not env_health():
        print(f"❌ Environment not reachable at {ENV_BASE_URL}")
        print("   Run: uvicorn environment:app --host 0.0.0.0 --port 7860")
        return
    print(f"✅ Environment live at {ENV_BASE_URL}")

    print(f"\nLoading model: {MODEL_NAME}")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=MODEL_NAME, max_seq_length=MAX_SEQ_LEN,
        dtype=None, load_in_4bit=True,
    )
    model = FastLanguageModel.get_peft_model(
        model, r=LORA_RANK,
        target_modules=["q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"],
        lora_alpha=LORA_RANK, lora_dropout=0, bias="none",
        use_gradient_checkpointing="unsloth", random_state=42,
    )

    # Baseline before training
    FastLanguageModel.for_inference(model)
    baseline = evaluate(model, tokenizer, "BASELINE (pre-training)")
    with open(f"{OUTPUT_DIR}/baseline_scores.json", "w") as f:
        json.dump(baseline, f, indent=2)

    # Dataset
    FastLanguageModel.for_training(model)
    print("\nBuilding dataset...")
    dataset = build_dataset(n_per_task=20)
    print(f"Dataset: {len(dataset)} prompts")

    # GRPO training
    grpo_args = GRPOConfig(
        output_dir=OUTPUT_DIR,
        num_train_epochs=3,
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        learning_rate=5e-6,
        num_generations=4,
        max_new_tokens=512,
        temperature=0.7,
        logging_steps=10,
        save_steps=50,
        report_to="none",
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
    )

    dataset_list = dataset.to_list()
    def reward_wrapper(completions, prompts=None, **kwargs):
        return reward_fn(completions, prompts=prompts, dataset_ref=dataset_list)

    trainer = GRPOTrainer(
        model=model, args=grpo_args,
        train_dataset=dataset,
        reward_funcs=reward_wrapper,
        processing_class=tokenizer,
    )

    print("\n🚀 Starting GRPO training...")
    trainer.train()

    # Save LoRA adapters
    model.save_pretrained_merged(f"{OUTPUT_DIR}/final_model", tokenizer, save_method="lora")
    print(f"\n✅ Model saved → {OUTPUT_DIR}/final_model")

    # Final comparison
    FastLanguageModel.for_inference(model)
    trained = evaluate(model, tokenizer, "FINAL EVALUATION (post-training)")

    print("\n📊 Before vs After:")
    print(f"{'Task':<30} {'Baseline':>10} {'Trained':>10} {'Delta':>10}")
    print("-" * 62)
    for task in CURRICULUM:
        b, t = baseline.get(task, 0.0), trained.get(task, 0.0)
        arrow = "✅" if t > b else "⚠️"
        print(f"{task:<30} {b:>10.4f} {t:>10.4f} {arrow} {t-b:>+8.4f}")

    results = {"baseline": baseline, "trained": trained}
    with open(f"{OUTPUT_DIR}/training_comparison.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nComparison saved → {OUTPUT_DIR}/training_comparison.json")
    print("\n✅ Done.")

if __name__ == "__main__":
    main()
