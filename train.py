#!/usr/bin/env python3
"""
train_colab.py — AWS Cloud Config Auditor
GRPO training tuned to reproduce Run 2 (loss 0.6124, no NaN grads, 100 steps)
"""
import os, json, re, requests, torch
os.environ["UNSLOTH_RETURN_LOGITS"] = "1"
os.environ["UNSLOTH_CACHE_DIR"]     = "/tmp/unsloth_cache"
import unsloth
from unsloth import FastLanguageModel, PatchFastRL
PatchFastRL("GRPO", FastLanguageModel)
from trl import GRPOConfig, GRPOTrainer
from datasets import Dataset

ENV_BASE_URL = os.getenv("ENV_BASE_URL", "https://kkaustav-cloud-config-auditor.hf.space")
MODEL_NAME   = os.getenv("MODEL_NAME", "unsloth/Qwen2.5-3B-Instruct-bnb-4bit")
OUTPUT_DIR   = os.getenv("OUTPUT_DIR", "/content/cloud-config-auditor/grpo_output")
HF_REPO      = os.getenv("HF_REPO",   "kkaustav/aws-security-auditor-lora")
HF_TOKEN     = os.getenv("HF_TOKEN",  "")
MAX_SEQ_LEN  = 2048
LORA_RANK    = 16
CURRICULUM   = ["easy_security_group", "medium_s3_policy", "hard_iam_vpc"]

# ── Env Client ─────────────────────────────────────────────────────────────────
def env_reset(task):
    r = requests.post(f"{ENV_BASE_URL}/reset?task={task}", timeout=30)
    r.raise_for_status(); return r.json()

def env_step(findings, severity, recommendations, config_patch):
    r = requests.post(f"{ENV_BASE_URL}/step", json={
        "findings": findings, "severity": severity,
        "recommendations": recommendations, "config_patch": config_patch
    }, timeout=30)
    r.raise_for_status(); return r.json()

def env_health():
    try: return requests.get(f"{ENV_BASE_URL}/health", timeout=10).status_code == 200
    except: return False

# ── Prompt ─────────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an expert AWS cloud security auditor.
Return your audit as valid JSON ONLY (no markdown, no code blocks):
{
  "findings": ["finding 1", "finding 2"],
  "severity": ["CRITICAL", "HIGH"],
  "recommendations": ["fix step 1", "fix step 2"],
  "config_patch": {"key": "suggested_value"}
}
Severity levels: CRITICAL, HIGH, MEDIUM, LOW. Be specific — generic findings score zero."""

def build_prompt(config, desc):
    return (
        f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n"
        f"<|im_start|>user\nTask: {desc}\n\nConfiguration:\n{config}<|im_end|>\n"
        f"<|im_start|>assistant\n"
    )

# ── Parser ─────────────────────────────────────────────────────────────────────
def parse_response(text):
    try: data = json.loads(text.strip())
    except:
        m = re.search(r'\{.*\}', text, re.DOTALL)
        try: data = json.loads(m.group()) if m else {}
        except: data = {}

    raw_findings = data.get("findings", [])
    findings = []
    if isinstance(raw_findings, list):
        for f in raw_findings:
            if isinstance(f, dict):   findings.append(f.get("description", f.get("rule", str(f))))
            elif isinstance(f, str):  findings.append(f)

    raw_sev = data.get("severity", [])
    if isinstance(raw_sev, str):    severity = [raw_sev]
    elif isinstance(raw_sev, list): severity = [s.get("severity", s) if isinstance(s, dict) else s for s in raw_sev]
    else:                           severity = []

    return {
        "findings":        findings,
        "severity":        severity,
        "recommendations": data.get("recommendations", []) if isinstance(data.get("recommendations"), list) else [],
        "config_patch":    data.get("config_patch", {})    if isinstance(data.get("config_patch"), dict) else {},
    }

# ── Reward ─────────────────────────────────────────────────────────────────────
def reward_fn(completions, prompts=None, **kwargs):
    rewards, dataset_ref = [], kwargs.get("dataset_ref", [])
    for i, completion in enumerate(completions):
        if len(completion.strip()) < 30: rewards.append(0.0); continue
        parsed = parse_response(completion)
        if not parsed["findings"]: rewards.append(0.01); continue
        try:
            task = dataset_ref[i % len(dataset_ref)]["task_name"] if dataset_ref else CURRICULUM[0]
            env_reset(task)
            result = env_step(parsed["findings"], parsed["severity"],
                              parsed["recommendations"], parsed["config_patch"])
            base  = float(result.get("reward", 0.0))
            bonus = sum(0.02 for k in ["findings","severity","recommendations","config_patch"] if parsed[k])
            if all(s in {"CRITICAL","HIGH","MEDIUM","LOW"} for s in parsed["severity"]): bonus += 0.02
            # Penalise vague responses
            vague = ["review your settings", "consult aws docs", "see documentation"]
            penalty = 0.05 if any(v in " ".join(parsed["findings"]).lower() for v in vague) else 0.0
            rewards.append(min(0.99, max(0.0, base + bonus - penalty)))
        except Exception as e:
            print(f"[reward] {e}"); rewards.append(0.0)
    return rewards

# ── Dataset ────────────────────────────────────────────────────────────────────
def build_dataset(n=10):          # ← Run 2 used 10 per task
    records = []
    for task in CURRICULUM:
        for _ in range(n):
            try:
                obs = env_reset(task).get("observation", {})
                records.append({
                    "prompt":    build_prompt(obs.get("config",""), obs.get("task_description", task)),
                    "task_name": task,
                })
            except Exception as e: print(f"[dataset] {task}: {e}")
    return Dataset.from_list(records)

# ── Evaluate ───────────────────────────────────────────────────────────────────
def evaluate(model, tokenizer, label, n=3):
    print(f"\n{'='*55}\n{label}\n{'='*55}")
    scores = {}
    for task in CURRICULUM:
        task_scores = []
        for i in range(n):
            try:
                obs    = env_reset(task).get("observation", {})
                inputs = tokenizer(
                    build_prompt(obs.get("config",""), obs.get("task_description", task)),
                    return_tensors="pt"
                ).to("cuda")
                with torch.no_grad():
                    out = model.generate(**inputs, max_new_tokens=384, temperature=0.7, do_sample=True)
                response = tokenizer.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
                parsed   = parse_response(response)
                env_reset(task)
                score = float(env_step(parsed["findings"], parsed["severity"],
                                       parsed["recommendations"], parsed["config_patch"]).get("reward", 0.0))
                task_scores.append(score)
                print(f"  [{task}] run {i+1}: {score:.4f}")
            except Exception as e:
                print(f"  [{task}] run {i+1}: error — {e}"); task_scores.append(0.0)
        scores[task] = round(sum(task_scores)/len(task_scores), 4)
        print(f"  [{task}] avg = {scores[task]:.4f}")
    return scores

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not env_health(): print(f"❌ Env not reachable at {ENV_BASE_URL}"); return
    print(f"✅ Environment live at {ENV_BASE_URL}")

    model, tokenizer = FastLanguageModel.from_pretrained(
        MODEL_NAME, max_seq_length=MAX_SEQ_LEN, dtype=None, load_in_4bit=True)
    model = FastLanguageModel.get_peft_model(
        model, r=LORA_RANK,
        target_modules=["q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"],
        lora_alpha=LORA_RANK, lora_dropout=0, bias="none",
        use_gradient_checkpointing="unsloth", random_state=42)

    FastLanguageModel.for_inference(model)
    baseline = evaluate(model, tokenizer, "BASELINE (pre-training)")
    with open(f"{OUTPUT_DIR}/baseline_scores.json","w") as f: json.dump(baseline, f, indent=2)

    FastLanguageModel.for_training(model)
    dataset = build_dataset(n=10)
    print(f"\nDataset: {len(dataset)} prompts")

    dataset_list = dataset.to_list()
    def reward_wrapper(completions, prompts=None, **kwargs):
        return reward_fn(completions, prompts=prompts, dataset_ref=dataset_list)

    trainer = GRPOTrainer(
        model=model,
        args=GRPOConfig(
            output_dir=OUTPUT_DIR,
            num_train_epochs=3,
            per_device_train_batch_size=2,
            gradient_accumulation_steps=2,    # ← lower than before → more steps, matches Run 2 ~100
            learning_rate=5e-6,
            max_grad_norm=1.0,                # ← explicit clip → prevents NaN grad_norm
            num_generations=4,
            max_completion_length=384,
            temperature=0.7,
            logging_steps=5,
            save_steps=25,
            report_to="none",
            # T4 FIX: disable mixed precision
            fp16=False,                       # ← CHANGED: always False on T4
            bf16=False,                       # ← CHANGED: T4 has no bfloat16
        ),
        train_dataset=dataset,
        reward_funcs=reward_wrapper,
        processing_class=tokenizer,
    )

    print("\n🚀 Starting GRPO training...")
    trainer.train()

    save_path = "/content/aws-security-auditor-lora"
    model.save_pretrained_merged(save_path, tokenizer, save_method="lora")
    print(f"✅ Model saved → {save_path}")

    # Push to HF Hub
    if HF_TOKEN:
        from huggingface_hub import HfApi
        HfApi().upload_folder(
            folder_path=save_path,
            repo_id=HF_REPO,
            token=HF_TOKEN,
            commit_message="Restore: GRPO v3 — original 3-task grading, Run2-config (n=10, max_grad_norm=1.0)"
        )
        print(f"✅ Pushed → {HF_REPO}")

    FastLanguageModel.for_inference(model)
    trained = evaluate(model, tokenizer, "FINAL EVALUATION (post-training)")

    print("\n📊 Before vs After:")
    print(f"{'Task':<30} {'Baseline':>10} {'Trained':>10} {'Delta':>10}")
    print("-"*62)
    for task in CURRICULUM:
        b, t = baseline.get(task, 0.0), trained.get(task, 0.0)
        print(f"{task:<30} {b:>10.4f} {t:>10.4f} {'✅' if t>b else '⚠️'} {t-b:>+8.4f}")

    with open(f"{OUTPUT_DIR}/training_comparison.json","w") as f:
        json.dump({"baseline": baseline, "trained": trained}, f, indent=2)
    print("\n✅ Done.")

if __name__ == "__main__": main()