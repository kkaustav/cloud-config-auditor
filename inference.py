#!/usr/bin/env python3

import os
import json
import re
import sys
import requests
from huggingface_hub import InferenceClient

# ── CONFIG ────────────────────────────────────────────────────────────────────
HF_TOKEN   = os.environ.get("HF_TOKEN", "")
BASE_URL   = "https://kkaustav-cloud-config-auditor.hf.space"
MAX_STEPS  = 5

# Free-tier models in priority order — switches to next on 402
MODELS = [
    "meta-llama/Llama-3.1-8B-Instruct",
    "google/gemma-2-9b-it",
    "mistralai/Mistral-7B-Instruct-v0.3",
]

TASKS = [
    "easy_security_group",
    "medium_s3_policy",
    "hard_iam_vpc",
    "medium_lambda_iam",
    "hard_rds_cloudtrail",
]

SYSTEM_PROMPT = (
    "You are an expert AWS cloud security auditor. "
    "Analyse the provided AWS configuration and return a security audit as valid JSON ONLY. "
    "Do not include any explanation, markdown, or text outside the JSON object. "
    "Return exactly this structure:\n"
    '{"findings":["<finding1>","<finding2>"],"severity":["CRITICAL","HIGH","MEDIUM","LOW"],"recommendations":["<rec1>"],"config_patch":{"key":"value"}}'
)
# ── END CONFIG ────────────────────────────────────────────────────────────────


def build_user_prompt(obs):
    task_desc = obs.get("task_description", "")
    config    = obs.get("config", "")
    feedback  = obs.get("feedback")
    reward    = obs.get("last_reward", 0.0)

    prompt = f"{task_desc}\n\nAWS Configuration:\n{config}"
    if feedback:
        prompt += f"\n\nPrevious attempt scored {reward:.2f}. Evaluator feedback: {feedback}"
        prompt += "\nFix ALL missed findings. Use explicit AWS service names and field names."
    return prompt


def parse_json(text):
    text = text.strip()
    # strip markdown code fences if present
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    # try direct parse first
    try:
        return json.loads(text)
    except Exception:
        pass
    # extract first { ... } block
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise ValueError("No JSON object found")
    raw = m.group().strip()
    # try progressively shorter line-wise prefixes to handle trailing garbage
    lines = raw.split("\n")
    for i in range(len(lines), 0, -1):
        try:
            return json.loads("\n".join(lines[:i]))
        except Exception:
            continue
    raise ValueError("Could not parse JSON")


def ask_llm(client, model, messages):
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=1024,
        temperature=0.1,
    )
    return response.choices[0].message.content


def get_client_and_model(hf_token):
    """Return (InferenceClient, model_name) using the first model that responds."""
    for model in MODELS:
        try:
            client = InferenceClient(token=hf_token)
            # quick probe — 1 token just to test the model is available
            client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=1,
            )
            print(f"[MODEL] Using {model}", flush=True)
            return client, model
        except Exception as e:
            err = str(e)
            if "402" in err or "429" in err or "503" in err or "loading" in err.lower():
                print(f"[MODEL] {model} unavailable ({err[:80]}), trying next…", flush=True)
                continue
            # unexpected error — still try next
            print(f"[MODEL] {model} error: {err[:120]}, trying next…", flush=True)
            continue
    raise RuntimeError("All models exhausted. Top up HuggingFace credits or add more fallback models.")


def run_task(task, client, model):
    # ── reset ──────────────────────────────────────────────────────────────
    r = requests.post(f"{BASE_URL}/reset", params={"task": task}, timeout=30)
    r.raise_for_status()
    obs = r.json()["observation"]

    print(f"[START] task={task} env=aws-security-auditor model={model}", flush=True)

    best_score  = 0.0
    all_rewards = []
    messages    = [{"role": "system", "content": SYSTEM_PROMPT}]

    for step in range(1, MAX_STEPS + 1):
        user_msg = build_user_prompt(obs)
        messages.append({"role": "user", "content": user_msg})

        # ── call LLM ───────────────────────────────────────────────────────
        raw_text   = None
        parsed     = None
        llm_error  = None

        try:
            raw_text = ask_llm(client, model, messages)
            parsed   = parse_json(raw_text)
        except Exception as e:
            llm_error = str(e)
            if "402" in llm_error:
                # credits exhausted mid-run — hard stop
                print(
                    f"[ERROR] ask_llm failed at step {step}: {llm_error}",
                    flush=True,
                )
                # send empty step so env records it
                parsed = {"findings": [], "severity": [], "recommendations": [], "config_patch": {}}
            else:
                print(f"[ERROR] ask_llm failed at step {step}: {llm_error}", flush=True)
                parsed = {"findings": [], "severity": [], "recommendations": [], "config_patch": {}}

        findings        = parsed.get("findings", [])
        severity        = parsed.get("severity", [])
        recommendations = parsed.get("recommendations", [])
        config_patch    = parsed.get("config_patch", {})

        # ── step ───────────────────────────────────────────────────────────
        step_r = requests.post(
            f"{BASE_URL}/step",
            json={
                "findings":        findings,
                "severity":        severity,
                "recommendations": recommendations,
                "config_patch":    config_patch,
            },
            timeout=30,
        )
        step_r.raise_for_status()
        step_data = step_r.json()

        reward = step_data.get("reward", 0.0) or 0.0
        done   = step_data.get("done", False)
        obs    = step_data.get("observation", obs)

        all_rewards.append(reward)
        if reward > best_score:
            best_score = reward

        n_findings = len(findings)
        print(
            f"[STEP] step={step} action=findings={n_findings} "
            f"reward={reward:.2f} done={str(done).lower()} "
            f"error={json.dumps(llm_error)}",
            flush=True,
        )

        # add assistant response to history so the model can iterate
        if raw_text:
            messages.append({"role": "assistant", "content": raw_text})

        if done:
            break

    rewards_str = ",".join(f"{x:.2f}" for x in all_rewards)
    success = best_score >= 0.55
    print(
        f"[END] task={task} success={str(success).lower()} "
        f"steps={len(all_rewards)} score={best_score:.3f} rewards={rewards_str}",
        flush=True,
    )
    print("", flush=True)
    return best_score


def main():
    if not HF_TOKEN:
        print("[FATAL] HF_TOKEN not set. Run: export HF_TOKEN=hf_...", flush=True)
        sys.exit(1)

    client, model = get_client_and_model(HF_TOKEN)

    scores = []
    for task in TASKS:
        try:
            score = run_task(task, client, model)
            scores.append(score)
        except Exception as e:
            print(f"[FATAL] task={task} crashed: {e}", flush=True)
            scores.append(0.0)

    print("Task scores:", scores)
    if scores:
        print(f"OVERALL: {sum(scores)/len(scores):.3f}")


if __name__ == "__main__":
    main()