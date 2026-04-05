import asyncio, json, os, re, textwrap, urllib.request
from typing import List, Optional
from openai import OpenAI

API_KEY           = os.getenv("HF_TOKEN") or os.getenv("API_KEY", "")
API_BASE_URL      = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME        = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
ENV_BASE_URL      = os.getenv("ENV_BASE_URL", "http://localhost:7860").rstrip("/")
BENCHMARK         = "aws-security-auditor"
MAX_STEPS         = 5
TEMPERATURE       = 0.2
MAX_TOKENS        = 1200
SUCCESS_THRESHOLD = 0.55
TASKS_TO_RUN      = ["easy_security_group", "medium_s3_policy", "hard_iam_vpc"]

def log_start(task, env, model):
    print(f"START task={task} env={env} model={model}", flush=True)

def log_step(step, action, reward, done, error=None):
    print(f"STEP step={step} action={action} reward={reward:.2f} done={str(done).lower()} error={error or 'null'}", flush=True)

def log_end(success, steps, score, rewards):
    r_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"END success={str(success).lower()} steps={steps} score={score:.3f} rewards={r_str}", flush=True)

def _post(path, body):
    url  = f"{ENV_BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8")
    req  = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))

def env_reset(task_name):
    return _post(f"/reset?task={task_name}", {})

def env_step(findings, severity, recommendations, config_patch={}):
    return _post("/step", {"findings": findings, "severity": severity, "recommendations": recommendations, "config_patch": config_patch})

SYSTEM_PROMPT = textwrap.dedent("""
You are a senior AWS Solutions Architect and cloud security expert.
Identify ALL security misconfigurations in the given AWS config.
Respond ONLY with valid JSON, no markdown:
{"findings": ["issue1"], "severity": ["HIGH"], "recommendations": ["fix1"], "config_patch": {}}
Rules: findings and recommendations same length. severity = HIGH/MEDIUM/LOW only.
""").strip()

def ask_llm(client, obs, feedback, step):
    config    = obs.get("config", "")
    task_desc = obs.get("task_description", "")
    prev_rew  = obs.get("last_reward", 0.0)
    user_msg  = f"Task: {task_desc}\n\nConfiguration:\n{config}"
    if feedback and step > 1:
        user_msg += f"\n\nFeedback (score {prev_rew:.2f}): {feedback}\nFind remaining issues."
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_msg}],
            temperature=TEMPERATURE, max_tokens=MAX_TOKENS,
        )
        raw  = (response.choices[0].message.content or "{}").strip()
        raw  = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.MULTILINE)
        data = json.loads(raw)
        return {"findings": data.get("findings", ["no findings"]), "severity": data.get("severity", []),
                "recommendations": data.get("recommendations", []), "config_patch": data.get("config_patch", {})}
    except Exception as e:
        print(f"[DEBUG] LLM error at step {step}: {e}", flush=True)
        return {"findings": ["llm call failed"], "severity": ["LOW"], "recommendations": ["retry"], "config_patch": {}}

async def run_task(client, task_name):
    rewards, steps_taken, success = [], 0, False
    log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)
    try:
        result   = env_reset(task_name)
        obs      = result.get("observation", {})
        feedback = obs.get("feedback")
        for step in range(1, MAX_STEPS + 1):
            if result.get("done", False): break
            parsed   = ask_llm(client, obs, feedback, step)
            result   = env_step(parsed["findings"], parsed["severity"], parsed["recommendations"], parsed["config_patch"])
            obs      = result.get("observation", {})
            reward   = float(result.get("reward", 0.0))
            done     = result.get("done", False)
            feedback = obs.get("feedback")
            rewards.append(reward)
            steps_taken = step
            log_step(step=step, action=f"findings={len(parsed['findings'])}", reward=reward, done=done)
            if done: break
        success = (max(rewards) if rewards else 0.0) >= SUCCESS_THRESHOLD
    except Exception as e:
        print(f"[DEBUG] Task {task_name} failed: {e}", flush=True)
    finally:
        final_score = max(rewards) if rewards else 0.0
        log_end(success=success, steps=steps_taken, score=final_score, rewards=rewards)

async def main():
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
    for task_name in TASKS_TO_RUN:
        await run_task(client, task_name)
        print("", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
