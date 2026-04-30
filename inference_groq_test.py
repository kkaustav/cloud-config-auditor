import os, json, re, requests
from groq import Groq

BASE_URL = "https://kkaustav-cloud-config-auditor.hf.space"
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
MODEL = "llama-3.3-70b-versatile"
client = Groq(api_key=GROQ_API_KEY)

SYSTEM_PROMPT = """You are an expert AWS cloud security auditor.
Analyze the AWS configuration and return ONLY valid JSON with NO markdown, NO explanation:
{
  "findings": ["specific finding 1", "specific finding 2"],
  "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
  "recommendations": ["specific recommendation 1", "specific recommendation 2"],
  "config_patch": {"key": "value"}
}
Be very specific — mention exact values like port numbers, CIDRs, policy names, ARNs."""

def ask_llm(messages):
    response = client.chat.completions.create(
        model=MODEL, messages=messages, temperature=0.1, max_tokens=2048,
    )
    return response.choices[0].message.content.strip()

def parse_json(text):
    text = re.sub(r'^```(?:json)?\s*', '', text.strip())
    text = re.sub(r'\s*```$', '', text)
    try:
        return json.loads(text)
    except:
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if m:
            return json.loads(m.group())
        raise ValueError(f"No JSON found in: {text[:300]}")

def run_task(task):
    print(f"\n[START] task={task} env=aws-security-auditor model={MODEL}")

    # Reset — response is {"observation": {"task_description": ..., "config": ..., ...}}
    reset_resp = requests.post(f"{BASE_URL}/reset?task={task}", timeout=30).json()
    obs = reset_resp.get("observation", {})
    task_desc = obs.get("task_description", "")
    config = obs.get("config", "")

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Task: {task_desc}\n\nAWS Configuration:\n{config}"}
    ]

    rewards = []
    score = 0.01

    for step in range(1, 6):
        try:
            raw = ask_llm(messages)
            parsed = parse_json(raw)
            error_msg = None
        except Exception as e:
            print(f"[ERROR] ask_llm failed at step {step}: {e}")
            parsed = {"findings": [], "severity": [], "recommendations": [], "config_patch": {}}
            error_msg = str(e)

        # Send fields DIRECTLY — not wrapped in "action"
        try:
            step_resp = requests.post(f"{BASE_URL}/step", json={
                "findings": parsed.get("findings", []),
                "severity": parsed.get("severity", []),
                "recommendations": parsed.get("recommendations", []),
                "config_patch": parsed.get("config_patch", {})
            }, timeout=30).json()
        except Exception as e:
            print(f"[ERROR] step call failed: {e}")
            break

        reward = step_resp.get("reward", 0.01)
        done = step_resp.get("done", False)
        rewards.append(reward)

        nfindings = len(parsed.get("findings", []))
        err_display = f'"{error_msg}"' if error_msg else "null"
        print(f"[STEP] step={step} action=findings={nfindings} reward={reward} done={str(done).lower()} error={err_display}")

        if reward > score:
            score = reward

        if done:
            break

        # Feed the environment's feedback back for refinement
        next_obs = step_resp.get("observation", {})
        feedback = next_obs.get("feedback", "")
        if feedback:
            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "user", "content": (
                f"Your score was {reward}. Feedback: {feedback}\n"
                f"Refine your audit — be more explicit and mention exact AWS terms. Return only JSON."
            )})

    rewards_str = ",".join(str(r) for r in rewards)
    print(f"[END] task={task} success={str(score>=0.5).lower()} steps={len(rewards)} score={score:.3f} rewards={rewards_str}")
    return score

if __name__ == "__main__":
    if not GROQ_API_KEY:
        print("[ERROR] GROQ_API_KEY not set. Run: export GROQ_API_KEY='gsk_...'")
        exit(1)
    print(f"[MODEL] Using {MODEL}")
    tasks = ["easy_security_group", "medium_s3_policy", "hard_iam_vpc", "medium_lambda_iam", "hard_rds_cloudtrail"]
    scores = []
    for task in tasks:
        try:
            scores.append(run_task(task))
        except Exception as e:
            print(f"[ERROR] task={task} failed: {e}")
            scores.append(0.01)
    print(f"\nTask scores: {scores}")
    print(f"OVERALL: {sum(scores)/len(scores):.3f}")