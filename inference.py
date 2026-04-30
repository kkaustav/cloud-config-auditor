import os, json, re, requests
from groq import Groq

BASE_URL = "https://kkaustav-cloud-config-auditor.hf.space"
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
MODEL = "llama-3.3-70b-versatile"

client = Groq(api_key=GROQ_API_KEY)

SYSTEM_PROMPT = """You are an expert AWS cloud security auditor.
Analyze the given AWS configuration and return ONLY valid JSON in this exact format:
{"findings": ["finding1", "finding2"], "severity": ["HIGH", "MEDIUM"], "recommendations": ["rec1", "rec2"], "config_patch": {"key": "value"}}
No markdown, no explanation, only the JSON object."""

def ask_llm(messages):
    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        temperature=0.1,
        max_tokens=1024,
    )
    return response.choices[0].message.content.strip()

def parse_json(text):
    text = text.strip()
    # Remove markdown code blocks if present
    text = re.sub(r'^```(?:json)?\s*', '', text)
    text = re.sub(r'\s*```$', '', text)
    try:
        return json.loads(text)
    except:
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if m:
            return json.loads(m.group())
        raise ValueError(f"No JSON found in: {text[:200]}")

def run_task(task):
    print(f"\n[START] task={task} env=aws-security-auditor model={MODEL}")
    
    # Reset and get initial observation
    resp = requests.post(f"{BASE_URL}/reset?task={task}", timeout=30)
    obs = resp.json().get("observation", "")
    
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Audit this AWS configuration:\n{obs}"}
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
        
        action_str = json.dumps(parsed)
        
        try:
            step_resp = requests.post(
                f"{BASE_URL}/step",
                json={"action": action_str},
                timeout=30
            ).json()
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
        
        # Feed the environment's feedback back to the model for next step
        env_feedback = step_resp.get("observation", "")
        if env_feedback:
            messages.append({"role": "assistant", "content": action_str})
            messages.append({"role": "user", "content": f"The environment responded: {env_feedback}\nRefine your audit JSON."})
    
    success = score >= 0.5
    rewards_str = ",".join(str(r) for r in rewards)
    print(f"[END] task={task} success={str(success).lower()} steps={len(rewards)} score={score:.3f} rewards={rewards_str}")
    return score

if __name__ == "__main__":
    if not GROQ_API_KEY:
        print("[ERROR] GROQ_API_KEY is not set. Run: export GROQ_API_KEY='gsk_...'")
        exit(1)
    
    print(f"[MODEL] Using {MODEL}")
    
    tasks = [
        "easy_security_group",
        "medium_s3_policy",
        "hard_iam_vpc",
        "medium_lambda_iam",
        "hard_rds_cloudtrail",
    ]
    
    scores = []
    for task in tasks:
        try:
            s = run_task(task)
            scores.append(s)
        except Exception as e:
            print(f"[ERROR] task={task} failed: {e}")
            scores.append(0.01)
    
    print(f"\nTask scores: {scores}")
    overall = sum(scores) / len(scores) if scores else 0
    print(f"OVERALL: {overall:.3f}")
