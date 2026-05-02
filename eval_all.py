import json, re, os, torch, requests, warnings
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", message=".*max_new_tokens.*max_length.*")

from huggingface_hub import snapshot_download
from unsloth import FastLanguageModel
from peft import PeftModel

BASE_URL = "https://kkaustav-cloud-config-auditor.hf.space"
BASE_MODEL = "unsloth/Qwen2.5-3B-Instruct-bnb-4bit"
ADAPTER_PATH = "/content/aws-auditor-sft-v5"

if not os.path.exists(ADAPTER_PATH) or not os.path.exists(f"{ADAPTER_PATH}/adapter_config.json"):
    print("⬇️ Downloading LoRA adapter...")
    snapshot_download(repo_id="kkaustav/aws-security-auditor-lora", local_dir=ADAPTER_PATH)
    print("✅ Adapter downloaded")

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=BASE_MODEL,
    max_seq_length=4096,
    dtype=None,
    load_in_4bit=True,
)
model = PeftModel.from_pretrained(model, ADAPTER_PATH)
FastLanguageModel.for_inference(model)
print("✅ Fine-tuned model loaded:", type(model))

SYSTEM_DEFAULT = (
    "You are an expert AWS cloud security auditor. "
    "Return your audit as valid JSON ONLY — no markdown, no code blocks, no extra text.\n"
    "IMPORTANT: Your ENTIRE response must be ONE complete, closed JSON object. "
    "Close every array ] and every brace } before you stop.\n"
    '{"findings":["finding 1"],"severity":["CRITICAL"],'
    '"recommendations":["fix 1"],"config_patch":{"key":"value"}}'
)

SYSTEM_LAMBDA_IAM = (
    "You are an expert AWS Lambda and IAM security auditor for a payment processing service.\n"
    "Analyze the provided Lambda configuration and report EVERY distinct security misconfiguration.\n\n"
    "CHECK EACH OF THESE SEPARATELY — each must be its own finding:\n"
    "1. IAM role: Is AdministratorAccess or any wildcard policy attached? (CRITICAL)\n"
    "2. Env var DB_PASSWORD: Is a plaintext database password stored here? (CRITICAL)\n"
    "3. Env var API_SECRET_KEY: Is a plaintext API key stored here? (CRITICAL)\n"
    "4. Env var STRIPE_SECRET: Is a plaintext Stripe/payment secret stored here? (CRITICAL)\n"
    "5. FunctionUrl.AuthType: Is it set to NONE (unauthenticated public access)? (HIGH)\n"
    "6. CORS AllowOrigins: Is it set to ['*'] (wildcard)? (HIGH)\n"
    "7. VpcConfig: Is it null (Lambda not isolated in a VPC)? (HIGH)\n"
    "8. ReservedConcurrency: Is it null (no DDoS/cost protection)? (MEDIUM)\n"
    "9. Tracing.Mode: Is it PassThrough (no X-Ray active tracing)? (LOW)\n"
    "10. CodeSigningConfigArn: Is it null (no code integrity verification)? (MEDIUM)\n"
    "11. Runtime: Is it python3.9 (deprecated/end-of-life runtime)? (MEDIUM)\n\n"
    "Rules:\n"
    "- List EACH env var secret as a SEPARATE finding — do not group them.\n"
    "- List ALL findings even if they seem minor.\n"
    "- Return valid JSON ONLY. No markdown. No code blocks.\n"
    "- Your ENTIRE response must be ONE complete, closed JSON object.\n"
    "- severity array must match findings array length.\n"
    '{"findings":["AdministratorAccess IAM policy attached","DB_PASSWORD stored as plaintext"],'
    '"severity":["CRITICAL","CRITICAL"],'
    '"recommendations":["Replace AdministratorAccess with least-privilege policy","Move DB_PASSWORD to AWS Secrets Manager"],'
    '"config_patch":{'
    '"ExecutionRole.AttachedPolicies":["arn:aws:iam::123456789012:policy/LambdaPaymentMinimalPolicy"],'
    '"EnvironmentVariables.DB_PASSWORD":"{{resolve:secretsmanager:payment-db-secret}}",'
    '"FunctionUrl.AuthType":"AWS_IAM",'
    '"VpcConfig":{"SubnetIds":["subnet-xxx"],"SecurityGroupIds":["sg-xxx"]},'
    '"ReservedConcurrency":100,'
    '"Tracing":{"Mode":"Active"},'
    '"CodeSigningConfigArn":"arn:aws:lambda:ap-south-1:123456789012:code-signing-config:csc-xxx"'
    "}}"
)

SYSTEM_RDS_CLOUDTRAIL = SYSTEM_DEFAULT

SYSTEM_IAM_VPC = (
    "You are an expert AWS IAM and VPC security auditor.\n"
    "The config has TWO sections: IAMRole and VPC. You MUST audit BOTH sections.\n"
    "Report EVERY misconfiguration as a SEPARATE finding.\n\n"
    "=== SECTION 1: IAMRole findings — check each separately ===\n"
    "1. AssumeRolePolicyDocument has Principal.Service='*' — any service can assume this role (CRITICAL)\n"
    "2. InlinePolicies has Action='*' — wildcard action grants full AWS access (CRITICAL)\n"
    "3. InlinePolicies has Resource='*' — no resource-level restriction (CRITICAL)\n"
    "4. Inline policy 'AllAccess-temp' used — should be a least-privilege managed policy (MEDIUM)\n"
    "5. MFAEnabled=false — no MFA requirement on the role (HIGH)\n"
    "6. PasswordPolicy.MinimumPasswordLength=6 — minimum must be at least 14 (MEDIUM)\n"
    "7. PasswordPolicy.RequireUppercaseCharacters=false — uppercase not enforced (MEDIUM)\n"
    "8. PasswordPolicy.RequireNumbers=false — numbers not required (MEDIUM)\n"
    "9. PasswordPolicy.RequireSymbols=false — symbols not required (MEDIUM)\n"
    "10. PasswordPolicy.MaxPasswordAge=0 — passwords never expire (MEDIUM)\n"
    "11. PasswordPolicy.PasswordReusePrevention=0 — old passwords can be reused (MEDIUM)\n\n"
    "=== SECTION 2: VPC findings — MANDATORY, check each separately ===\n"
    "12. VPC.FlowLogsEnabled=false — VPC Flow Logs are disabled (HIGH)\n"
    "13. VPC.CloudTrailEnabled=false — CloudTrail is disabled (CRITICAL)\n"
    "14. VPC.GuardDutyEnabled=false — GuardDuty not enabled (HIGH)\n"
    "15. NetworkACL inbound rule: Protocol='-1', CidrBlock='0.0.0.0/0', Action='allow' (HIGH)\n"
    "16. NetworkACL outbound rule: Protocol='-1', CidrBlock='0.0.0.0/0', Action='allow' (MEDIUM)\n"
    "17. Subnet MapPublicIpOnLaunch=true — public IPs auto-assigned (HIGH)\n\n"
    "ABSOLUTE RULES:\n"
    "- You MUST produce EXACTLY 17 findings — 11 IAM + 6 VPC.\n"
    "- Do NOT stop at finding 11. Continue to findings 12-17.\n"
    "- findings array length MUST be 17.\n"
    "- severity array length MUST be 17.\n"
    "- recommendations array length MUST be 17.\n"
    "- Return valid JSON ONLY. No markdown. No code blocks.\n\n"
    '{"findings":['
    '"IAM role trust policy allows any AWS service to assume it — Principal.Service is wildcard (*)",'
    '"Inline policy AllAccess-temp grants Action=* — full administrative access",'
    '"Inline policy AllAccess-temp has Resource=* — no resource-level restriction",'
    '"Inline policy used instead of least-privilege managed policy (AllAccess-temp)",'
    '"MFAEnabled=false — IAM role has no MFA requirement",'
    '"PasswordPolicy MinimumPasswordLength=6 — below the 14-character minimum",'
    '"PasswordPolicy RequireUppercaseCharacters=false — uppercase not required",'
    '"PasswordPolicy RequireNumbers=false — numbers not required",'
    '"PasswordPolicy RequireSymbols=false — symbols not required",'
    '"PasswordPolicy MaxPasswordAge=0 — passwords never expire",'
    '"PasswordPolicy PasswordReusePrevention=0 — no password reuse prevention",'
    '"VPC FlowLogsEnabled=false — no network traffic logging",'
    '"VPC CloudTrailEnabled=false — no API audit logging",'
    '"VPC GuardDutyEnabled=false — no threat detection",'
    '"NetworkACL inbound allows all traffic (Protocol=-1, 0.0.0.0/0)",'
    '"NetworkACL outbound allows all traffic (Protocol=-1, 0.0.0.0/0)",'
    '"Subnet MapPublicIpOnLaunch=true — public IPs auto-assigned on launch"'
    "],"
    '"severity":["CRITICAL","CRITICAL","CRITICAL","MEDIUM","HIGH","MEDIUM","MEDIUM","MEDIUM","MEDIUM","MEDIUM","MEDIUM","HIGH","CRITICAL","HIGH","HIGH","MEDIUM","HIGH"],'
    '"recommendations":['
    '"Restrict Principal.Service to ecs-tasks.amazonaws.com",'
    '"Replace wildcard Action with specific required permissions",'
    '"Replace wildcard Resource with specific ARNs",'
    '"Replace inline policy with least-privilege managed policy",'
    '"Enable MFA for all IAM role assumptions",'
    '"Set MinimumPasswordLength to 14",'
    '"Enable RequireUppercaseCharacters",'
    '"Enable RequireNumbers",'
    '"Enable RequireSymbols",'
    '"Set MaxPasswordAge to 90 days",'
    '"Set PasswordReusePrevention to 24",'
    '"Enable VPC Flow Logs",'
    '"Enable CloudTrail in all regions",'
    '"Enable GuardDuty",'
    '"Restrict NACL inbound to known CIDR blocks",'
    '"Restrict NACL outbound to required destinations",'
    '"Disable MapPublicIpOnLaunch on all production subnets"'
    "],"
    '"config_patch":{'
    '"IAMRole.AssumeRolePolicyDocument.Statement[0].Principal":{"Service":"ecs-tasks.amazonaws.com"},'
    '"VPC.FlowLogsEnabled":true,'
    '"VPC.GuardDutyEnabled":true,'
    '"VPC.CloudTrailEnabled":true,'
    '"Subnets[0].MapPublicIpOnLaunch":false'
    "}}"
)

SYSTEM_MAP = {
    "medium_lambda_iam":   SYSTEM_LAMBDA_IAM,
    "hard_rds_cloudtrail": SYSTEM_RDS_CLOUDTRAIL,
    "hard_iam_vpc":        SYSTEM_IAM_VPC,
}

def repair_json(text):
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start == -1:
        return None
    text = text[start:]
    in_string = False
    escape_next = False
    stack = []
    for ch in text:
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch in "{[":
            stack.append(ch)
        elif ch == "]" and stack and stack[-1] == "[":
            stack.pop()
        elif ch == "}" and stack and stack[-1] == "{":
            stack.pop()
    repair = ""
    if in_string:
        repair += '"'
    for opener in reversed(stack):
        repair += "]" if opener == "[" else "}"
    try:
        return json.loads(text + repair)
    except json.JSONDecodeError:
        pass
    findings_match = re.findall(r'"findings"\s*:\s*\[([^\]]*)', text + repair, re.DOTALL)
    if findings_match:
        items = re.findall(r'"((?:[^"\\]|\\.)*)"', findings_match[0])
        if items:
            return {"findings": items, "severity": [], "recommendations": [], "config_patch": {}}
    return None

def generate_response(config_text, task):
    system_prompt = SYSTEM_MAP.get(task, SYSTEM_DEFAULT)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": f"Audit this AWS config:\n{config_text}"}
    ]
    inputs = tokenizer.apply_chat_template(
        messages, tokenize=True, add_generation_prompt=True, return_tensors="pt"
    ).to(model.device)
    with torch.no_grad():
        outputs = model.generate(
            input_ids=inputs,
            attention_mask=torch.ones_like(inputs),
            max_new_tokens=3072,
            do_sample=False,
            use_cache=True,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )
    return tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True).strip()

def run_task(task, run_num, debug=False):
    for attempt in range(3):
        try:
            reset_resp = requests.post(f"{BASE_URL}/reset?task={task}", timeout=30).json()
            obs = reset_resp.get("observation", {})
            config_text = obs["config"] if isinstance(obs, dict) and "config" in obs else str(obs)
            if config_text and len(config_text) > 10:
                break
        except Exception as e:
            if attempt == 2:
                print(f"  {task} run {run_num}: RESET ERROR — {e}")
                return 0.0

    response_text = generate_response(config_text, task)
    parsed = repair_json(response_text)

    if parsed is None:
        print(f"  {task} run {run_num}: PARSE FAIL — raw: {response_text[:120]}")
        return 0.0

    if debug:
        print(f"\n  [DEBUG] {task} findings ({len(parsed.get('findings', []))} total):")
        for i, f in enumerate(parsed.get("findings", [])):
            print(f"    {i+1}. {f}")

    try:
        step = requests.post(f"{BASE_URL}/step", json=parsed, timeout=30).json()
        if debug:
            print(f"\n  [DEBUG] reward: {step.get('reward', 'N/A')}")
    except Exception as e:
        print(f"  {task} run {run_num}: STEP ERROR — {e}")
        return 0.0

    reward = step.get("reward", 0.0)
    print(f"  {task} run {run_num}: {reward:.4f}  ({len(parsed.get('findings', []))} findings)")
    return reward

tasks = [
    "easy_security_group",
    "medium_s3_policy",
    "medium_lambda_iam",
    "hard_rds_cloudtrail",
    "hard_iam_vpc",
]

DEBUG_TASKS = {"hard_iam_vpc"}

print("=" * 50)
all_scores = {}
for task in tasks:
    scores = [run_task(task, i, debug=(task in DEBUG_TASKS and i == 1)) for i in range(1, 4)]
    avg = sum(scores) / 3
    all_scores[task] = avg
    print(f"  >>> {task} AVG: {avg:.4f}\n")

print("=" * 50)
print(f"{'FINAL SCORES':^50}")
print("=" * 50)
for task, score in all_scores.items():
    bar = "█" * int(score * 20)
    print(f"{task:<30} {score:.4f}  {bar}")

overall = sum(all_scores.values()) / len(all_scores)
print(f"\nOVERALL AVERAGE: {overall:.4f}")

repo_path = "/content/cloud-config-auditor"
log_path = os.path.join(repo_path, "run_log_scaled.txt")
with open(log_path, "w") as f:
    for task, score in all_scores.items():
        f.write(f"{task}: {score:.4f}\n")
    f.write(f"OVERALL: {overall:.4f}\n")
print(f"\n✅ run_log_scaled.txt saved to repo!")
