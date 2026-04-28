import os
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="AWS Security Auditor")

model = None
tokenizer = None

def load_model():
    global model, tokenizer
    if model is None:
        from unsloth import FastLanguageModel
        model, tokenizer = FastLanguageModel.from_pretrained(
            "kkaustav/aws-security-auditor-lora",
            max_seq_length=2048,
            dtype=None,
            load_in_4bit=True,
        )
        FastLanguageModel.for_inference(model)
    return model, tokenizer

class AuditRequest(BaseModel):
    config: str

@app.get("/health")
def health():
    return {"status": "healthy", "environment": "aws-security-auditor", "version": "1.0.0"}

@app.post("/audit")
def audit(request: AuditRequest):
    m, t = load_model()
    prompt = f"<|im_start|>user\nAudit this AWS config: {request.config}<|im_end|>\n<|im_start|>assistant\n"
    inputs = t(prompt, return_tensors="pt").to("cuda")
    outputs = m.generate(**inputs, max_new_tokens=200)
    response = t.decode(outputs[0], skip_special_tokens=True)
    result = response.split("assistant")[-1].strip()
    return {"audit_result": result, "config": request.config}