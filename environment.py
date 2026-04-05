import uuid, json
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Query
from pydantic import BaseModel, Field
from tasks import TASKS, TASK_SEQUENCE, grade_easy, grade_medium, grade_hard

app = FastAPI(title="AWS Security Auditor", version="1.0.0")

class AuditAction(BaseModel):
    findings: List[str] = Field(...)
    severity: List[str] = Field(default=[])
    recommendations: List[str] = Field(default=[])
    config_patch: dict = Field(default={})

class AuditObservation(BaseModel):
    config: str
    task_description: str
    step: int
    max_steps: int
    last_reward: float
    feedback: Optional[str]
    task_name: str
    difficulty: str

class StepResult(BaseModel):
    observation: AuditObservation
    reward: float
    done: bool
    info: Dict[str, Any] = {}

class EpisodeState(BaseModel):
    episode_id: str
    step: int
    task_name: str
    difficulty: str
    total_reward: float
    best_reward: float
    done: bool

_episode: Dict[str, Any] = {"id": None, "task": None, "step": 0, "done": False, "rewards": [], "last_reward": 0.0}

def _build_observation(task, step, reward, feedback):
    return AuditObservation(
        config=task["config"], task_description=task["description"],
        step=step, max_steps=task["max_steps"],
        last_reward=reward, feedback=feedback,
        task_name=task["name"], difficulty=task["difficulty"]
    )

def _feedback_message(reward, task_name):
    if reward == 0.0:   return "No issues identified yet."
    elif reward < 0.35: return f"Score {reward:.2f} — several critical misconfigurations missing."
    elif reward < 0.60: return f"Score {reward:.2f} — good progress. Review encryption and logging."
    elif reward < 0.85: return f"Score {reward:.2f} — almost complete. Check severity labels."
    else:               return f"Score {reward:.2f} — excellent audit!"

@app.post("/reset", response_model=StepResult)
async def reset(task: str = Query(default="easy_security_group")):
    global _episode
    task_name = task if task in TASKS else TASK_SEQUENCE[0]
    task_data = TASKS[task_name]
    _episode  = {"id": str(uuid.uuid4()), "task": task_data, "step": 0, "done": False, "rewards": [], "last_reward": 0.0}
    obs = _build_observation(task_data, 0, 0.0, None)
    return StepResult(observation=obs, reward=0.0, done=False, info={"task": task_name})

@app.post("/step", response_model=StepResult)
async def step(action: AuditAction):
    global _episode
    if not _episode["task"] or _episode["done"]:
        task_data = TASKS[TASK_SEQUENCE[0]]
        obs = _build_observation(task_data, 0, 0.0, "Call /reset first.")
        return StepResult(observation=obs, reward=0.0, done=True, info={"error": "not started"})
    _episode["step"] += 1
    task_data = _episode["task"]
    cur_step  = _episode["step"]
    if task_data["name"] == "easy_security_group":
        reward, breakdown = grade_easy(action.findings, action.severity, action.recommendations, action.config_patch)
    elif task_data["name"] == "medium_s3_policy":
        reward, breakdown = grade_medium(action.findings, action.severity, action.recommendations, action.config_patch)
    else:
        reward, breakdown = grade_hard(action.findings, action.severity, action.recommendations, action.config_patch)
    _episode["rewards"].append(reward)
    _episode["last_reward"] = reward
    done = (reward >= 0.85) or (cur_step >= task_data["max_steps"])
    _episode["done"] = done
    obs = _build_observation(task_data, cur_step, reward, _feedback_message(reward, task_data["name"]))
    return StepResult(observation=obs, reward=reward, done=done, info={"breakdown": breakdown})

@app.get("/state", response_model=EpisodeState)
async def state():
    rewards = _episode.get("rewards", [])
    return EpisodeState(
        episode_id=_episode.get("id") or "not-started",
        step=_episode.get("step", 0),
        task_name=_episode["task"]["name"] if _episode["task"] else "none",
        difficulty=_episode["task"]["difficulty"] if _episode["task"] else "none",
        total_reward=sum(rewards), best_reward=max(rewards) if rewards else 0.0,
        done=_episode.get("done", False)
    )

@app.get("/health")
async def health():
    return {"status": "healthy", "environment": "aws-security-auditor", "version": "1.0.0"}

@app.get("/tasks")
async def list_tasks():
    return {"tasks": [{"name": t["name"], "difficulty": t["difficulty"], "max_steps": t["max_steps"]} for t in TASKS.values()]}

@app.get("/metadata")
async def metadata():
    return {
        "name": "aws-security-auditor",
        "description": "An OpenEnv-compatible RL environment for training AI agents to audit AWS cloud infrastructure configurations.",
        "version": "1.0.0",
        "tasks": list(TASKS.keys())
    }

@app.get("/schema")
async def schema():
    return {
        "action": {
            "type": "object",
            "properties": {
                "findings": {"type": "array", "items": {"type": "string"}},
                "severity": {"type": "array", "items": {"type": "string"}},
                "recommendations": {"type": "array", "items": {"type": "string"}},
                "config_patch": {"type": "object"}
            }
        },
        "observation": {
            "type": "object",
            "properties": {
                "config": {"type": "string"},
                "task_description": {"type": "string"},
                "step": {"type": "integer"},
                "max_steps": {"type": "integer"},
                "last_reward": {"type": "number"},
                "feedback": {"type": "string"},
                "task_name": {"type": "string"},
                "difficulty": {"type": "string"}
            }
        },
        "state": {
            "type": "object",
            "properties": {
                "episode_id": {"type": "string"},
                "step": {"type": "integer"},
                "task_name": {"type": "string"},
                "difficulty": {"type": "string"},
                "total_reward": {"type": "number"},
                "best_reward": {"type": "number"},
                "done": {"type": "boolean"}
            }
        }
    }

@app.post("/mcp")
async def mcp(request: dict):
    method = request.get("method", "")
    req_id = request.get("id", 1)
    if method == "tools/list":
        result = {"tools": [
            {"name": "reset", "description": "Reset environment and start a new episode"},
            {"name": "step",  "description": "Submit audit findings and get reward"},
            {"name": "state", "description": "Get current episode state"}
        ]}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "Use /reset, /step, /state endpoints directly."}]}
    else:
        result = {"message": "OpenEnv MCP interface ready"}
    return {"jsonrpc": "2.0", "id": req_id, "result": result}
