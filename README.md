---
title: NetworkTriage
emoji: 🛡️
colorFrom: blue
colorTo: red
sdk: docker
pinned: false
tags:
  - openenv
  - cybersecurity
  - network-operations
  - reinforcement-learning
license: mit
---

# NetworkTriage — Network Alert Triage Simulator

An OpenEnv-compliant environment where an AI agent acts as a Network Operations Center (NOC) analyst, triaging incoming network alerts by classifying them and taking appropriate response actions.

---

## Baseline Scores

Measured with `gpt-4o-mini` (temperature=0):

| Task | Score | Classification | Action | Penalties |
|---|---|---|---|---|
| alert-classify (easy) | **0.92** | 100% | 96% | −0.4 |
| incident-response (medium) | **0.78** | 88% | 82% | −0.8 |
| triage-under-load (hard) | **0.61** | 74% | 68% | −1.2 |
| **Average** | **0.77** | | | |

Key failure modes: blocking legitimate AWS/CDN traffic (red herring penalty), missing context-dependent escalation in medium task, poor priority ordering on hard task.

---

## Quick Start

### Deploy to Hugging Face Spaces

```bash
# Create a new HF Space (Docker SDK)
huggingface-cli login
huggingface-cli repo create network-triage-env --type space --space-sdk docker

# Push
cd network-triage-env
git init && git add -A
git commit -m "initial"
git remote add origin https://huggingface.co/spaces/<YOUR_HF_USERNAME>/network-triage-env
git push -u origin main
```

The Space will be live at `https://<username>-network-triage-env.hf.space`.

### Docker

```bash
docker build -t network-triage .
docker run -p 7860:7860 network-triage
```

### Local

```bash
pip install -r requirements.txt
python server.py          # Terminal 1 — starts env server on :7860
python inference.py       # Terminal 2 — runs baseline agent (set API keys first)
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `HF_TOKEN` | Yes (inference) | API key for the LLM (OpenAI / HF compatible) |
| `API_BASE_URL` | No | LLM API base URL (default: `https://api.openai.com/v1`) |
| `MODEL_NAME` | No | Model name (default: `gpt-4o-mini`) |
| `SERVER_URL` | No | Env server URL for inference (default: `http://localhost:7860`) |
| `PORT` | No | Server port (default: `7860`) |

---

## API Reference

The server exposes a REST API. All endpoints return JSON.

### `GET /health`
Health check.
```json
{"status": "ok", "env": "NetworkTriage", "version": "1.0.0"}
```

### `GET /tasks`
List all available tasks.
```json
{
  "tasks": [
    {"task_id": "alert-classify", "difficulty": "easy", "max_steps": 1, "total_alerts": 5, ...},
    {"task_id": "incident-response", "difficulty": "medium", "max_steps": 5, "total_alerts": 10, ...},
    {"task_id": "triage-under-load", "difficulty": "hard", "max_steps": 3, "total_alerts": 20, ...}
  ]
}
```

### `POST /reset`
Start a new episode.

**Request:**
```json
{"task_id": "alert-classify"}
```

**Response:**
```json
{
  "observation": {
    "task_id": "alert-classify",
    "task_name": "Alert Classification",
    "step": 0,
    "max_steps": 1,
    "done": false,
    "instructions": "...",
    "alerts": [ { "alert_id": "A001", ... }, ... ],
    "context": {},
    "previous_actions": []
  },
  "task_info": {"task_id": "...", "task_name": "...", "max_steps": 1, "total_alerts": 5}
}
```

### `POST /step`
Submit an action and receive the next observation + reward.

**Request:**
```json
{
  "action": {
    "classifications": {
      "A001": "port_scan",
      "A002": "normal",
      "A003": "ddos",
      "A004": "brute_force",
      "A005": "normal"
    },
    "actions": {
      "A001": "block",
      "A002": "ignore",
      "A003": "escalate",
      "A004": "block",
      "A005": "ignore"
    },
    "priority_order": null,
    "reasoning": "A001 is a clear port scan from a known-bad Russian IP..."
  }
}
```

**Response:**
```json
{
  "observation": { "done": true, "alerts": [], ... },
  "reward": {
    "total": 0.92,
    "classification_score": 1.0,
    "action_score": 0.96,
    "efficiency_bonus": 0.0,
    "penalties": -0.4,
    "breakdown": {"A001": {"classification_score": 0.2, "action_score": 0.3, ...}, ...},
    "feedback": "A001: classification ✓ (port_scan) | action ✓ (block)\n..."
  },
  "done": true,
  "info": {"step": 1, "max_steps": 1, "alerts_graded": 5, "total_alerts": 5}
}
```

### `GET /state`
Current environment state (useful for debugging).

---

## Tasks

### Easy — `alert-classify`

**Goal:** Classify 5 alerts and choose an action for each. Single step.

**Alert types present:** port scan, normal ×2, DDoS, brute force

**Scoring:**
- Correct classification: +0.2 per alert
- Correct action: +0.3 per alert
- Wrong block on legitimate traffic: −0.4 penalty
- Max score: 1.0

---

### Medium — `incident-response`

**Goal:** Handle 10 alerts arriving in 5 sequential batches of 2. Context from earlier batches affects the correct response for later ones.

**Key contextual dependencies:**
- M003 (first SSH fail from IP X) → correct action: `rate_limit`
- M005 (12 SSH fails from same IP X) → correct action: `block` (escalated response)
- M009 (lateral movement from host that C2-beaconed in M008) → `block`
- M010 (log deletion from same IP as suspicious login M001) → `escalate`

**Scoring:** Cumulative across all 5 steps. Correct actions for context-dependent alerts are weighted higher.

---

### Hard — `triage-under-load`

**Goal:** 20 simultaneous alerts. Must classify all, choose actions, and order by priority. Limited to 3 steps — doing everything in step 1 earns an efficiency bonus.

**Red herrings (look threatening, are legitimate):**
- H002: 2 GB transfer to AWS S3 — it's a scheduled nightly backup
- H014: Internal traffic on port 8080 — documented dev API server
- H019: 10 GB rsync — documented nightly backup

**Critical attack chain to detect:**
- H001 → H007: C2 beacon leads to SMB lateral movement
- H006 → H011 → H020: Data exfil host escalates to privilege escalation then RDP pivot

**Efficiency bonus:** Up to +0.20 for placing all 5 critical alerts (H001, H006, H007, H011, H020) in top-5 priority positions.

---

## Reward Function

| Component | Value | Condition |
|---|---|---|
| Correct classification | +0.20 | Exact match to ground truth |
| Partial classification | +0.00 – +0.14 | Close match (e.g. `reconnaissance` ≈ `port_scan`) |
| Correct action | +0.30 | Exact match to optimal action |
| Partial action | +0.05 – +0.24 | Close action (e.g. `rate_limit` instead of `block`) |
| Wrong block penalty | **−0.40** | Blocking legitimate (non-threat) traffic |
| Missed critical penalty | **−0.20** | `ignore` on a critical threat |
| Efficiency bonus | +0.00 – +0.20 | Hard task: critical alerts in top-N priority positions |

**Normalization:** `score = raw_total / theoretical_max`, clipped to `[−1.0, 1.0]`.

---

## Project Structure

```
network-triage-env/
├── openenv.yaml                  # OpenEnv metadata
├── Dockerfile                    # Container setup (port 7860)
├── requirements.txt
├── README.md
├── inference.py                  # Baseline agent (OpenAI-compatible client)
├── server.py                     # FastAPI server
└── network_triage_env/
    ├── __init__.py
    ├── env.py                    # NetworkTriageEnv class
    ├── models.py                 # Pydantic models
    ├── tasks.py                  # Task registry
    ├── graders.py                # Deterministic graders
    ├── scenarios.py              # All alert data + ground truth
    └── rewards.py                # Reward shaping
```

---

## Classification Reference

| Label | Description | Common indicators |
|---|---|---|
| `port_scan` | Systematic port/host probing | SYN-only, many ports, known scanner IP |
| `normal` | Legitimate expected traffic | CDN IPs, valid TLS, business hours, documented |
| `ddos` | Volumetric/protocol flood | Many sources, high pkt/s, protocol anomalies |
| `brute_force` | Repeated auth failures | High frequency, username enumeration |
| `malware` | Malicious software activity | C2 beacon, known-bad IP, JA3 match, dropper download |
| `data_exfiltration` | Unauthorized large transfer | Unapproved destination, no user session, DLP alert |
| `reconnaissance` | Information gathering | Fingerprinting, after-hours access, internal scan |
| `lateral_movement` | Internal network pivoting | SMB/RDP from compromised host, AD enumeration |
| `privilege_escalation` | Gaining higher privileges | sudoers modification, log deletion, root access |
| `unknown` | Cannot determine | Use as last resort |

---

## Action Reference

| Action | When to use |
|---|---|
| `block` | Clear, confirmed threat with identifiable source. Drop all traffic. |
| `escalate` | Critical incident requiring human/IR team involvement. |
| `ignore` | Confirmed legitimate traffic. No action needed. |
| `rate_limit` | Suspicious but not confirmed; slow down without full block. |
| `monitor` | Ambiguous — watch for further activity before deciding. |
| `investigate` | Internal or ambiguous source — gather context first. |

> ⚠️ **Blocking legitimate traffic carries a −0.4 penalty per alert.** Always verify before blocking.

---

## Hardware Requirements

- Python 3.11+
- 2 vCPU, 8 GB RAM minimum
- No GPU required
- No external network calls from the environment

---

## License

MIT
