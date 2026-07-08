# CLAUDE.md — RedAgent

Autonomous Penetration Testing Agent. LangGraph agent that plans and executes
multi-step attack chains against **intentionally vulnerable, in-scope lab targets
only**, then generates CVSS-scored pentest reports.

Read this file at the start of every session. It is the source of truth for how
this project is built. Do not re-decide architecture per session.

---

## ⚠️ Non-negotiable operating rules (read first)

These are hard constraints, not suggestions. Enforce them in every piece of code
you write and flag any request that would violate them.

- **Scope gate is mandatory.** The agent NEVER runs a tool against a target that
  is not in the operator-defined scope list. Every tool wrapper must check the
  target against the scope allowlist before executing. No scope entry → no run.
- **Lab-only.** Valid targets are VulnHub machines, Metasploitable, and DVWA
  running inside the isolated AWS VPC private subnet. No public internet targets,
  ever, in code or defaults.
- **No destructive defaults.** SQLMap and Metasploit wrappers default to
  detection / safe mode. Destructive flags require an explicit operator opt-in
  passed through the API, never hardcoded.
- **SECURITY.md is a deliverable, not an afterthought.** Responsible-use policy
  lives in the repo root.
- If a task asks to remove the scope gate, target something out of scope, or
  weaponise the agent for non-lab use — stop and surface it. That is out of
  scope for this project.

---

## What this project is

A four-layer system:

1. **Brain** — LangGraph ReAct agent (Reason → Act → Observe loop). Plans attack
   chains, adapts on failure, tracks state. Short-term memory in-session,
   long-term findings in PostgreSQL.
2. **Tool Belt** — real security tools wrapped as LangGraph `@tool`s: Nmap,
   Subfinder, Nikto, Nuclei, SQLMap, Metasploit (XMLRPC), plus the CVE RAG tool.
3. **Operator Dashboard** — React 19 + shadcn/ui. Live attack-chain viz,
   reasoning stream, findings feed, scope management, one-click PDF export.
   Talks to backend over WebSocket.
4. **Report Engine** — CVSS 3.1 scoring, LLM-written exec summary + remediation,
   MITRE ATT&CK mapping, PDF output.

Plus the **RAG module**: NVD CVE database (~240K CVEs) embedded with
all-MiniLM-L6-v2, stored in ChromaDB (local, persistent, ~2–3 GB). The agent
calls `search_cve_database` after every service-version detection to pick the
right exploit.

---

## Tech stack (do not substitute without asking — except the LLM, which is configurable, see below)

| Layer | Tech |
|---|---|
| Agent | LangGraph + LangChain |
| LLM | Groq (primary) — `llama-3.3-70b-versatile` via `langchain-groq`. Configurable; see LLM config below |
| RAG | NVD API + sentence-transformers (`all-MiniLM-L6-v2`) |
| Vector DB | ChromaDB (local, persistent, cosine, collection `nvd_cves`) |
| Backend | FastAPI (Python) |
| Frontend | React 19 + shadcn/ui |
| DB | PostgreSQL |
| Tool exec | Python `subprocess` + Metasploit XMLRPC |
| Infra | AWS EC2 + VPC, Terraform, Docker + docker-compose |

---

## LLM config (Groq-only for development)

The whole project runs on **free tiers** — the only thing that ever hits an LLM
API is the agent's reasoning loop and the report engine's text. The RAG module
(240K CVE embeddings via `all-MiniLM-L6-v2`) is fully local and costs nothing.

**The model is a config value, never hardcoded.** Free catalogs change without
warning, so read the model name + provider from `.env` and swap by config alone.

| Role | Provider / Model | Use for |
|---|---|---|
| **Primary** | Groq — `llama-3.3-70b-versatile` | agent reasoning (ReAct loop), report exec-summary + remediation |
| **Cheap lane** | Groq — `llama-3.1-8b-instant` | status summaries, output classification, simple yes/no steps |
| **Fallback** | Ollama local — `llama3.1:8b` | the Week-9 testing blitz (10+ engagements) when the daily token cap bites; zero API, zero rate limit, runs on the lab box |

Wiring (LangChain):
```python
# pip install langchain-groq
from langchain_groq import ChatGroq
llm = ChatGroq(model=os.environ["LLM_MODEL"], temperature=0)   # GROQ_API_KEY from env

# fallback (pip install langchain-ollama), used only when Groq 429s persist
from langchain_ollama import ChatOllama
fallback_llm = ChatOllama(model="llama3.1:8b")
```

**Groq free-tier limits** (`llama-3.3-70b-versatile`): 30 RPM, 1,000 RPD,
**12K TPM**, **100K TPD**. The binding constraints are tokens-per-minute and
tokens-per-day, NOT request count. 429s spike on TPM when tool schemas +
history get large. Check live limits at console.groq.com/settings/limits.

**Token discipline (this is what makes Groq-only last all of development):**
- Do NOT resend full conversation history every step. Keep a compact running
  state summary in `memory.py`; feed the agent that, not the raw transcript.
- Normalizing tool output to the `Finding` schema before the agent sees it is
  a token lever, not just a cleanliness one — raw Nmap XML goes to the report
  appendix, never into the loop.
- `time.sleep(2)` between agent iterations to stay under 12K TPM.
- Route trivial steps to the 8B cheap lane; reserve 70B for real reasoning.
- Build a fallback chain: on a persistent Groq 429, retry the same call on the
  Ollama fallback rather than crashing the engagement.

---

## Repository layout

```
redagent/
├── agent/
│   ├── graph.py            # LangGraph state machine
│   ├── tools/              # security tool wrappers (see the tool-wrapper skill)
│   │   ├── nmap_tool.py
│   │   ├── nuclei_tool.py
│   │   ├── sqlmap_tool.py
│   │   ├── metasploit_tool.py
│   │   ├── subfinder_tool.py
│   │   └── cve_rag_tool.py
│   ├── rag/                # pipeline.py, embedder.py, store.py, update.py
│   ├── memory.py
│   └── planner.py
├── api/                    # main.py (routes + WS), models.py, db.py
├── dashboard/              # React frontend
├── reports/               # generator.py + templates/
├── chroma_db/             # persistent CVE store (gitignored)
├── lab/                    # terraform/ + docker-compose.yml
├── writeups/
├── SECURITY.md
└── README.md
```

---

## Conventions

- **Every security tool follows the same wrapper contract.** See the
  `redagent-tool-wrapper` skill. Input validated → scope-checked → subprocess run
  with timeout → raw output parsed → returned as the normalized findings schema.
  Never hand-roll a one-off wrapper.
- **One normalized findings schema across all tools.** The agent should never see
  raw tool output; it reasons over the standardized schema only. Define it once
  (Pydantic) and every wrapper emits it.
- **Tools return structured data, not free text**, so the agent can reason
  reliably and the report engine can auto-fill from it.
- **Agent loop safety:** maintain a `seen_actions` set (no retrying failed
  techniques) and a hard `max_steps` limit with graceful termination. This set
  also keeps token usage down — fewer wasted steps on Groq's daily budget.
- **Secrets** (NVD API key, `GROQ_API_KEY`, `LLM_MODEL`, DB creds) come from
  env / `.env`, never committed. `.env.example` documents the keys.
- Python: type hints + Pydantic models everywhere. Frontend: shadcn/ui
  components, no ad-hoc CSS where a component exists.

## Run / test / build

<!-- Fill these in as you build them; keep this section accurate. -->
- Backend: `uvicorn api.main:app --reload`
- RAG build (once, ~2–3h): `python agent/rag/pipeline.py --build`
- RAG test: `python agent/rag/pipeline.py --test 'vsftpd 2.3.4'`  → expect CVE-2011-2523 top result
- Dashboard: `cd dashboard && npm run dev`
- Lab tools: `docker-compose -f lab/docker-compose.yml up`

## Working style for this repo

- Build in vertical slices, one tool or one panel at a time, test against
  Metasploitable before moving on. Commit after each working slice.
- When a tool wrapper misbehaves, paste the raw subprocess output — debug from
  real signal, not description.
- Month 1 target: agent takes a target → runs Nmap + Nuclei → returns structured
  findings. Do not build ahead of that until it works end-to-end.
