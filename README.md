# RedAgent — Autonomous Penetration Testing Agent

A LangGraph ReAct agent that plans and executes multi-step attack chains against
**intentionally vulnerable, in-scope lab targets only**, then generates
CVSS-3.1-scored pentest reports with MITRE ATT&CK mapping.

> ⚠️ **Lab-only.** Read [SECURITY.md](SECURITY.md) before running anything. RedAgent
> refuses any target that is not a private lab address on the operator allowlist.

## Architecture (four layers + RAG)

1. **Brain** — LangGraph ReAct loop (Reason → Act → Observe), adaptive replanning,
   short-term memory in-session + long-term findings in PostgreSQL.
2. **Tool Belt** — Nmap, Subfinder, Nikto, Nuclei, SQLMap, Metasploit (XMLRPC),
   each wrapped to one scope-gated contract emitting a shared `Finding` schema.
3. **Operator Dashboard** — React 19 + shadcn/ui; live attack-chain viz, reasoning
   stream, findings feed, scope management, one-click PDF export (over WebSocket).
4. **Report Engine** — CVSS 3.1 scoring, LLM exec summary + remediation, PDF.

Plus a **RAG module**: ~240K NVD CVEs embedded with `all-MiniLM-L6-v2` in local
ChromaDB. The agent calls `search_cve_database` after each service-version detection.

## Layout

```
agent/     LangGraph brain, tool wrappers, RAG module, scope gate, config
api/       FastAPI backend (routes + WebSocket, Pydantic models, PostgreSQL)
dashboard/ React 19 + shadcn/ui frontend
reports/   CVSS scoring + LLM report generation + templates
lab/       Terraform + docker-compose for the isolated lab
writeups/  VulnHub machine walkthroughs
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # fill in GROQ_API_KEY, LLM_MODEL, NVD_API_KEY, DB creds, REDAGENT_SCOPE
```

## Run / test / build

```bash
uvicorn api.main:app --reload                        # backend
python agent/rag/pipeline.py --build                 # build CVE store (once, ~2-3h)
python agent/rag/pipeline.py --test 'vsftpd 2.3.4'   # expect CVE-2011-2523 top result
cd dashboard && npm run dev                           # dashboard
docker-compose -f lab/docker-compose.yml up           # lab tool containers
```

## Status

Skeleton stage. Foundations wired: scope gate, shared `Finding` schema, LLM config,
Nmap wrapper. Everything else is a contract-following stub — see the roadmap in
[CLAUDE.md](CLAUDE.md). **Month 1 target:** target → Nmap + Nuclei → structured findings.

## Configuration

The LLM is a config value, never hardcoded (Groq primary, Ollama fallback). Secrets
come from `.env`. Scope is set via `REDAGENT_SCOPE` (comma-separated IPs/CIDRs) —
empty means every target is denied, by design.
