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

**Code-complete.** All four layers + the RAG module are built and covered by the
offline test suite (`pytest` — 116 tests, ~0.6s, no external services required):
scope gate · 6-tool belt (nmap, subfinder, nuclei, cve_rag, sqlmap, metasploit) ·
LangGraph ReAct brain · attack-chain planner · memory + PostgreSQL persistence ·
NVD → ChromaDB RAG + weekly refresh · FastAPI + WebSocket API · CVSS/MITRE/PDF
report engine · React 19 operator dashboard (live reasoning stream, scope
management, PDF export).

Heavy/live dependencies (Groq, ChromaDB, sentence-transformers, tool binaries,
Metasploit RPC, PostgreSQL) are lazily imported and injectable, so the whole
suite runs without any of them. What remains is **live provisioning**, below.

## Testing

```bash
python -m venv .venv && ./.venv/bin/pip install -r requirements-dev.txt
./.venv/bin/python -m pytest          # 116 tests, offline
cd dashboard && npm install && npm run build   # typecheck + build the frontend
```

## Live setup — from code-complete to a real Metasploitable run

Everything above is code + tests. To run a real engagement you provision the lab
and secrets, build the CVE store once, then launch. **Lab-only** — read
[SECURITY.md](SECURITY.md) first.

1. **Secrets.** `cp .env.example .env` and fill in:
   - `GROQ_API_KEY` (agent reasoning + report prose) — free at console.groq.com
   - `NVD_API_KEY` (CVE fetch) — free at nvd.nist.gov/developers/request-an-api-key
   - `DATABASE_URL` (PostgreSQL), and `REDAGENT_SCOPE` (e.g. `10.0.0.0/24`)
2. **Tool binaries** on the attack host (Kali EC2 / Docker): `nmap`, `subfinder`,
   `nuclei`, `sqlmap`, and Metasploit with `msfrpcd` running
   (`MSF_RPC_PASSWORD`/`HOST`/`PORT`). `docker-compose -f lab/docker-compose.yml up`
   brings up the vulnerable targets (DVWA; add Metasploitable) on an
   internet-isolated network.
3. **PostgreSQL.** Point `DATABASE_URL` at a reachable instance; the schema is
   created on first `get_store()`.
4. **Build the CVE store** (once, ~2–3h): `python agent/rag/pipeline.py --build`,
   then verify: `python agent/rag/pipeline.py --test 'vsftpd 2.3.4'` → expect
   `CVE-2011-2523` as the top result. Keep it current with a weekly cron:
   `0 2 * * 0 python agent/rag/update.py`.
5. **Launch.** Start the backend (`uvicorn api.main:app --reload`) and dashboard
   (`cd dashboard && npm run dev`). In the dashboard: add your lab CIDR to scope,
   enter the Metasploitable IP, hit **Launch**, watch the reasoning stream +
   findings, then **Export PDF**.

## Configuration

The LLM is a config value, never hardcoded (Groq primary, Ollama fallback). Secrets
come from `.env`. Scope is set via `REDAGENT_SCOPE` (comma-separated IPs/CIDRs) and
can also be managed at runtime from the dashboard — empty means every target is
denied, by design. Destructive tool paths (SQLMap `--dump`, Metasploit `exploit`)
are always opt-in, never defaulted on.
