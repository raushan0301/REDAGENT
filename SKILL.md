---
name: redagent-tool-wrapper
description: "Use when adding or editing a security tool wrapper in RedAgent's agent/tools/ directory (Nmap, Nuclei, Nikto, Subfinder, SQLMap, Metasploit, or any new CLI tool the agent calls). Ensures every wrapper follows the same contract: scope-gated, timed-out subprocess execution with output normalized to the shared findings schema and exposed as a LangGraph @tool. Do NOT use for the CVE RAG tool (that queries ChromaDB, not a subprocess) or for non-tool agent code."
---

# RedAgent security-tool wrapper pattern

Every tool in `agent/tools/` (except `cve_rag_tool.py`) wraps a real CLI security
tool the LangGraph agent can call. They must all follow the same contract so the
agent reasons over one consistent schema and the report engine can auto-fill from
it. Do not hand-roll one-off wrappers.

## The five stages, in order

1. **Validate input.** Pydantic-typed args. Reject empty/malformed targets.
2. **Scope gate (mandatory).** Check the target against the operator scope
   allowlist. Not in scope → return a refusal finding, do NOT execute. This is a
   hard project rule, never skip it.
3. **Execute** via `subprocess` with an explicit timeout and captured
   stdout/stderr. Default to non-destructive flags (detection/safe mode).
   Destructive behaviour only if an explicit operator opt-in arg is passed.
4. **Parse** raw output into the shared `Finding` schema. The agent must never
   see raw tool text. This is also a **token lever**: the project runs on Groq's
   free tier (12K tokens/min, 100K tokens/day), so keep `detail` concise and put
   bulky raw output in `raw` (report appendix only) — never let full tool dumps
   reach the agent loop, or you'll blow the daily token budget in a few steps.
5. **Return** a list of `Finding`s (or a single status finding on
   no-result/error). Decorate the callable with `@tool` so LangGraph can invoke it.
   Keep `@tool` docstrings tight — every tool's schema is resent to Groq on every
   agent step, so verbose docstrings cost tokens on the TPM limit.

## Shared findings schema (define once, import everywhere)

Keep this in a single module (e.g. `agent/tools/schema.py`) and import it in
every wrapper. All wrappers emit the same shape.

```python
from pydantic import BaseModel
from typing import Optional

class Finding(BaseModel):
    tool: str              # e.g. "nmap"
    phase: str             # recon | scanning | exploitation | post-exploit
    target: str
    title: str             # short human label
    detail: str            # normalized description
    service: Optional[str] = None      # e.g. "vsftpd"
    version: Optional[str] = None       # e.g. "2.3.4"
    cve: Optional[str] = None
    cvss: Optional[float] = None
    severity: Optional[str] = None      # Low|Medium|High|Critical
    evidence: Optional[str] = None      # trimmed raw snippet / PoC pointer
    mitre: Optional[str] = None         # ATT&CK technique id
    raw: Optional[str] = None           # full raw output, for the report appendix
```

## Wrapper skeleton

```python
import subprocess
from langchain_core.tools import tool
from agent.tools.schema import Finding
from agent.scope import in_scope          # raises/returns False if out of scope

TOOL_NAME = "nmap"
PHASE = "recon"
TIMEOUT_S = 300

def _run(args: list[str]) -> str:
    proc = subprocess.run(
        args, capture_output=True, text=True, timeout=TIMEOUT_S
    )
    return proc.stdout + ("\n" + proc.stderr if proc.stderr else "")

def _parse(target: str, raw: str) -> list[Finding]:
    findings: list[Finding] = []
    # tool-specific parsing -> populate Finding fields
    # ALWAYS set tool=TOOL_NAME, phase=PHASE, target=target, raw=raw
    return findings

@tool
def nmap_scan(target: str) -> list[Finding]:
    """Run an Nmap service/version scan against an in-scope lab target and
    return normalized findings. Use during recon to enumerate open ports and
    detect service versions."""
    if not in_scope(target):
        return [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                        title="Out of scope",
                        detail="Target not in operator scope list; not executed.")]
    raw = _run(["nmap", "-sV", "-oX", "-", target])
    findings = _parse(target, raw)
    return findings or [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                                title="No findings", detail="Scan returned nothing.",
                                raw=raw)]
```

## Checklist before you consider a wrapper done

- [ ] Scope gate present and unbypassable
- [ ] Timeout on the subprocess call
- [ ] Non-destructive default flags; destructive path requires explicit opt-in
- [ ] Output normalized to `Finding` — no raw text leaks to the agent
- [ ] `@tool` docstring tells the agent *when* to use it and *what phase*
- [ ] Returns a status `Finding` on empty/error rather than throwing
- [ ] `raw` retained for the report appendix

## Per-tool notes

- **Nmap** — `-sV` for versions; parse XML (`-oX -`) not human output. Feed
  detected `service`+`version` straight into the CVE RAG tool.
- **Nuclei** — use `-jsonl` output; one Finding per template hit.
- **SQLMap** — detection only by default (`--batch`, no `--dump`). Destructive
  extraction is opt-in.
- **Metasploit** — via XMLRPC, not shelling out. Async session handling; poll
  for completion. Default to `check` before `exploit` where the module supports it.
- **Subfinder** — recon phase, returns subdomains as Findings with `phase=recon`.
