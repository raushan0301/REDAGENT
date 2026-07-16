"""NVD CVE data pipeline — build/refresh the ChromaDB store.

Pure helpers (NVD JSON -> fields -> searchable chunk) live here and are unit-
tested offline. The heavy build() (network fetch + embed + store) lazily imports
requests / the store so importing this module stays cheap.

CLI:
    python agent/rag/pipeline.py --build              # once, ~2-3h
    python agent/rag/pipeline.py --test 'vsftpd 2.3.4'  # expect CVE-2011-2523 top
"""

from __future__ import annotations

import argparse
from typing import Any, Optional

from agent.tools.schema import severity_from_cvss


def _extract_cvss(metrics: dict) -> tuple[Optional[float], Optional[str]]:
    """Pull base score + severity, preferring CVSS v3.1 > v3.0 > v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            sev = data.get("baseSeverity")
            return (float(score) if score is not None else None,
                    sev.title() if isinstance(sev, str) else severity_from_cvss(score))
    entries = metrics.get("cvssMetricV2") or []
    if entries:
        data = entries[0].get("cvssData", {})
        score = data.get("baseScore")
        sev = entries[0].get("baseSeverity") or severity_from_cvss(score)
        return (float(score) if score is not None else None,
                sev.title() if isinstance(sev, str) else sev)
    return None, None


def _extract_cpes(configurations: list) -> list[str]:
    """Collect CPE match criteria strings from an NVD configurations block."""
    cpes: list[str] = []
    for cfg in configurations or []:
        for node in cfg.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                crit = match.get("criteria")
                if crit:
                    cpes.append(crit)
    return cpes


def _cpe_label(criteria: str) -> str:
    """cpe:2.3:a:vendor:product:version:... -> 'product version' (searchable)."""
    parts = criteria.split(":")
    if len(parts) >= 6:
        product, version = parts[4], parts[5]
        product = product.replace("_", " ")
        return f"{product} {version}".strip() if version not in ("*", "-", "") else product
    return criteria


def extract_cve_fields(item: dict[str, Any]) -> dict[str, Any]:
    """Normalize one NVD API 2.0 item (or its inner `cve`) into flat fields."""
    cve = item.get("cve", item)
    cid = cve.get("id")
    desc = next((d.get("value", "") for d in cve.get("descriptions", [])
                 if d.get("lang") == "en"), "")
    cvss, severity = _extract_cvss(cve.get("metrics", {}) or {})
    cpes = _extract_cpes(cve.get("configurations", []) or [])
    return {"id": cid, "description": desc, "cvss": cvss,
            "severity": severity, "cpes": cpes}


def cve_to_chunk(fields: dict[str, Any]) -> str:
    """Build a single searchable text chunk for embedding."""
    parts = [fields.get("id") or "", fields.get("description") or ""]
    if fields.get("cvss") is not None:
        parts.append(f"CVSS {fields['cvss']} {fields.get('severity') or ''}".strip())
    cpes = fields.get("cpes") or []
    if cpes:
        labels = ", ".join(dict.fromkeys(_cpe_label(c) for c in cpes[:10]))
        parts.append(f"Affected: {labels}")
    return " | ".join(p for p in parts if p)


def build() -> None:
    """Full build: NVD fetch -> chunk -> embed -> ChromaDB. Lazy imports."""
    raise NotImplementedError("pipeline.build stub — implement NVD fetch loop (Week 10).")


def test(query: str) -> None:
    """Query the built store and print top CVE matches."""
    from agent.rag.store import CveStore
    for row in CveStore.default().query(query):
        print(f"{row['id']}  CVSS {row['cvss']} {row['severity']}  {row['description'][:80]}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="RedAgent RAG pipeline")
    p.add_argument("--build", action="store_true", help="build the CVE store (once)")
    p.add_argument("--test", metavar="QUERY", help="query the store, e.g. 'vsftpd 2.3.4'")
    args = p.parse_args()
    if args.build:
        build()
    elif args.test:
        test(args.test)
    else:
        p.print_help()
