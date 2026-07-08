"""Weekly NVD refresh job — keeps the CVE store current.

Cron: 0 2 * * 0 python agent/rag/update.py
STUB (Month 3, Week 10). Fetches CVEs modified since the last run and upserts them.
"""

from __future__ import annotations


def refresh() -> None:
    """Fetch recently-modified CVEs from NVD and upsert into ChromaDB. STUB (Week 10)."""
    raise NotImplementedError("refresh stub — implement incremental NVD update (Week 10).")


if __name__ == "__main__":
    refresh()
