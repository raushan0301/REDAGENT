"""Weekly NVD refresh job — keeps the CVE store current.

Cron: 0 2 * * 0 python agent/rag/update.py
Fetches CVEs modified in the last `days` (NVD lastMod window, max 120 days) and
upserts them into ChromaDB. Reuses the pipeline's paginated fetch; the network
session + store are injectable for tests.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from agent.rag.pipeline import PAGE_SIZE, _iter_all, extract_cve_fields

# NVD expects ISO-8601 with milliseconds, e.g. 2026-07-16T00:00:00.000Z
_NVD_TS = "%Y-%m-%dT%H:%M:%S.000Z"


def _window(days: int, now: Optional[datetime] = None) -> dict[str, str]:
    end = now or datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return {
        "lastModStartDate": start.strftime(_NVD_TS),
        "lastModEndDate": end.strftime(_NVD_TS),
    }


def refresh(days: int = 7, store=None, api_key: Optional[str] = None, session=None,
            sleep_s: Optional[float] = None, page_size: int = PAGE_SIZE,
            now: Optional[datetime] = None) -> int:
    """Upsert CVEs modified in the last `days`. Returns the number upserted."""
    api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
    if sleep_s is None:
        sleep_s = 0.6 if api_key else 6.0
    if store is None:
        from agent.rag.store import CveStore
        store = CveStore.default()

    params = _window(days, now)
    upserted = 0
    for items in _iter_all(params=params, api_key=api_key, session=session,
                           page_size=page_size, sleep_s=sleep_s):
        upserted += store.add([extract_cve_fields(it) for it in items])
    return upserted


if __name__ == "__main__":
    print(f"Upserted {refresh()} modified CVEs.")
