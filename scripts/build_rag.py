"""Full NVD ingest with live progress output + exponential backoff.

Run:  python scripts/build_rag.py
      python scripts/build_rag.py --sleep 2.0   # back off if NVD throttles
      python scripts/build_rag.py --resume 46000 # skip already-fetched pages

Resumes automatically (upsert is idempotent). Safe to kill and re-run.
Kills the old process first: kill $(lsof -ti tcp:8000) or Ctrl-C the tail.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.rag.pipeline import NVD_URL, PAGE_SIZE, extract_cve_fields
from agent.rag.store import CveStore


def build_with_progress(
    api_key: str,
    page_size: int = PAGE_SIZE,
    sleep_s: float = 0.6,
    resume_at: int = 0,
) -> None:
    import requests

    store = CveStore.default()
    start_count = store.collection.count()
    print(f"[RAG BUILD] Store currently has {start_count:,} CVEs.")
    print(f"[RAG BUILD] Page size: {page_size}  |  Sleep: {sleep_s}s  |  Resume at index: {resume_at}  |  API key: {'yes' if api_key else 'NO'}")
    print("-" * 72)

    session = requests.Session()
    headers = {"apiKey": api_key} if api_key else {}

    start_index = resume_at
    total_results = None
    pages_done = 0
    total_added = 0
    build_start = time.time()
    consecutive_errors = 0

    while True:
        page_start = time.time()

        # Exponential backoff: 10s, 30s, 60s, 120s, 300s then give up
        retry_delays = [10, 30, 60, 120, 300]
        fetched = False
        for attempt, delay in enumerate(retry_delays + [None]):
            try:
                resp = session.get(
                    NVD_URL,
                    params={"resultsPerPage": page_size, "startIndex": start_index},
                    headers=headers,
                    timeout=90,
                )
                resp.raise_for_status()
                fetched = True
                consecutive_errors = 0
                break
            except Exception as exc:
                if delay is None:
                    print(f"[RAG BUILD] ❌ Gave up after {len(retry_delays)} retries at index {start_index}. Exiting.")
                    sys.exit(1)
                wait = delay + consecutive_errors * 10  # extra backoff if errors keep coming
                print(f"[RAG BUILD] ⚠  Error (attempt {attempt+1}): {exc}")
                print(f"[RAG BUILD]    Backing off {wait}s before retry…")
                time.sleep(wait)
                consecutive_errors += 1

        data = resp.json()
        items = data.get("vulnerabilities", [])
        if total_results is None:
            total_results = data.get("totalResults", 0)
            total_pages = (total_results + page_size - 1) // page_size
            print(f"[RAG BUILD] Total CVEs from NVD: {total_results:,}  |  Estimated pages: {total_pages}")

        if not items:
            break

        fields = [extract_cve_fields(it) for it in items]
        added = store.add(fields)
        total_added += added
        start_index += len(items)
        pages_done += 1

        elapsed = time.time() - build_start
        page_t = time.time() - page_start
        pct = (start_index / total_results * 100) if total_results else 0
        # ETA based on rate since this run started (not including skipped resume pages)
        fetched_this_run = start_index - resume_at
        remaining = total_results - start_index
        rate = fetched_this_run / elapsed if elapsed > 0 else 1
        eta_s = remaining / rate if rate > 0 else 0
        eta_str = f"{eta_s/3600:.1f}h" if eta_s > 3600 else f"{eta_s/60:.0f}m"

        print(
            f"[RAG BUILD] Page {pages_done:>4}  |  {start_index:>8,}/{total_results:,} ({pct:5.1f}%)"
            f"  |  +{added} this page  |  store={store.collection.count():,}"
            f"  |  {page_t:.0f}s/page  |  ETA ~{eta_str}"
        )
        sys.stdout.flush()

        if start_index >= total_results:
            break
        time.sleep(sleep_s)

    total_elapsed = time.time() - build_start
    print("-" * 72)
    print(
        f"[RAG BUILD] ✅ Done!  Added {total_added:,} CVEs this run  |  "
        f"Store total: {store.collection.count():,}  |  "
        f"Elapsed: {total_elapsed/3600:.2f}h"
    )
    print("[RAG BUILD] Verify: python agent/rag/pipeline.py --test 'vsftpd 2.3.4'")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="RedAgent NVD full ingest")
    p.add_argument("--sleep", type=float, default=0.6,
                   help="Seconds to sleep between NVD pages (default 0.6; increase to 2.0 if throttled)")
    p.add_argument("--resume", type=int, default=0,
                   help="startIndex to resume from (skip already-fetched pages)")
    p.add_argument("--page-size", type=int, default=PAGE_SIZE,
                   help=f"Results per NVD page (default {PAGE_SIZE}, max 2000)")
    args = p.parse_args()

    key = os.environ.get("NVD_API_KEY", "")
    if not key:
        print("WARNING: No NVD_API_KEY — unauthenticated rate limit applies.")

    build_with_progress(api_key=key, page_size=args.page_size,
                        sleep_s=args.sleep, resume_at=args.resume)
