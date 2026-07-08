"""NVD CVE data pipeline — build/refresh the ChromaDB store.

STUB (Month 3, Week 10). Fetches ~240K CVEs from the NVD API in batches of 2000,
extracts (id, description, cvss, severity, CPE), builds a searchable text chunk
per CVE, embeds via embedder.py, writes to store.py.

CLI:
    python agent/rag/pipeline.py --build              # once, ~2-3h
    python agent/rag/pipeline.py --test 'vsftpd 2.3.4'  # expect CVE-2011-2523 top
"""

from __future__ import annotations

import argparse


def build() -> None:
    """Full build: NVD fetch -> chunk -> embed -> ChromaDB. STUB (Week 10)."""
    raise NotImplementedError("pipeline.build stub — implement NVD fetch + embed (Week 10).")


def test(query: str) -> None:
    """Query the built store and print top CVE matches. STUB (Week 10)."""
    raise NotImplementedError("pipeline.test stub — query ChromaDB (Week 10).")


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
