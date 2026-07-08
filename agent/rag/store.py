"""ChromaDB store operations — read/write/query the CVE collection.

Collection: `nvd_cves`, similarity metric: cosine, persistent local dir chroma_db/.
Each record: embedding + metadata (id, cvss, severity, description).
Query supports a minimum-CVSS filter. STUB (Month 3, Week 10).
"""

from __future__ import annotations

COLLECTION = "nvd_cves"
PERSIST_DIR = "chroma_db"
DISTANCE = "cosine"


def get_collection():
    """Return the persistent ChromaDB collection, creating it if needed. STUB."""
    # import chromadb
    # client = chromadb.PersistentClient(path=PERSIST_DIR)
    # return client.get_or_create_collection(COLLECTION, metadata={"hnsw:space": DISTANCE})
    raise NotImplementedError("get_collection stub — wire ChromaDB (Week 10).")


def query(text: str, top_n: int = 5, min_cvss: float = 7.0):
    """Cosine search -> top_n CVEs at/above min_cvss. STUB (Week 10)."""
    raise NotImplementedError("query stub — implement cosine search + CVSS filter (Week 10).")
