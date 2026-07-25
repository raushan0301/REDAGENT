"""ChromaDB store operations — the CVE vector collection.

`CveStore` is injectable with any collection object exposing Chroma's
`query`/`upsert` shape and an `embed_fn`, so the filtering + ranking logic is
unit-tested offline with fakes. `CveStore.default()` wires the real persistent
ChromaDB + sentence-transformers embedder (both lazily imported).

Collection: `nvd_cves`, cosine distance, persistent dir chroma_db/.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

COLLECTION = "nvd_cves"
PERSIST_DIR = "chroma_db"
DISTANCE = "cosine"


class CveStore:
    def __init__(self, collection, embed_fn: Callable[[list[str]], list[list[float]]]):
        self.collection = collection
        self.embed_fn = embed_fn

    # --- write ---------------------------------------------------------------
    def add(self, fields_list: list[dict[str, Any]]) -> int:
        """Embed and upsert normalized CVE fields (from pipeline.extract_cve_fields)."""
        from agent.rag.pipeline import cve_to_chunk

        fields_list = [f for f in fields_list if f.get("id")]
        if not fields_list:
            return 0
        docs = [cve_to_chunk(f) for f in fields_list]
        embeddings = self.embed_fn(docs)
        metadatas = [{
            # Chroma metadata cannot hold None; use sentinels.
            "cvss": float(f["cvss"]) if f.get("cvss") is not None else -1.0,
            "severity": f.get("severity") or "",
            "description": (f.get("description") or "")[:500],
        } for f in fields_list]
        self.collection.upsert(
            ids=[f["id"] for f in fields_list],
            embeddings=embeddings,
            documents=docs,
            metadatas=metadatas,
        )
        return len(fields_list)

    # --- read ----------------------------------------------------------------
    def query(self, text: str, top_n: int = 5, min_cvss: Optional[float] = 7.0) -> list[dict]:
        """Cosine search -> rows filtered by min_cvss, ranked by semantic
        relevance (distance asc). CVSS is a filter, not a ranking key — sorting
        by CVSS first would let an unrelated CVSS-10.0 CVE outrank the CVE that
        actually matches the query (discovered live: 'vsftpd 2.3.4' surfaced
        several unrelated 1999-era CVSS-10.0 CVEs ahead of CVE-2011-2523, which
        had the smallest/best distance but a 9.8 score). Returns dicts: id,
        cvss, severity, description, distance."""
        qvec = self.embed_fn([text])[0]
        raw = self.collection.query(query_embeddings=[qvec], n_results=max(top_n * 3, top_n))

        ids = (raw.get("ids") or [[]])[0]
        metas = (raw.get("metadatas") or [[]])[0]
        dists = (raw.get("distances") or [[]])[0]

        rows: list[dict] = []
        for i, cid in enumerate(ids):
            meta = metas[i] if i < len(metas) and metas[i] else {}
            cvss = meta.get("cvss")
            cvss = None if cvss in (None, -1.0) else float(cvss)
            if min_cvss is not None and (cvss is None or cvss < min_cvss):
                continue
            rows.append({
                "id": cid,
                "cvss": cvss,
                "severity": meta.get("severity") or None,
                "description": meta.get("description", ""),
                "distance": dists[i] if i < len(dists) else None,
            })
        rows.sort(key=lambda r: r["distance"] if r["distance"] is not None else 1e9)
        return rows[:top_n]

    # --- factory -------------------------------------------------------------
    @classmethod
    def default(cls) -> "CveStore":
        """Real persistent ChromaDB + sentence-transformers embedder."""
        import chromadb  # pip install chromadb
        from agent.rag.embedder import embed

        client = chromadb.PersistentClient(path=PERSIST_DIR)
        collection = client.get_or_create_collection(
            COLLECTION, metadata={"hnsw:space": DISTANCE})
        return cls(collection, embed_fn=embed)
