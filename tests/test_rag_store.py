"""CveStore filtering + ranking tests with a fake Chroma-shaped collection."""

from __future__ import annotations

from agent.rag.store import CveStore


class FakeCollection:
    """Returns a canned Chroma-shaped result, ignoring the query vector."""
    def __init__(self, result):
        self.result = result
        self.upserts = []

    def query(self, query_embeddings, n_results):
        return self.result

    def upsert(self, ids, embeddings, documents, metadatas):
        self.upserts.append((ids, documents, metadatas))


def _fake_embed(texts):
    return [[0.0, 0.0] for _ in texts]


def _store(result):
    return CveStore(FakeCollection(result), embed_fn=_fake_embed)


def test_query_filters_below_min_cvss():
    result = {
        "ids": [["CVE-A", "CVE-B", "CVE-C"]],
        "metadatas": [[
            {"cvss": 10.0, "severity": "Critical", "description": "a"},
            {"cvss": 5.0, "severity": "Medium", "description": "b"},
            {"cvss": 8.0, "severity": "High", "description": "c"},
        ]],
        "distances": [[0.1, 0.2, 0.3]],
    }
    rows = _store(result).query("x", min_cvss=7.0)
    assert [r["id"] for r in rows] == ["CVE-A", "CVE-C"]   # B (5.0) filtered out


def test_query_ranks_by_cvss_desc():
    result = {
        "ids": [["low", "high"]],
        "metadatas": [[
            {"cvss": 7.1, "severity": "High", "description": "l"},
            {"cvss": 9.9, "severity": "Critical", "description": "h"},
        ]],
        "distances": [[0.05, 0.9]],   # 'low' is closer, but 'high' outranks on CVSS
    }
    rows = _store(result).query("x", min_cvss=7.0)
    assert [r["id"] for r in rows] == ["high", "low"]


def test_query_respects_top_n():
    result = {
        "ids": [[f"CVE-{i}" for i in range(10)]],
        "metadatas": [[{"cvss": 9.0, "severity": "Critical", "description": str(i)}
                       for i in range(10)]],
        "distances": [[i / 100 for i in range(10)]],
    }
    assert len(_store(result).query("x", top_n=3, min_cvss=7.0)) == 3


def test_sentinel_cvss_treated_as_none_and_filtered():
    result = {
        "ids": [["CVE-X"]],
        "metadatas": [[{"cvss": -1.0, "severity": "", "description": "x"}]],
        "distances": [[0.1]],
    }
    assert _store(result).query("x", min_cvss=7.0) == []


def test_add_embeds_and_upserts():
    store = _store({"ids": [[]], "metadatas": [[]], "distances": [[]]})
    n = store.add([{"id": "CVE-2011-2523", "description": "vsftpd backdoor",
                    "cvss": 10.0, "severity": "Critical",
                    "cpes": ["cpe:2.3:a:x:vsftpd:2.3.4:*:*:*:*:*:*:*"]}])
    assert n == 1
    ids, docs, metas = store.collection.upserts[0]
    assert ids == ["CVE-2011-2523"]
    assert metas[0]["cvss"] == 10.0
    assert "CVE-2011-2523" in docs[0]
