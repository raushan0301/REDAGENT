"""Pure NVD-parsing + chunking tests (offline, no chromadb / sentence-transformers)."""

from __future__ import annotations

import json

from agent.rag.pipeline import (
    cve_to_chunk,
    extract_cve_fields,
    _cpe_label,
    _extract_cvss,
)
from tests.conftest import read_fixture


def _fields():
    return extract_cve_fields(json.loads(read_fixture("nvd_vsftpd.json")))


def test_extract_fields_from_nvd_item():
    f = _fields()
    assert f["id"] == "CVE-2011-2523"
    assert "backdoor" in f["description"]
    assert f["cvss"] == 10.0
    assert f["severity"] == "Critical"
    assert f["cpes"] == ["cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*"]


def test_english_description_selected():
    assert "espanol" not in _fields()["description"]


def test_chunk_is_searchable_and_contains_key_tokens():
    chunk = cve_to_chunk(_fields())
    assert "CVE-2011-2523" in chunk
    assert "vsftpd 2.3.4" in chunk        # from CPE label
    assert "CVSS 10.0 Critical" in chunk


def test_cpe_label_parsing():
    assert _cpe_label("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*") == "http server 2.4.49"
    assert _cpe_label("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*") == "product"


def test_cvss_v2_fallback_and_derived_severity():
    metrics = {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]}
    cvss, severity = _extract_cvss(metrics)
    assert cvss == 7.5 and severity == "High"


def test_missing_metrics_yields_none():
    f = extract_cve_fields({"cve": {"id": "CVE-0000-0000", "descriptions": [], "metrics": {}}})
    assert f["cvss"] is None and f["severity"] is None
    # chunk still builds without crashing
    assert cve_to_chunk(f) == "CVE-0000-0000"
