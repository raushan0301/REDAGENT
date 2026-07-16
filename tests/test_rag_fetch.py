"""NVD fetch/pagination tests with a fake HTTP session — no network, no API key."""

from __future__ import annotations

from datetime import datetime, timezone

from agent.rag import pipeline, update


class FakeResp:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


class FakeSession:
    """Serves a fixed list of NVD vulnerability items with real pagination."""
    def __init__(self, items):
        self.items = items
        self.requests: list[dict] = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.requests.append({"params": params or {}, "headers": headers or {}})
        start = params["startIndex"]
        size = params["resultsPerPage"]
        return FakeResp({
            "vulnerabilities": self.items[start:start + size],
            "totalResults": len(self.items),
        })


class FakeStore:
    def __init__(self):
        self.added: list[dict] = []

    def add(self, fields):
        self.added.extend(fields)
        return len(fields)


def _cve(i):
    return {"cve": {"id": f"CVE-2026-{i:04d}",
                    "descriptions": [{"lang": "en", "value": f"desc {i}"}],
                    "metrics": {}, "configurations": []}}


def test_fetch_page_returns_items_and_total():
    session = FakeSession([_cve(i) for i in range(5)])
    items, total = pipeline._fetch_page(0, session=session, page_size=2)
    assert total == 5 and len(items) == 2


def test_iter_all_paginates_to_exhaustion():
    session = FakeSession([_cve(i) for i in range(5)])
    pages = list(pipeline._iter_all(session=session, page_size=2, sleep_s=0))
    assert [len(p) for p in pages] == [2, 2, 1]           # 5 items over 3 pages
    assert session.requests[0]["params"]["startIndex"] == 0
    assert session.requests[-1]["params"]["startIndex"] == 4


def test_iter_all_respects_max_pages():
    session = FakeSession([_cve(i) for i in range(100)])
    pages = list(pipeline._iter_all(session=session, page_size=10, sleep_s=0, max_pages=2))
    assert len(pages) == 2


def test_build_normalizes_and_adds_all(monkeypatch):
    session = FakeSession([_cve(i) for i in range(5)])
    store = FakeStore()
    n = pipeline.build(store=store, session=session, page_size=2, sleep_s=0)
    assert n == 5
    assert {f["id"] for f in store.added} == {f"CVE-2026-{i:04d}" for i in range(5)}


def test_build_sends_api_key_header():
    session = FakeSession([_cve(0)])
    pipeline.build(store=FakeStore(), session=session, api_key="secret", page_size=2, sleep_s=0)
    assert session.requests[0]["headers"] == {"apiKey": "secret"}


def test_update_window_uses_lastmod_dates():
    now = datetime(2026, 7, 16, tzinfo=timezone.utc)
    win = update._window(days=7, now=now)
    assert win["lastModStartDate"] == "2026-07-09T00:00:00.000Z"
    assert win["lastModEndDate"] == "2026-07-16T00:00:00.000Z"


def test_refresh_passes_window_params_and_upserts():
    session = FakeSession([_cve(i) for i in range(3)])
    store = FakeStore()
    now = datetime(2026, 7, 16, tzinfo=timezone.utc)
    n = update.refresh(days=7, store=store, session=session, page_size=2, sleep_s=0, now=now)
    assert n == 3
    assert session.requests[0]["params"]["lastModStartDate"] == "2026-07-09T00:00:00.000Z"
