"""Shared pytest fixtures + path setup so `import agent...` works without install."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Make the repo root importable (agent/, api/, reports/).
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FIXTURES = Path(__file__).parent / "fixtures"


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


import pytest  # noqa: E402


@pytest.fixture
def nmap_xml() -> str:
    return read_fixture("nmap_metasploitable.xml")


@pytest.fixture
def scoped_env(monkeypatch):
    """Set a lab scope and force scope module to re-read env."""
    monkeypatch.setenv("REDAGENT_SCOPE", "10.0.0.0/24,127.0.0.0/8")
    import importlib
    import agent.scope as scope
    importlib.reload(scope)
    yield scope


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """slowapi's limiter storage is global/in-memory and persists across the
    whole pytest session, so tests hammering rate-limited endpoints (e.g.
    /scope at 5/min) can 429 depending on run order across files. Reset before
    every test so each one gets a fresh window, keeping the suite order-
    independent. Skipped harmlessly if api.main hasn't been imported yet."""
    try:
        from api.main import app
        app.state.limiter.reset()
    except ImportError:
        pass
    yield
