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
