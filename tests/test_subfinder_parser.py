"""Subfinder output parser tests — deterministic, offline (no subfinder binary)."""

from __future__ import annotations

from agent.tools.subfinder_tool import _parse
from tests.conftest import read_fixture


def _findings():
    return _parse("lab.local", read_fixture("subfinder_output.txt"))


def test_parses_unique_subdomains_and_skips_junk():
    hosts = [f.evidence for f in _findings()]
    # 4 valid unique hostnames; the dup and the "not a hostname" line are dropped.
    assert hosts == ["www.lab.local", "admin.lab.local", "mail.lab.local",
                     "dev.internal.lab.local"]


def test_all_tagged_recon_with_target_and_raw():
    findings = _findings()
    assert all(f.tool == "subfinder" and f.phase == "recon" for f in findings)
    assert all(f.target == "lab.local" and f.raw is not None for f in findings)


def test_title_contains_subdomain():
    assert _findings()[0].title == "Subdomain: www.lab.local"


def test_empty_output_returns_empty():
    assert _parse("lab.local", "\n   \n") == []
