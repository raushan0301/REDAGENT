"""Finding schema + CVSS severity banding tests."""

from __future__ import annotations

import pytest

from agent.tools.schema import Finding, severity_from_cvss


def test_finding_minimal_required_fields():
    f = Finding(tool="nmap", phase="recon", target="10.0.0.5",
                title="Open port 21", detail="ftp on 21")
    assert f.tool == "nmap"
    assert f.cve is None and f.cvss is None   # optionals default to None


@pytest.mark.parametrize("score,band", [
    (10.0, "Critical"), (9.0, "Critical"),
    (8.9, "High"), (7.0, "High"),
    (6.9, "Medium"), (4.0, "Medium"),
    (3.9, "Low"), (0.1, "Low"),
    (0.0, "None"), (None, None),
])
def test_severity_bands(score, band):
    assert severity_from_cvss(score) == band
