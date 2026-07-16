"""Scope gate tests — the single most important safety control. Default-deny,
lab-only (private/loopback), allowlist-driven."""

from __future__ import annotations

import importlib

import pytest


def _reload_scope(monkeypatch, scope_value: str | None):
    if scope_value is None:
        monkeypatch.delenv("REDAGENT_SCOPE", raising=False)
    else:
        monkeypatch.setenv("REDAGENT_SCOPE", scope_value)
    import agent.scope as scope
    return importlib.reload(scope)


def test_empty_scope_denies_everything(monkeypatch):
    scope = _reload_scope(monkeypatch, None)
    assert scope.in_scope("10.0.0.5") is False
    assert scope.in_scope("127.0.0.1") is False


def test_scoped_private_target_allowed(monkeypatch):
    scope = _reload_scope(monkeypatch, "10.0.0.0/24")
    assert scope.in_scope("10.0.0.5") is True
    assert scope.in_scope("10.0.0.255") is True


def test_target_outside_allowlist_denied(monkeypatch):
    scope = _reload_scope(monkeypatch, "10.0.0.0/24")
    assert scope.in_scope("10.0.1.5") is False


def test_public_target_always_denied_even_if_in_scope(monkeypatch):
    # Lab-only: a public address must be refused even if mistakenly allowlisted.
    scope = _reload_scope(monkeypatch, "8.8.8.0/24")
    assert scope.in_scope("8.8.8.8") is False


@pytest.mark.parametrize("bad", ["", "   ", "not-an-ip-or-host-xyz.invalid"])
def test_malformed_or_unresolvable_denied(monkeypatch, bad):
    scope = _reload_scope(monkeypatch, "10.0.0.0/24")
    assert scope.in_scope(bad) is False


def test_malformed_scope_entry_is_ignored_not_allowed(monkeypatch):
    # A junk scope entry must never be treated as "allow".
    scope = _reload_scope(monkeypatch, "garbage,10.0.0.0/24")
    assert scope.in_scope("10.0.0.5") is True   # valid entry still works
    assert scope.in_scope("192.168.1.1") is False


def test_loopback_scopable(monkeypatch):
    scope = _reload_scope(monkeypatch, "127.0.0.0/8")
    assert scope.in_scope("127.0.0.1") is True


def test_url_target_scoped_by_host(monkeypatch):
    # Nuclei/SQLMap pass URLs — scope must check the underlying host.
    scope = _reload_scope(monkeypatch, "10.0.0.0/24")
    assert scope.in_scope("http://10.0.0.5/vuln.php?id=1") is True
    assert scope.in_scope("https://10.9.9.9/") is False       # out of allowlist
    assert scope.in_scope("http://8.8.8.8/") is False          # public, refused


def test_host_port_target_scoped_by_host(monkeypatch):
    scope = _reload_scope(monkeypatch, "10.0.0.0/24")
    assert scope.in_scope("10.0.0.5:8080") is True
