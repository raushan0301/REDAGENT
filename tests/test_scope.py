"""Scope gate tests — the single most important safety control. Default-deny,
lab-only (private/loopback), allowlist-driven."""

from __future__ import annotations

import importlib

import pytest


def _reload_scope(monkeypatch, scope_value: str | None, public_scope_value: str | None = None):
    if scope_value is None:
        monkeypatch.delenv("REDAGENT_SCOPE", raising=False)
    else:
        monkeypatch.setenv("REDAGENT_SCOPE", scope_value)
    if public_scope_value is None:
        monkeypatch.delenv("REDAGENT_PUBLIC_SCOPE", raising=False)
    else:
        monkeypatch.setenv("REDAGENT_PUBLIC_SCOPE", public_scope_value)
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


# ── Authorized Public Scope ──────────────────────────────────────────────
# A separate, opt-in allowlist for public targets the operator explicitly
# declares ownership of. Never mixed with lab scope defaults.

def test_public_scope_empty_by_default_denies_public_target(monkeypatch):
    scope = _reload_scope(monkeypatch, None)
    assert scope.list_public_scope() == []
    assert scope.in_scope("93.184.216.34") is False


def test_public_scope_from_env_allows_declared_target(monkeypatch):
    scope = _reload_scope(monkeypatch, None, public_scope_value="93.184.216.34/32")
    assert scope.in_scope("93.184.216.34") is True
    assert scope.in_scope("8.8.8.8") is False   # a different public IP, not declared


def test_public_scope_does_not_leak_into_lab_scope(monkeypatch):
    # Declaring a public target must never grant access to private addresses,
    # and lab scope must stay independently empty/deny.
    scope = _reload_scope(monkeypatch, None, public_scope_value="93.184.216.34/32")
    assert scope.in_scope("10.0.0.5") is False


def test_lab_scope_does_not_leak_into_public_scope(monkeypatch):
    scope = _reload_scope(monkeypatch, "10.0.0.0/24", public_scope_value=None)
    assert scope.in_scope("93.184.216.34") is False


def test_add_public_scope_accepts_ip_cidr_and_hostname(monkeypatch):
    scope = _reload_scope(monkeypatch, None)
    # Hostname validation resolves via DNS; stub it out to keep the suite offline.
    monkeypatch.setattr(scope.socket, "getaddrinfo",
                        lambda *a, **kw: [(2, 1, 6, "", ("93.184.216.34", 0))])
    assert scope.add_public_scope("93.184.216.34") is True
    assert scope.add_public_scope("203.0.113.0/24") is True
    assert scope.add_public_scope("example.com") is True
    assert set(scope.list_public_scope()) == {"93.184.216.34", "203.0.113.0/24", "example.com"}


def test_add_public_scope_rejects_rfc1918_and_loopback(monkeypatch):
    # Private/loopback addresses belong in lab scope (add_scope), not public
    # scope — keeps the two allowlists from blurring together.
    scope = _reload_scope(monkeypatch, None)
    assert scope.add_public_scope("10.0.0.5") is False
    assert scope.add_public_scope("192.168.1.1") is False
    assert scope.add_public_scope("172.16.0.1") is False
    assert scope.add_public_scope("127.0.0.1") is False
    assert scope.add_public_scope("10.0.0.0/24") is False
    assert scope.list_public_scope() == []


def test_add_public_scope_rejects_hostname_resolving_to_private(monkeypatch):
    scope = _reload_scope(monkeypatch, None)
    monkeypatch.setattr(scope.socket, "getaddrinfo",
                        lambda *a, **kw: [(2, 1, 6, "", ("10.0.0.5", 0))])
    assert scope.add_public_scope("internal.example.com") is False


def test_add_public_scope_rejects_unresolvable_garbage(monkeypatch):
    scope = _reload_scope(monkeypatch, None)
    assert scope.add_public_scope("not a real host!!") is False
    assert scope.list_public_scope() == []


def test_add_public_scope_takes_effect_immediately(monkeypatch):
    scope = _reload_scope(monkeypatch, None)
    assert scope.in_scope("93.184.216.34") is False
    scope.add_public_scope("93.184.216.34/32")
    assert scope.in_scope("93.184.216.34") is True


def test_remove_public_scope(monkeypatch):
    scope = _reload_scope(monkeypatch, None)
    scope.add_public_scope("93.184.216.34/32")
    assert scope.remove_public_scope("93.184.216.34/32") is True
    assert scope.in_scope("93.184.216.34") is False
    assert scope.remove_public_scope("93.184.216.34/32") is False   # already gone


def test_public_scope_by_cidr_matches_range(monkeypatch):
    scope = _reload_scope(monkeypatch, None)
    scope.add_public_scope("203.0.113.0/24")
    assert scope.in_scope("203.0.113.42") is True
    assert scope.in_scope("203.0.114.1") is False
