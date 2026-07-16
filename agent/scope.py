"""Scope gate — the single most important safety control in RedAgent.
# Author: Raushan

HARD RULE (see CLAUDE.md): the agent NEVER runs a tool against a target that is
not on the operator-defined allowlist. Every tool wrapper calls `in_scope(target)`
before executing. No scope entry -> no run. Default deny.

Lab-only: valid targets must resolve to private (RFC 1918) addresses inside the
isolated lab VPC. Public-internet targets are refused unconditionally, even if an
operator mistakenly adds one to the allowlist.
"""

from __future__ import annotations

import ipaddress
import os
import socket


# Operators declare scope here (or via REDAGENT_SCOPE env, comma-separated).
# Entries may be single IPs or CIDR ranges. Everything defaults to DENY.
DEFAULT_SCOPE: tuple[str, ...] = ()

# Runtime scope added via the operator dashboard / API. Merged with the env
# allowlist. Still subject to the private/loopback lab-only rule in in_scope().
_RUNTIME_SCOPE: list[str] = []


def _scope_entries() -> list[str]:
    raw = os.environ.get("REDAGENT_SCOPE", "")
    env_entries = [e.strip() for e in raw.split(",") if e.strip()] if raw else list(DEFAULT_SCOPE)
    return env_entries + list(_RUNTIME_SCOPE)


def _load_scope() -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for entry in _scope_entries():
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            # A malformed scope entry is ignored, never treated as "allow".
            continue
    return nets


def list_scope() -> list[str]:
    """All active scope entries (env + runtime), de-duplicated, order-preserving."""
    return list(dict.fromkeys(_scope_entries()))


def add_scope(entry: str) -> bool:
    """Add a lab network/IP to the runtime allowlist. Rejects malformed entries
    and any non-private/loopback network (lab-only). Returns True if added."""
    try:
        net = ipaddress.ip_network(entry.strip(), strict=False)
    except (ValueError, AttributeError):
        return False
    if not (net.is_private or net.is_loopback):
        return False  # lab-only: never allow a public network into scope
    normalized = str(net)
    if normalized not in _RUNTIME_SCOPE:
        _RUNTIME_SCOPE.append(normalized)
    return True


def remove_scope(entry: str) -> bool:
    """Remove a runtime scope entry. Returns True if it was present."""
    try:
        normalized = str(ipaddress.ip_network(entry.strip(), strict=False))
    except (ValueError, AttributeError):
        normalized = entry.strip()
    for candidate in (normalized, entry.strip()):
        if candidate in _RUNTIME_SCOPE:
            _RUNTIME_SCOPE.remove(candidate)
            return True
    return False


def _host_of(target: str) -> str:
    """Extract the bare host from an IP, hostname, host:port, or URL.

    Tool targets vary — Nmap gets an IP, Nuclei/SQLMap get a URL — but the scope
    gate must always check the underlying host. Strips scheme, path, and port.
    """
    target = target.strip()
    if "://" in target or "/" in target or ":" in target:
        from urllib.parse import urlparse
        parsed = urlparse(target if "://" in target else "//" + target)
        if parsed.hostname:
            return parsed.hostname
    return target


def _resolve(target: str) -> ipaddress._BaseAddress | None:
    """Resolve a target (IP, hostname, host:port, or URL) to an IP address, or
    None on failure."""
    host = _host_of(target)
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(socket.gethostbyname(host))
    except (socket.gaierror, ValueError, OSError):
        return None


def in_scope(target: str) -> bool:
    """Return True only if `target` is (a) resolvable, (b) a private lab address,
    and (c) inside the operator allowlist. Default deny on anything ambiguous."""
    if not target or not target.strip():
        return False

    addr = _resolve(target)
    if addr is None:
        return False

    # Lab-only: refuse anything that is not a private/loopback lab address.
    if not (addr.is_private or addr.is_loopback):
        return False

    scope = _load_scope()
    if not scope:
        # No scope configured -> nothing is in scope. This is intentional.
        return False

    return any(addr in net for net in scope)


def scope_summary() -> str:
    """Human-readable summary of the active scope, for logs / the dashboard.
    Not cached — scope is mutable at runtime via add_scope/remove_scope."""
    nets = _load_scope()
    return ", ".join(str(n) for n in nets) if nets else "(empty — all targets denied)"
