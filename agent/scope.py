"""Scope gate — the single most important safety control in RedAgent.

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
from functools import lru_cache
from typing import Iterable


# Operators declare scope here (or via REDAGENT_SCOPE env, comma-separated).
# Entries may be single IPs or CIDR ranges. Everything defaults to DENY.
DEFAULT_SCOPE: tuple[str, ...] = ()


def _load_scope() -> list[ipaddress._BaseNetwork]:
    raw = os.environ.get("REDAGENT_SCOPE", "")
    entries: Iterable[str] = (
        [e.strip() for e in raw.split(",") if e.strip()] if raw else DEFAULT_SCOPE
    )
    nets: list[ipaddress._BaseNetwork] = []
    for entry in entries:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            # A malformed scope entry is ignored, never treated as "allow".
            continue
    return nets


def _resolve(target: str) -> ipaddress._BaseAddress | None:
    """Resolve a target (IP or hostname) to an IP address, or None on failure."""
    target = target.strip()
    try:
        return ipaddress.ip_address(target)
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(socket.gethostbyname(target))
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


@lru_cache(maxsize=1)
def scope_summary() -> str:
    """Human-readable summary of the active scope, for logs / the dashboard."""
    nets = _load_scope()
    return ", ".join(str(n) for n in nets) if nets else "(empty — all targets denied)"
