"""Scope gate — the single most important safety control in RedAgent.
# Author: Raushan

HARD RULE (see CLAUDE.md): the agent NEVER runs a tool against a target that is
not on the operator-defined allowlist. Every tool wrapper calls `in_scope(target)`
before executing. No scope entry -> no run. Default deny.

Lab scope (REDAGENT_SCOPE): valid targets must resolve to private (RFC 1918)
addresses inside the isolated lab VPC. Public-internet targets are refused
unconditionally from this list.

Authorized public scope (REDAGENT_PUBLIC_SCOPE): explicitly declared public
targets the operator owns/is authorized to test. Requires deliberate opt-in via
a separate env var — not mixed with lab scope to avoid accidental exposure.
"""

from __future__ import annotations

import ipaddress
import os
import socket

# Strictly RFC 1918 + loopback — narrower than Python's ipaddress.is_private,
# which also covers IANA special-use ranges (TEST-NET, benchmarking, etc.)
# that are not "private" in the traditional sense this project means.
_RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _is_rfc1918_or_loopback(addr: ipaddress._BaseAddress) -> bool:
    return addr.is_loopback or any(addr in net for net in _RFC1918_NETS)


# Operators declare scope here (or via REDAGENT_SCOPE env, comma-separated).
# Entries may be single IPs or CIDR ranges. Everything defaults to DENY.
DEFAULT_SCOPE: tuple[str, ...] = ()

# Runtime scope added via the operator dashboard / API. Merged with the env
# allowlist. Still subject to the private/loopback lab-only rule in in_scope().
_RUNTIME_SCOPE: list[str] = []

# ── Authorized Public Scope ──────────────────────────────────────────────────
# Explicitly declared public IPs / CIDRs / hostnames the operator OWNS and is
# authorized to test. Loaded from REDAGENT_PUBLIC_SCOPE (comma-separated).
# Runtime entries can be added via add_public_scope() / the API.
# These bypass the private-only guard but are still subject to allowlist check.
_RUNTIME_PUBLIC_SCOPE: list[str] = []


# ── Lab scope helpers ────────────────────────────────────────────────────────

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
    """All active lab scope entries (env + runtime), de-duplicated, order-preserving."""
    return list(dict.fromkeys(_scope_entries()))


def add_scope(entry: str) -> bool:
    """Add a lab network/IP to the runtime allowlist. Rejects malformed entries
    and any non-private/loopback network (lab-only). Returns True if added."""
    try:
        net = ipaddress.ip_network(entry.strip(), strict=False)
    except (ValueError, AttributeError):
        return False
    if not (net.is_private or net.is_loopback):
        return False  # lab-only: never allow a public network into lab scope
    normalized = str(net)
    if normalized not in _RUNTIME_SCOPE:
        _RUNTIME_SCOPE.append(normalized)
    return True


def remove_scope(entry: str) -> bool:
    """Remove a runtime lab scope entry. Returns True if it was present."""
    try:
        normalized = str(ipaddress.ip_network(entry.strip(), strict=False))
    except (ValueError, AttributeError):
        normalized = entry.strip()
    for candidate in (normalized, entry.strip()):
        if candidate in _RUNTIME_SCOPE:
            _RUNTIME_SCOPE.remove(candidate)
            return True
    return False


# ── Authorized public scope helpers ─────────────────────────────────────────

def _public_scope_entries() -> list[str]:
    """Entries from REDAGENT_PUBLIC_SCOPE env + runtime additions."""
    raw = os.environ.get("REDAGENT_PUBLIC_SCOPE", "")
    env_entries = [e.strip() for e in raw.split(",") if e.strip()] if raw else []
    return env_entries + list(_RUNTIME_PUBLIC_SCOPE)


def _resolve_public_entry(entry: str) -> list[ipaddress._BaseAddress]:
    """Resolve a public scope entry (IP, CIDR, or hostname) to a list of addresses."""
    entry = entry.strip()
    resolved: list[ipaddress._BaseAddress] = []
    # Try as a CIDR network first
    try:
        net = ipaddress.ip_network(entry, strict=False)
        resolved.append(net.network_address)  # use network addr as the canonical check
        return resolved
    except ValueError:
        pass
    # Try as a bare IP
    try:
        resolved.append(ipaddress.ip_address(entry))
        return resolved
    except ValueError:
        pass
    # Try as a hostname — resolve all A records
    try:
        infos = socket.getaddrinfo(entry, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for info in infos:
            try:
                resolved.append(ipaddress.ip_address(info[4][0]))
            except ValueError:
                pass
    except (socket.gaierror, OSError):
        pass
    return resolved


def list_public_scope() -> list[str]:
    """All active authorized-public scope entries, de-duplicated, order-preserving."""
    return list(dict.fromkeys(_public_scope_entries()))


def add_public_scope(entry: str) -> bool:
    """Add a public IP/CIDR/hostname to the authorized-public allowlist.
    The operator asserts they own / are authorized to test this target.
    Rejects entries that resolve to an RFC 1918 / loopback address — those
    belong in lab scope (add_scope), not here, to keep the two allowlists
    from blurring into each other. Returns True if successfully added."""
    entry = entry.strip()
    if not entry:
        return False
    # Validate: must be a valid IP, CIDR, or resolvable hostname — and must
    # not resolve to an RFC 1918 / loopback address (that belongs in lab scope).
    try:
        net = ipaddress.ip_network(entry, strict=False)
        if _is_rfc1918_or_loopback(net.network_address):
            return False
    except ValueError:
        try:
            addr = ipaddress.ip_address(entry)
            if _is_rfc1918_or_loopback(addr):
                return False
        except ValueError:
            # Try resolving as hostname; reject if it's unresolvable or every
            # resolved address is RFC 1918 / loopback.
            try:
                infos = socket.getaddrinfo(entry, None)
            except (socket.gaierror, OSError):
                return False
            resolved = []
            for info in infos:
                try:
                    resolved.append(ipaddress.ip_address(info[4][0]))
                except ValueError:
                    pass
            if not resolved or all(_is_rfc1918_or_loopback(a) for a in resolved):
                return False
    if entry not in _RUNTIME_PUBLIC_SCOPE:
        _RUNTIME_PUBLIC_SCOPE.append(entry)
    return True


def remove_public_scope(entry: str) -> bool:
    """Remove a runtime authorized-public scope entry. Returns True if present."""
    entry = entry.strip()
    if entry in _RUNTIME_PUBLIC_SCOPE:
        _RUNTIME_PUBLIC_SCOPE.remove(entry)
        return True
    return False


# ── Common helpers ───────────────────────────────────────────────────────────

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


def _in_public_scope(addr: ipaddress._BaseAddress) -> bool:
    """Check if addr matches any entry in the authorized-public allowlist."""
    for entry in _public_scope_entries():
        entry = entry.strip()
        if not entry:
            continue
        # Check as CIDR/network
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if addr in net:
                return True
            continue
        except ValueError:
            pass
        # Check as bare IP
        try:
            if addr == ipaddress.ip_address(entry):
                return True
            continue
        except ValueError:
            pass
        # Check as hostname — resolve and compare
        try:
            infos = socket.getaddrinfo(entry, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for info in infos:
                try:
                    if addr == ipaddress.ip_address(info[4][0]):
                        return True
                except ValueError:
                    pass
        except (socket.gaierror, OSError):
            pass
    return False


def in_scope(target: str) -> bool:
    """Return True only if `target` is resolvable AND inside the operator allowlist.

    Two allowlists are checked, authorized-public first:
      1. Authorized public scope (REDAGENT_PUBLIC_SCOPE) — explicitly declared
         public targets the operator owns.
      2. Lab scope (REDAGENT_SCOPE) — private/loopback only.

    Public scope is checked FIRST because Python's ipaddress.is_private is
    broader than RFC 1918 — it also covers IANA special-use ranges like
    TEST-NET (203.0.113.0/24). An address in one of those ranges would
    otherwise get misrouted into the (typically empty) lab-scope path below
    and silently denied, even after the operator explicitly declared it via
    add_public_scope(). Checking the explicit, deliberate allowlist first
    avoids that misrouting regardless of how Python classifies the address.

    Default deny on anything ambiguous or unresolvable.
    """
    if not target or not target.strip():
        return False

    addr = _resolve(target)
    if addr is None:
        return False

    # ── Path 1: explicitly authorized public scope ───────────────────────────
    if _in_public_scope(addr):
        return True

    # ── Path 2: private/loopback address → check lab scope ──────────────────
    if addr.is_private or addr.is_loopback:
        scope = _load_scope()
        if not scope:
            return False
        return any(addr in net for net in scope)

    return False


def scope_summary() -> str:
    """Human-readable summary of the active scope, for logs / the dashboard.
    Not cached — scope is mutable at runtime via add_scope/remove_scope."""
    lab = _load_scope()
    pub = list_public_scope()
    parts = []
    if lab:
        parts.append("Lab: " + ", ".join(str(n) for n in lab))
    if pub:
        parts.append("Public: " + ", ".join(pub))
    return " | ".join(parts) if parts else "(empty — all targets denied)"
