# SECURITY.md — Responsible Use Policy

RedAgent is an **autonomous offensive-security research tool** built for a single
purpose: exercising real security tooling against **intentionally vulnerable,
operator-owned lab machines** inside an isolated network. It is a portfolio and
learning project, not a product for use against systems you do not own.

## Authorized use only

You may run RedAgent **only** against targets that are all of the following:

1. **Intentionally vulnerable lab machines** — VulnHub images, Metasploitable
   (2/3), DVWA, or equivalents you have deliberately deployed for testing.
2. **Owned or explicitly authorized by you** — you have full legal authority over
   the target and written permission where applicable.
3. **Inside an isolated lab network** — an AWS VPC private subnet (or equivalent)
   with no route to the public internet from the target subnet.
4. **On the operator scope allowlist** — see the scope gate below.

## Hard technical controls (enforced in code)

- **Scope gate (`agent/scope.py`).** Every tool wrapper calls `in_scope(target)`
  before executing. Default deny: if the target is not on the allowlist, it does
  not run. Public / routable addresses are refused unconditionally, even if
  mistakenly added to scope — only private (RFC 1918) and loopback lab addresses
  are ever eligible.
- **Non-destructive defaults.** SQLMap runs detection-only (`--batch`, no
  `--dump`); Metasploit defaults to `check` over `exploit`. Destructive actions
  require an explicit, per-request operator opt-in passed through the API — never
  hardcoded, never defaulted on.
- **Lab-only by design.** There are no public-internet targets in any code path,
  default, or example.

## What this project will NOT do

The following are out of scope and will not be implemented or assisted:

- Removing, weakening, or bypassing the scope gate.
- Targeting any system the operator does not own or is not authorized to test.
- Use against production systems, third parties, or the public internet.
- Detection-evasion features intended to hide activity from a system's owner.

## Reporting

This is a personal research/portfolio project. If you find a security issue in
RedAgent itself, open an issue in the repository describing it. Do not use this
tool to test systems you are not authorized to test — doing so may be illegal.

## Legal

VulnHub and Metasploitable images are distributed specifically for authorized
security practice. Using RedAgent against anything else may violate computer-
misuse and unauthorized-access laws in your jurisdiction. You are solely
responsible for how you use it.
