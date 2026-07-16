"""Metasploit wrapper tests with a fake XMLRPC client — no live Metasploit.

Covers check-before-exploit safety, the run_exploit opt-in, the 'safe' short-
circuit, session polling, and the scope gate.
"""

from __future__ import annotations

import pytest

from agent.tools import metasploit_tool
from agent.tools.metasploit_tool import metasploit_run, set_client


class FakeModule:
    def __init__(self, verdict, opens_session=False):
        self.verdict = verdict
        self.opens_session = opens_session
        self.options: dict = {}
        self.executed = False
        self.payload = None

    def set(self, key, value):
        self.options[key] = value

    def check(self):
        return self.verdict

    def execute(self, payload=None):
        self.executed = True
        self.payload = payload
        return {"job_id": 1}


class FakeClient:
    def __init__(self, module):
        self.module = module
        self.used = None

    def use_exploit(self, name):
        self.used = name
        return self.module

    def session_ids(self):
        # A session appears only after a successful execute() on an exploitable target.
        return ["1"] if (self.module.executed and self.module.opens_session) else []


@pytest.fixture(autouse=True)
def fast_poll_and_reset(monkeypatch):
    monkeypatch.setattr(metasploit_tool, "POLL_SLEEP_S", 0)
    monkeypatch.setenv("REDAGENT_SCOPE", "10.0.0.0/24")
    import importlib
    import agent.scope
    importlib.reload(agent.scope)
    monkeypatch.setattr(metasploit_tool, "in_scope", agent.scope.in_scope)
    yield
    metasploit_tool._client = None


def test_check_only_by_default_does_not_execute():
    mod = FakeModule("vulnerable")
    set_client(FakeClient(mod))
    findings = metasploit_run.invoke({"target": "10.0.0.5",
                                      "module": "unix/ftp/vsftpd_234_backdoor"})
    assert mod.executed is False                      # safe default: check only
    assert any("Vulnerable to" in f.title for f in findings)
    assert mod.options["RHOSTS"] == "10.0.0.5"


def test_safe_verdict_never_exploits_even_with_opt_in():
    mod = FakeModule("safe", opens_session=True)
    set_client(FakeClient(mod))
    findings = metasploit_run.invoke({"target": "10.0.0.5", "module": "some/module",
                                      "run_exploit": True})
    assert mod.executed is False                      # 'safe' short-circuits exploit
    assert findings[0].title == "Not vulnerable"


def test_run_exploit_opens_session_reported_post_exploit():
    mod = FakeModule("appears", opens_session=True)
    set_client(FakeClient(mod))
    findings = metasploit_run.invoke({"target": "10.0.0.5",
                                      "module": "unix/ftp/vsftpd_234_backdoor",
                                      "run_exploit": True,
                                      "payload": "cmd/unix/interact"})
    assert mod.executed is True and mod.payload == "cmd/unix/interact"
    session = next(f for f in findings if f.phase == "post-exploit")
    assert session.severity == "Critical"
    assert "session_id=1" in session.evidence


def test_run_exploit_but_no_session_opened():
    mod = FakeModule("vulnerable", opens_session=False)   # exploit runs, no shell
    set_client(FakeClient(mod))
    findings = metasploit_run.invoke({"target": "10.0.0.5", "module": "m",
                                      "run_exploit": True})
    assert mod.executed is True
    assert all(f.phase != "post-exploit" for f in findings)


def test_out_of_scope_never_touches_client():
    mod = FakeModule("vulnerable")
    set_client(FakeClient(mod))
    findings = metasploit_run.invoke({"target": "10.9.9.9", "module": "m",
                                      "run_exploit": True})
    assert findings[0].title == "Out of scope"
    assert mod.executed is False
