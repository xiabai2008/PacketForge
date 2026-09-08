"""Tests for NSE script scanning (nmap_nse_scan)."""

import pytest

from packetforge.core.audit import AuditLog
from packetforge.core.security import (
    RateLimiter,
    SecurityError,
    validate_nse_script_spec,
)
from packetforge.interfaces.nmap_interface import NmapInterface
from packetforge.tools.nmap_scan import NmapScanTools


def test_validate_nse_script_spec_ok():
    assert validate_nse_script_spec("vuln") == "vuln"
    assert (
        validate_nse_script_spec("http-enum,ssl-heartbleed")
        == "http-enum,ssl-heartbleed"
    )
    assert validate_nse_script_spec("http-*") == "http-*"
    assert validate_nse_script_spec("default or safe") == "default or safe"


def test_validate_nse_script_spec_rejects_injection():
    with pytest.raises(SecurityError):
        validate_nse_script_spec("vuln; rm -rf /")
    with pytest.raises(SecurityError):
        validate_nse_script_spec("$(whoami)")
    with pytest.raises(SecurityError):
        validate_nse_script_spec("vuln --script-args 'x=1'")
    with pytest.raises(SecurityError):
        validate_nse_script_spec("")


def test_nse_scan_builds_command():
    itf = NmapInterface()
    cmd = itf.nse_scan_cmd("1.2.3.4", "80,443", "http-enum,vuln")
    assert "--script" in cmd and "http-enum,vuln" in cmd
    assert "-oX" in cmd and "-" in cmd
    assert "-p" in cmd and "80,443" in cmd


def test_nse_scan_ok(monkeypatch):
    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    monkeypatch.setattr(tools.nmap, "nse_scan", lambda t, p, s: "<nmaprun></nmaprun>")
    out = tools.nmap_nse_scan("127.0.0.1", "80", "http-enum")
    assert out["status"] == "ok"


def test_nse_scan_rejects_bad_script(monkeypatch):
    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    monkeypatch.setattr(
        tools.nmap,
        "nse_scan",
        lambda *a: (_ for _ in ()).throw(AssertionError("must not run")),
    )
    out = tools.nmap_nse_scan("127.0.0.1", "80", "vuln; id")
    assert out["status"] == "error"


def test_nse_scan_rate_limited(monkeypatch):
    tools = NmapScanTools(
        audit=AuditLog(), limiter=RateLimiter(max_calls=1, window_seconds=60)
    )
    monkeypatch.setattr(tools.nmap, "nse_scan", lambda t, p, s: "<nmaprun/>")
    tools.nmap_nse_scan("127.0.0.1", "80", "vuln")
    out = tools.nmap_nse_scan("127.0.0.1", "80", "vuln")
    assert out["status"] == "error"
    assert "rate" in out["error"].lower()


def test_nse_scan_structured(monkeypatch):
    from tests.test_nmap_structured import SAMPLE_XML

    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    monkeypatch.setattr(tools.nmap, "nse_scan", lambda t, p, s: SAMPLE_XML)
    out = tools.nmap_nse_scan("127.0.0.1", "80,443", "vuln")
    assert out["data"]["structured"]["hosts"][0]["ip"] == "1.2.3.4"
