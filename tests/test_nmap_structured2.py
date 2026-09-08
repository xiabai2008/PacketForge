"""Tests for structured output of remaining nmap scan tools."""

from packetforge.core.audit import AuditLog
from packetforge.core.security import RateLimiter
from packetforge.tools.nmap_scan import NmapScanTools
from tests.test_nmap_structured import SAMPLE_XML


def make_tools():
    return NmapScanTools(audit=AuditLog(), limiter=RateLimiter())


def test_quick_scan_structured(monkeypatch):
    tools = make_tools()
    monkeypatch.setattr(tools.nmap, "quick_scan", lambda t: SAMPLE_XML)
    out = tools.nmap_quick_scan("127.0.0.1")
    assert out["data"]["structured"]["hosts"][0]["ip"] == "1.2.3.4"


def test_quick_scan_xml_command(monkeypatch):
    tools = make_tools()
    seen = {}

    def fake_run(args):
        seen["args"] = args
        return SAMPLE_XML

    monkeypatch.setattr(tools.nmap, "_run", fake_run)
    tools.nmap_quick_scan("127.0.0.1")
    assert "-oX" in seen["args"] and "-" in seen["args"]


def test_vulnerability_scan_structured(monkeypatch):
    tools = make_tools()
    monkeypatch.setattr(tools.nmap, "vulnerability_scan", lambda t, p: SAMPLE_XML)
    out = tools.nmap_vulnerability_scan("127.0.0.1", "80")
    assert out["data"]["structured"]["hosts"][0]["ports"][0]["service"] == "http"


def test_os_detection_structured(monkeypatch):
    tools = make_tools()
    monkeypatch.setattr(tools.nmap, "os_detection", lambda t: SAMPLE_XML)
    out = tools.nmap_os_detection("127.0.0.1")
    assert "structured" in out["data"]
