"""Tests for threat-intel tools."""

import urllib.request

from packetforge.core.audit import AuditLog
from packetforge.interfaces.threat_intel import ThreatIntelInterface
from packetforge.interfaces.tshark_interface import TsharkError
from packetforge.tools.threat import ThreatTools


def test_urlhaus_query_builds_url():
    itf = ThreatIntelInterface()
    assert itf.urlhaus_query_url() is not None


def test_check_ip_rejects_bad_ip():
    itf = ThreatIntelInterface()
    out = itf.check_ip("999.999.1.1")
    assert out["status"] == "error"


def test_urlhaus_key_sent_in_header(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=10, context=None):
        captured["req"] = req

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    itf = ThreatIntelInterface(urlhaus_key="abc123")
    itf._query("1.2.3.4")
    headers = {k.lower(): v for k, v in captured["req"].headers.items()}
    assert headers["auth-key"] == "abc123"
    assert headers["content-type"] == "application/json"


def test_no_key_degrades_gracefully(monkeypatch):
    import urllib.error

    def fake_urlopen(req, timeout=10, context=None):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", None, None)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    itf = ThreatIntelInterface()
    out = itf.check_ip("8.8.8.8")
    assert out["status"] == "degraded"
    assert out["checked"] is False


def test_check_ip_threat_intel_ok(monkeypatch):
    tools = ThreatTools(audit=AuditLog())
    monkeypatch.setattr(
        tools.intel,
        "check_ip",
        lambda ip: {"status": "ok", "ip": ip, "urlhaus": "no_result"},
    )
    out = tools.check_ip_threat_intel("8.8.8.8")
    assert out["status"] == "ok"
    assert out["urlhaus"] == "no_result"
    assert "audit_id" in out


def test_scan_capture_for_threats_ok(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = ThreatTools(audit=AuditLog())
    # two packets: src,dst lines
    monkeypatch.setattr(
        tools.tshark, "_run", lambda cmd: "1.2.3.4,5.6.7.8\n5.6.7.8,1.2.3.4\n"
    )
    monkeypatch.setattr(
        tools.intel,
        "check_ip",
        lambda ip: (
            {"status": "ok", "ip": ip, "urlhaus": "no_result"}
            if ip == "1.2.3.4"
            else {"status": "degraded", "ip": ip}
        ),
    )
    out = tools.scan_capture_for_threats(str(p))
    assert out["status"] == "ok"
    assert out["data"]["ips"] == ["1.2.3.4", "5.6.7.8"]
    assert out["data"]["findings"] == [{"ip": "1.2.3.4", "status": "no_result"}]


def test_scan_capture_for_threats_error(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = ThreatTools(audit=AuditLog())
    monkeypatch.setattr(
        tools.tshark, "_run", lambda cmd: (_ for _ in ()).throw(TsharkError("bad pcap"))
    )
    out = tools.scan_capture_for_threats(str(p))
    assert out["status"] == "error"


def test_scan_capture_for_threats_missing_file(tmp_path):
    tools = ThreatTools(audit=AuditLog())
    out = tools.scan_capture_for_threats(str(tmp_path / "nope.pcap"))
    assert out["status"] == "error"
