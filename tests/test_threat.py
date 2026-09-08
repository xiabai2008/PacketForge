"""Tests for threat-intel tools."""

import json
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


def test_abuseipdb_query_with_key(monkeypatch):

    captured = {}

    class FakeResp:
        def read(self):
            return json.dumps(
                {"data": {"abuseConfidenceScore": 100, "totalReports": 7}}
            ).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=10, context=None):
        captured["url"] = req.full_url
        captured["key"] = req.headers.get("Key")
        return FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    itf = ThreatIntelInterface(abuseipdb_key="k1", urlhaus_host="http://invalid")
    out = itf.check_ip("1.2.3.4")
    assert out["abuseipdb"]["abuse_confidence_score"] == 100
    assert out["abuseipdb"]["total_reports"] == 7
    assert captured["key"] == "k1"
    assert "api.abuseipdb.com" in captured["url"]


def test_abuseipdb_no_key_skipped():
    itf = ThreatIntelInterface(urlhaus_host="http://invalid")
    out = itf.check_ip("1.2.3.4")
    assert "abuseipdb" not in out


def test_abuseipdb_failure_does_not_break_urlhaus(monkeypatch):
    import urllib.error

    calls = []

    def fake_urlopen(req, timeout=10, context=None):
        calls.append(req.full_url)
        if "abuseipdb" in req.full_url:
            raise urllib.error.URLError("network down")
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", None, None)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    itf = ThreatIntelInterface(abuseipdb_key="k1", urlhaus_host="http://invalid")
    out = itf.check_ip("1.2.3.4")
    # urlhaus degraded but abuseipdb failure recorded without breaking flow
    assert out["status"] == "degraded"
    assert out["abuseipdb"]["checked"] is False


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
