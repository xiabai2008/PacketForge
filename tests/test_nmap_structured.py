"""Tests for structured Nmap XML output parsing."""

from packetforge.interfaces.nmap_interface import parse_nmap_xml

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -p 80,443 1.2.3.4">
<host starttime="1" endtime="2">
<status state="up" reason="reset"/>
<address addr="1.2.3.4" addrtype="ipv4"/>
<hostnames><hostname name="example.com" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.24.0"/></port>
<port protocol="tcp" portid="443"><state state="closed" reason="reset"/><service name="https" method="table" conf="3"/></port>
</ports>
</host>
<runstats><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""


def test_parse_nmap_xml_hosts_and_ports():
    out = parse_nmap_xml(SAMPLE_XML)
    assert len(out["hosts"]) == 1
    host = out["hosts"][0]
    assert host["ip"] == "1.2.3.4"
    assert host["hostname"] == "example.com"
    assert host["status"] == "up"
    assert len(host["ports"]) == 2
    p80 = host["ports"][0]
    assert p80 == {
        "port": 80,
        "protocol": "tcp",
        "state": "open",
        "service": "http",
        "product": "nginx",
        "version": "1.24.0",
    }
    p443 = host["ports"][1]
    assert p443["state"] == "closed"
    assert p443["product"] is None


def test_parse_nmap_xml_runstats():
    out = parse_nmap_xml(SAMPLE_XML)
    assert out["runstats"] == {"up": 1, "down": 0, "total": 1}


def test_parse_nmap_xml_invalid_returns_none():
    assert parse_nmap_xml("not xml at all") is None
    assert parse_nmap_xml("") is None
    assert parse_nmap_xml("<other><tag/></other>") is None


def test_port_scan_returns_structured(monkeypatch):
    from packetforge.core.audit import AuditLog
    from packetforge.core.security import RateLimiter
    from packetforge.tools.nmap_scan import NmapScanTools

    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    monkeypatch.setattr(tools.nmap, "port_scan", lambda t, p, s: SAMPLE_XML)
    out = tools.nmap_port_scan("127.0.0.1", "80,443")
    assert out["status"] == "ok"
    assert out["data"]["structured"]["hosts"][0]["ip"] == "1.2.3.4"
    assert "raw" in out["data"]


def test_port_scan_falls_back_to_raw(monkeypatch):
    from packetforge.core.audit import AuditLog
    from packetforge.core.security import RateLimiter
    from packetforge.tools.nmap_scan import NmapScanTools

    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    monkeypatch.setattr(
        tools.nmap, "port_scan", lambda t, p, s: "Starting Nmap... plain text"
    )
    out = tools.nmap_port_scan("127.0.0.1", "80")
    assert out["status"] == "ok"
    assert "structured" not in out["data"]
    assert "raw" in out["data"]


def test_service_detection_structured(monkeypatch):
    from packetforge.core.audit import AuditLog
    from packetforge.core.security import RateLimiter
    from packetforge.tools.nmap_scan import NmapScanTools

    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    monkeypatch.setattr(tools.nmap, "service_detection", lambda t, p: SAMPLE_XML)
    out = tools.nmap_service_detection("127.0.0.1", "80,443")
    assert out["data"]["structured"]["hosts"][0]["ports"][0]["service"] == "http"
