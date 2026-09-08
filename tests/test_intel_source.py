"""Tests for pluggable third-party intel sources."""

from packetforge.interfaces.threat_intel import (
    IntelSource,
    ThreatIntelInterface,
)


class BlocklistSource:
    """Example third-party source: a local blocklist."""

    name = "blocklist"

    def __init__(self, blocked: set[str]):
        self.blocked = blocked

    def check(self, ip: str) -> dict:
        return {
            "status": "ok",
            "malicious": ip in self.blocked,
            "detail": "listed" if ip in self.blocked else "not listed",
        }


class BrokenSource:
    name = "broken"

    def check(self, ip: str) -> dict:
        raise RuntimeError("source exploded")


def test_extra_source_clean():
    itf = ThreatIntelInterface(
        urlhaus_host="http://invalid", extra_sources=[BlocklistSource(set())]
    )
    out = itf.check_ip("1.2.3.4")
    assert out["sources"] == ["urlhaus", "blocklist"]
    assert out["blocklist"]["malicious"] is False
    assert out["verdict"] == "clean"


def test_extra_source_malicious(monkeypatch):
    def fake_urlopen(req, timeout=10, context=None):
        return _resp({"query_status": "no_results"})

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    itf = ThreatIntelInterface(extra_sources=[BlocklistSource({"1.2.3.4"})])
    out = itf.check_ip("1.2.3.4")
    assert out["verdict"] == "malicious"


def test_broken_source_does_not_break_check(monkeypatch):
    def fake_urlopen(req, timeout=10, context=None):
        return _resp({"query_status": "no_results"})

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    itf = ThreatIntelInterface(extra_sources=[BrokenSource()])
    out = itf.check_ip("1.2.3.4")
    assert out["verdict"] == "clean"
    assert out["broken"]["checked"] is False


def test_intel_source_protocol():
    # IntelSource is a runtime-checkable protocol; BlocklistSource conforms
    assert isinstance(BlocklistSource(set()), IntelSource)


def _resp(payload):
    import io
    import json
    import urllib.response

    body = json.dumps(payload).encode()
    return urllib.response.addinfourl(
        io.BytesIO(body),
        headers={"Content-Type": "application/json"},
        url="mock",
        code=200,
    )
