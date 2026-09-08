"""Tests for the optional poxiao IPCollector adapter (IntelSource)."""

import json
import sys
import types
import urllib.request
from pathlib import Path

import pytest

from packetforge.interfaces.poxiao_source import PoxiaoIPSource, load_poxiao_source
from packetforge.interfaces.threat_intel import ThreatIntelInterface


def _resp(payload):
    import io
    import urllib.response

    body = json.dumps(payload).encode()
    return urllib.response.addinfourl(
        io.BytesIO(body),
        headers={"Content-Type": "application/json"},
        url="mock",
        code=200,
    )


class _FakeIPCollector:
    """Stands in for src.vernalequinox.ip_info.IPCollector."""

    def __init__(self, timeout=10.0, **kwargs):
        self.timeout = timeout

    async def collect(self, ip: str):
        class R:
            def to_dict(self):
                return {"ip": ip, "country": "US", "isp": "TestNet", "asn": "AS64500"}

        return R()


def install_fake_poxiao(monkeypatch, collector_cls=_FakeIPCollector):
    """Put a fake `src.vernalequinox.ip_info` module on sys.path."""
    src = types.ModuleType("src")
    ve = types.ModuleType("src.vernalequinox")
    ip_info = types.ModuleType("src.vernalequinox.ip_info")
    ip_info.IPCollector = collector_cls
    ve.ip_info = ip_info
    src.vernalequinox = ve
    monkeypatch.setitem(sys.modules, "src", src)
    monkeypatch.setitem(sys.modules, "src.vernalequinox", ve)
    monkeypatch.setitem(sys.modules, "src.vernalequinox.ip_info", ip_info)


def test_load_source_success(monkeypatch):
    install_fake_poxiao(monkeypatch)
    source = load_poxiao_source()
    assert source is not None
    assert source.name == "poxiao_ipinfo"


def test_load_source_missing_package(monkeypatch, tmp_path):
    # sys.modules value None marks a module as not importable (ImportError)
    monkeypatch.setitem(sys.modules, "src", None)
    monkeypatch.setitem(sys.modules, "src.vernalequinox", None)
    monkeypatch.setitem(sys.modules, "src.vernalequinox.ip_info", None)
    assert load_poxiao_source(poxiao_root=tmp_path) is None


@pytest.mark.skipif(
    not Path(r"D:\HZR_PROJECTS\poxiao\poxiao\src").is_dir(),
    reason="poxiao not installed on this machine",
)
def test_real_poxiao_import():
    source = load_poxiao_source(poxiao_root=Path(r"D:\HZR_PROJECTS\poxiao\poxiao"))
    assert source is not None
    assert source.name == "poxiao_ipinfo"


def test_check_ip_clean():
    source = PoxiaoIPSource(collector_factory=lambda: _FakeIPCollector())
    out = source.check("8.8.8.8")
    assert out["status"] == "ok"
    assert out["malicious"] is None  # enrichment data, no verdict signal
    assert out["detail"]["isp"] == "TestNet"


def test_check_ip_collector_failure_degrades():
    class BrokenCollector:
        def __init__(self, **kwargs):
            pass

        async def collect(self, ip):
            raise RuntimeError("network down")

    source = PoxiaoIPSource(collector_factory=lambda: BrokenCollector())
    out = source.check("8.8.8.8")
    assert out["status"] == "degraded"
    assert out["checked"] is False
    assert out["malicious"] is None


def test_merged_into_threat_intel(monkeypatch):
    install_fake_poxiao(monkeypatch)
    source = load_poxiao_source()
    itf = ThreatIntelInterface(extra_sources=[source])

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, timeout=10, context=None: _resp({"query_status": "no_results"}),
    )
    out = itf.check_ip("8.8.8.8")
    assert out["sources"] == ["urlhaus", "poxiao_ipinfo"]
    assert out["poxiao_ipinfo"]["detail"]["country"] == "US"
    assert out["verdict"] == "clean"
