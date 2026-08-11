"""Tests for capture tools."""

from packetforge.core.audit import AuditLog
from packetforge.core.security import RateLimiter
from packetforge.interfaces.tshark_interface import TsharkError
from packetforge.tools.capture import CaptureTools


def make_tools():
    return CaptureTools(audit=AuditLog(), limiter=RateLimiter())


def test_get_network_interfaces_returns_structured():
    # Plan note: tshark -D may fail without Npcap/tshark; asserts structured
    # output either way (ok with interfaces, or graceful error envelope).
    tools = make_tools()
    out = tools.get_network_interfaces()
    assert out["status"] in ("ok", "error")
    assert "data" in out or "error" in out


def test_capture_live_requires_interface():
    tools = make_tools()
    out = tools.capture_live(interface="", count=5)
    assert out["status"] == "error"
    assert "interface" in out["error"].lower()


def test_get_network_interfaces_ok(monkeypatch):
    tools = make_tools()
    monkeypatch.setattr(
        tools.tshark,
        "_run",
        lambda cmd: "1. eth0\n2. \\Device\\NPF_xxx (Local)\n",
    )
    out = tools.get_network_interfaces()
    assert out["status"] == "ok"
    assert out["data"]["interfaces"] == ["eth0", "\\Device\\NPF_xxx (Local)"]


def test_get_network_interfaces_error(monkeypatch):
    tools = make_tools()
    monkeypatch.setattr(
        tools.tshark,
        "_run",
        lambda cmd: (_ for _ in ()).throw(TsharkError("no tshark")),
    )
    out = tools.get_network_interfaces()
    assert out["status"] == "error"
    assert "no tshark" in out["error"]


def test_capture_live_ok(monkeypatch):
    tools = make_tools()
    monkeypatch.setattr(
        tools.tshark, "capture_live", lambda i, c, f, t, fmt: '{"packets": []}'
    )
    out = tools.capture_live(interface="eth0", count=10)
    assert out["status"] == "ok"
    assert out["data"]["interface"] == "eth0"
    assert out["data"]["raw"] == '{"packets": []}'


def test_capture_live_error(monkeypatch):
    tools = make_tools()
    monkeypatch.setattr(
        tools.tshark,
        "capture_live",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    out = tools.capture_live(interface="eth0")
    assert out["status"] == "error"
    assert "boom" in out["error"]


def test_analyze_pcap_file_ok(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = make_tools()
    monkeypatch.setattr(tools.tshark, "analyze_pcap", lambda f, d, m: "[{}]")
    out = tools.analyze_pcap_file(str(p))
    assert out["status"] == "ok"
    assert out["data"]["raw"] == "[{}]"


def test_analyze_pcap_file_rejects_bad_extension(tmp_path):
    tools = make_tools()
    bad = tmp_path / "a.txt"
    bad.write_text("x")
    out = tools.analyze_pcap_file(str(bad))
    assert out["status"] == "error"
    assert "file type" in out["error"].lower()


def test_analyze_pcap_file_missing_file(tmp_path):
    tools = make_tools()
    out = tools.analyze_pcap_file(str(tmp_path / "nope.pcap"))
    assert out["status"] == "error"


def test_get_protocol_statistics_ok(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = make_tools()
    monkeypatch.setattr(tools.tshark, "protocol_stats", lambda f: "tcp 100%")
    out = tools.get_protocol_statistics(str(p))
    assert out["status"] == "ok"
    assert out["data"]["stats"] == "tcp 100%"


def test_get_protocol_statistics_error(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = make_tools()
    monkeypatch.setattr(
        tools.tshark,
        "protocol_stats",
        lambda f: (_ for _ in ()).throw(TsharkError("bad pcap")),
    )
    out = tools.get_protocol_statistics(str(p))
    assert out["status"] == "error"
