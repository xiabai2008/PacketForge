"""Tests for stream tools."""

from packetforge.core.audit import AuditLog
from packetforge.interfaces.tshark_interface import TsharkError
from packetforge.tools.streams import StreamTools


def make_tools():
    return StreamTools(audit=AuditLog())


def test_follow_tcp_stream_errors_on_bad_file(tmp_path):
    tools = make_tools()
    out = tools.follow_tcp_stream(str(tmp_path / "missing.pcap"), 0)
    assert out["status"] == "error"


def test_list_streams_errors_on_bad_file(tmp_path):
    tools = make_tools()
    out = tools.list_tcp_streams(str(tmp_path / "missing.pcap"))
    assert out["status"] == "error"


def test_follow_tcp_stream_ok(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = make_tools()
    seen = {}

    def fake_follow(f, idx, proto, fmt):
        seen["proto"] = proto
        seen["idx"] = idx
        return "GET / HTTP/1.1"

    monkeypatch.setattr(tools.tshark, "follow_stream", fake_follow)
    out = tools.follow_tcp_stream(str(p), 3)
    assert out["status"] == "ok"
    assert out["data"]["stream"] == "GET / HTTP/1.1"
    assert seen["proto"] == "tcp" and seen["idx"] == 3


def test_follow_udp_stream_ok(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = make_tools()
    monkeypatch.setattr(tools.tshark, "follow_stream", lambda f, i, proto, fmt: "dns")
    out = tools.follow_udp_stream(str(p), 0)
    assert out["status"] == "ok"


def test_follow_tcp_stream_error(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = make_tools()
    monkeypatch.setattr(
        tools.tshark,
        "follow_stream",
        lambda *a: (_ for _ in ()).throw(TsharkError("no stream")),
    )
    out = tools.follow_tcp_stream(str(p), 0)
    assert out["status"] == "error"


def test_list_tcp_streams_ok(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = make_tools()
    monkeypatch.setattr(tools.tshark, "list_streams", lambda f: "0  1.2.3.4:80")
    out = tools.list_tcp_streams(str(p))
    assert out["status"] == "ok"
    assert out["data"]["streams"] == "0  1.2.3.4:80"
