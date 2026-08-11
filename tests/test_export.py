"""Tests for export tools."""

from packetforge.core.audit import AuditLog
from packetforge.interfaces.tshark_interface import TsharkError
from packetforge.tools.export import ExportTools


def make_tools():
    return ExportTools(audit=AuditLog())


def test_export_json_errors_on_bad_file(tmp_path):
    tools = make_tools()
    out = tools.export_packets_json(str(tmp_path / "missing.pcap"))
    assert out["status"] == "error"


def test_export_json_ok(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = make_tools()
    monkeypatch.setattr(tools.tshark, "analyze_pcap", lambda f, d, m: "[{}]")
    out = tools.export_packets_json(str(p))
    assert out["status"] == "ok"
    assert out["data"]["packets"] == "[{}]"


def test_export_json_error(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = make_tools()
    monkeypatch.setattr(
        tools.tshark,
        "analyze_pcap",
        lambda *a: (_ for _ in ()).throw(TsharkError("nope")),
    )
    out = tools.export_packets_json(str(p))
    assert out["status"] == "error"


def test_export_csv_ok(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = make_tools()
    seen = {}

    def fake_run(cmd):
        seen["cmd"] = cmd
        return "1,1.2.3.4,5.6.7.8"

    monkeypatch.setattr(tools.tshark, "_run", fake_run)
    out = tools.export_packets_csv(str(p), fields="frame.number,ip.src,ip.dst")
    assert out["status"] == "ok"
    assert out["data"]["csv"] == "1,1.2.3.4,5.6.7.8"
    assert "-T" in seen["cmd"] and "fields" in seen["cmd"]
    assert "-e" in seen["cmd"] and "frame.number" in seen["cmd"]
    assert "-E" in seen["cmd"] and "header=y" in seen["cmd"]
    assert "ip.src" in seen["cmd"] and "ip.dst" in seen["cmd"]


def test_export_csv_error(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = make_tools()
    monkeypatch.setattr(
        tools.tshark, "_run", lambda *a: (_ for _ in ()).throw(TsharkError("nope"))
    )
    out = tools.export_packets_csv(str(p))
    assert out["status"] == "error"
