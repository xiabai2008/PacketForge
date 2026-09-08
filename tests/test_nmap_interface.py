"""Tests for nmap interface command construction."""

from pathlib import Path

from packetforge.core.audit import AuditLog
from packetforge.core.security import RateLimiter
from packetforge.interfaces.nmap_interface import NmapError, NmapInterface
from packetforge.tools.nmap_scan import NmapScanTools


def test_build_port_scan_connect():
    itf = NmapInterface()
    cmd = itf._build_scan_cmd("1.2.3.4", "80,443", "connect")
    assert Path(cmd[0]).name.lower() in ("nmap", "nmap.exe")
    assert "-sT" in cmd
    assert "-p" in cmd and "80,443" in cmd


def test_build_port_scan_syn():
    itf = NmapInterface()
    cmd = itf._build_scan_cmd("1.2.3.4", "80", "syn")
    assert "-sS" in cmd


def test_build_port_scan_udp_with_extra():
    itf = NmapInterface()
    cmd = itf._build_scan_cmd(
        "1.2.3.4", "53", "udp", extra=["--script", "dns-zone-transfer"]
    )
    assert "-sU" in cmd
    assert "--script" in cmd and "dns-zone-transfer" in cmd


def test_build_defaults_to_connect():
    itf = NmapInterface()
    cmd = itf._build_scan_cmd("1.2.3.4", "80", "bogus")
    assert "-sT" in cmd


def test_scan_tools_rate_limited():
    tools = NmapScanTools(
        audit=AuditLog(), limiter=RateLimiter(max_calls=1, window_seconds=60)
    )
    tools.nmap_port_scan("1.2.3.4", "80")
    out = tools.nmap_port_scan("1.2.3.4", "80")
    assert out["status"] == "error"
    assert "rate" in out["error"].lower()


def test_nmap_port_scan_ok(monkeypatch):
    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    monkeypatch.setattr(tools.nmap, "port_scan", lambda t, p, s: "Nmap done")
    out = tools.nmap_port_scan("127.0.0.1", "80")
    assert out["status"] == "ok"
    assert out["data"]["raw"] == "Nmap done"


def test_nmap_port_scan_rejects_injection(monkeypatch):
    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    called = {}

    def fake_scan(t, p, s):
        called["yes"] = True
        return "x"

    monkeypatch.setattr(tools.nmap, "port_scan", fake_scan)
    out = tools.nmap_port_scan("1.2.3.4; rm -rf /", "80")
    assert out["status"] == "error"
    assert "called" not in called


def test_nmap_port_scan_error(monkeypatch):
    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    monkeypatch.setattr(
        tools.nmap,
        "port_scan",
        lambda *a: (_ for _ in ()).throw(NmapError("permission denied")),
    )
    out = tools.nmap_port_scan("127.0.0.1", "80")
    assert out["status"] == "error"
    assert "permission denied" in out["error"]


def test_nmap_service_detection_ok(monkeypatch):
    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    monkeypatch.setattr(tools.nmap, "service_detection", lambda t, p: "http")
    out = tools.nmap_service_detection("127.0.0.1", "80")
    assert out["status"] == "ok"


def test_nmap_os_detection_ok(monkeypatch):
    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    monkeypatch.setattr(tools.nmap, "os_detection", lambda t: "Windows")
    out = tools.nmap_os_detection("127.0.0.1")
    assert out["status"] == "ok"


def test_nmap_quick_scan_ok(monkeypatch):
    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    monkeypatch.setattr(tools.nmap, "quick_scan", lambda t: "done")
    out = tools.nmap_quick_scan("127.0.0.1")
    assert out["status"] == "ok"


def test_nmap_vulnerability_scan_ok(monkeypatch):
    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    monkeypatch.setattr(
        tools.nmap, "vulnerability_scan", lambda t, p: "CVE-2021-44228 found"
    )
    out = tools.nmap_vulnerability_scan("127.0.0.1", "80,443")
    assert out["status"] == "ok"
    assert "CVE" in out["data"]["raw"]


def test_nmap_vulnerability_scan_rejects_injection(monkeypatch):
    tools = NmapScanTools(audit=AuditLog(), limiter=RateLimiter())
    monkeypatch.setattr(
        tools.nmap,
        "vulnerability_scan",
        lambda *a: (_ for _ in ()).throw(AssertionError("should not run")),
    )
    out = tools.nmap_vulnerability_scan("1.2.3.4; id", "80")
    assert out["status"] == "error"


def test_nmap_vulnerability_scan_rate_limited(monkeypatch):
    tools = NmapScanTools(
        audit=AuditLog(), limiter=RateLimiter(max_calls=1, window_seconds=60)
    )
    monkeypatch.setattr(tools.nmap, "vulnerability_scan", lambda t, p: "ok")
    tools.nmap_vulnerability_scan("127.0.0.1", "80")
    out = tools.nmap_vulnerability_scan("127.0.0.1", "80")
    assert out["status"] == "error"
    assert "rate" in out["error"].lower()


def test_nmap_interface_run_missing_binary(monkeypatch):
    import subprocess

    itf = NmapInterface()
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError())
    )
    try:
        itf._run(["nmap", "-V"])
        assert False, "expected NmapError"
    except NmapError as e:
        assert "nmap not found" in str(e)


def test_nmap_interface_run_timeout(monkeypatch):
    import subprocess

    itf = NmapInterface()
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="nmap", timeout=300)
        ),
    )
    try:
        itf._run(["nmap", "-V"])
        assert False, "expected NmapError"
    except NmapError as e:
        assert "timed out" in str(e)


def test_nmap_interface_run_nonzero(monkeypatch):
    import subprocess

    class FakeProc:
        returncode = 1
        stderr = b"permission denied"
        stdout = b""

    itf = NmapInterface()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())
    try:
        itf._run(["nmap", "-V"])
        assert False, "expected NmapError"
    except NmapError as e:
        assert "permission denied" in str(e)


def test_nmap_interface_run_ok(monkeypatch):
    import subprocess

    class FakeProc:
        returncode = 0
        stderr = b""
        stdout = b"Starting Nmap 7.99"

    itf = NmapInterface()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())
    assert itf._run(["nmap", "-V"]) == "Starting Nmap 7.99"
