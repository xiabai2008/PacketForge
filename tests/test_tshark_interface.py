"""Tests for tshark interface (mock subprocess)."""

import shutil
import subprocess

import pytest

from packetforge.interfaces.tshark_interface import TsharkError, TsharkInterface


def test_capture_live_builds_command(monkeypatch):
    calls = {}

    def fake_run(cmd, capture_output, text, timeout, shell):
        calls["cmd"] = cmd

    # We test command construction via a patched low-level runner
    itf = TsharkInterface()
    cmd = itf._build_capture_cmd("eth0", 10, "tcp port 80", 5, "json")
    assert cmd[0].endswith("tshark") or "tshark" in cmd[0]
    assert "-i" in cmd and "eth0" in cmd
    assert "-c" in cmd and "10" in cmd


def test_analyze_pcap_command(tmp_path):
    itf = TsharkInterface()
    cmd = itf._build_analyze_cmd(str(tmp_path / "x.pcap"), "http.request", 10)
    assert "-r" in cmd
    assert "-Y" in cmd and "http.request" in cmd


def test_tshark_available_detection(monkeypatch):
    monkeypatch.setattr(
        shutil, "which", lambda name: "/usr/bin/tshark" if name == "tshark" else None
    )
    itf = TsharkInterface()
    assert itf.is_available() is True


def test_build_capture_cmd_text_format():
    itf = TsharkInterface()
    cmd = itf._build_capture_cmd("eth0", 5, "", 0, "text")
    assert "-T" in cmd and "text" in cmd
    assert "-f" not in cmd
    assert "-a" not in cmd


def test_build_analyze_cmd_no_filter():
    itf = TsharkInterface()
    cmd = itf._build_analyze_cmd("x.pcap", None, 0)
    assert "-Y" not in cmd
    assert "-c" not in cmd


def test_run_missing_binary(monkeypatch):
    itf = TsharkInterface()
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError())
    )
    with pytest.raises(TsharkError) as exc:
        itf._run(["tshark", "-V"])
    assert "tshark not found" in str(exc.value)


def test_run_timeout(monkeypatch):
    itf = TsharkInterface()
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="tshark", timeout=60)
        ),
    )
    with pytest.raises(TsharkError) as exc:
        itf._run(["tshark", "-V"])
    assert "timed out" in str(exc.value)


def test_run_nonzero_exit(monkeypatch):
    class FakeProc:
        returncode = 1
        stderr = b"error: bad filter"
        stdout = b""

    itf = TsharkInterface()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())
    with pytest.raises(TsharkError) as exc:
        itf._run(["tshark", "-V"])
    assert "error: bad filter" in str(exc.value)


def test_run_ok(monkeypatch):
    class FakeProc:
        returncode = 0
        stderr = b""
        stdout = b'[{"_source": {}}]'

    itf = TsharkInterface()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())
    assert itf._run(["tshark", "-V"]) == '[{"_source": {}}]'


def test_decode_output_utf8():
    from packetforge.interfaces.tshark_interface import _decode_output

    assert _decode_output("本地连接".encode()) == "本地连接"


def test_decode_output_falls_back_to_locale(monkeypatch):
    import locale

    from packetforge.interfaces.tshark_interface import _decode_output

    monkeypatch.setattr(locale, "getpreferredencoding", lambda *a: "gbk")
    gbk_bytes = "本地连接".encode("gbk")
    assert _decode_output(gbk_bytes) == "本地连接"


def test_decode_output_undecodable(monkeypatch):
    from packetforge.interfaces.tshark_interface import _decode_output

    # invalid in both utf-8 and any locale; must not raise
    assert _decode_output(b"\xff\xfe\x00\x01") is not None


def test_check_display_filter_skips_when_unavailable(monkeypatch):
    itf = TsharkInterface()
    monkeypatch.setattr(itf, "is_available", lambda: False)
    called = {}

    def fake_run(cmd):
        called["yes"] = True

    monkeypatch.setattr(itf, "_run", fake_run)
    itf.check_display_filter("http.request")
    assert "yes" not in called


def test_check_display_filter_empty_is_noop(monkeypatch):
    itf = TsharkInterface()
    monkeypatch.setattr(itf, "is_available", lambda: True)
    monkeypatch.setattr(
        itf, "_run", lambda cmd: (_ for _ in ()).throw(AssertionError("should not run"))
    )
    itf.check_display_filter("")
    itf.check_display_filter(None)


def test_check_display_filter_valid(monkeypatch):
    itf = TsharkInterface()
    monkeypatch.setattr(itf, "is_available", lambda: True)
    monkeypatch.setattr(itf, "_run", lambda cmd: "")
    itf.check_display_filter("http.request")


def test_check_display_filter_invalid(monkeypatch):
    itf = TsharkInterface()
    monkeypatch.setattr(itf, "is_available", lambda: True)

    def fake_run(cmd):
        raise TsharkError('"bogus!!" is not a valid display filter')

    monkeypatch.setattr(itf, "_run", fake_run)
    with pytest.raises(TsharkError) as exc:
        itf.check_display_filter("bogus!!")
    assert "not a valid display filter" in str(exc.value)
