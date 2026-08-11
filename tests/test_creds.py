"""Tests for credential extraction."""

from packetforge.core.audit import AuditLog
from packetforge.interfaces.creds_interface import extract_credentials_from_text
from packetforge.interfaces.tshark_interface import TsharkError
from packetforge.tools.creds import CredsTools


def test_extract_http_basic_auth():
    text = "Authorization: Basic dXNlcjpwYXNz"  # base64("user:pass")
    creds = extract_credentials_from_text(text)
    assert any(
        c["type"] == "http_basic" and c["user"] == "user" and c["password"] == "pass"
        for c in creds
    )


def test_extract_no_credentials():
    assert extract_credentials_from_text("no credentials here") == []


def test_extract_ftp_credentials():
    text = "220 FTP ready\nUSER alice\nPASS secret\n230 logged in"
    creds = extract_credentials_from_text(text)
    assert any(
        c["type"] == "ftp" and c["user"] == "alice" and c["password"] == "secret"
        for c in creds
    )


def test_creds_tools_ok_redacts_password(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = CredsTools(audit=AuditLog())
    # hex payload of "Authorization: Basic YWxpY2U6czNjcmV0LXB3" (alice:s3cret-pw)
    hex_payload = b"Authorization: Basic YWxpY2U6czNjcmV0LXB3".hex()
    monkeypatch.setattr(tools.tshark, "_run", lambda cmd: hex_payload)
    out = tools.extract_credentials(str(p))
    assert out["status"] == "ok"
    assert out["data"]["count"] == 1
    cred = out["data"]["credentials"][0]
    assert cred["type"] == "http_basic"
    assert cred["user"] == "alice"
    assert cred["password"] == "***"


def test_creds_tools_ok_no_credentials(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = CredsTools(audit=AuditLog())
    monkeypatch.setattr(tools.tshark, "_run", lambda cmd: b"hello world".hex())
    out = tools.extract_credentials(str(p))
    assert out["status"] == "ok"
    assert out["data"]["count"] == 0


def test_creds_tools_error(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = CredsTools(audit=AuditLog())
    monkeypatch.setattr(
        tools.tshark, "_run", lambda cmd: (_ for _ in ()).throw(TsharkError("bad pcap"))
    )
    out = tools.extract_credentials(str(p))
    assert out["status"] == "error"


def test_creds_tools_missing_file(tmp_path):
    tools = CredsTools(audit=AuditLog())
    out = tools.extract_credentials(str(tmp_path / "nope.pcap"))
    assert out["status"] == "error"
