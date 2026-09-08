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


def test_extract_ftp_credentials_at_text_start():
    # USER/PASS at the very beginning of the payload (no leading newline)
    text = "USER bob\nPASS pwd123\n"
    creds = extract_credentials_from_text(text)
    assert any(
        c["type"] == "ftp" and c["user"] == "bob" and c["password"] == "pwd123"
        for c in creds
    )


def test_extract_telnet_credentials():
    text = "User Access Verification\n\nUsername: admin\nPassword: hunter2\n"
    creds = extract_credentials_from_text(text)
    assert any(
        c["type"] == "telnet" and c["user"] == "admin" and c["password"] == "hunter2"
        for c in creds
    )


def test_extract_telnet_login_prompt():
    text = "\nlogin: root\nPassword: toor\nLast login: never"
    creds = extract_credentials_from_text(text)
    assert any(
        c["type"] == "telnet" and c["user"] == "root" and c["password"] == "toor"
        for c in creds
    )


def test_extract_http_digest_challenge():
    text = (
        'WWW-Authenticate: Digest realm="Protected Area", '
        'nonce="MTcwOTM4MzQ0NiA4YjBhZTA=", qop="auth"'
    )
    auths = extract_credentials_from_text(text)
    entry = next(a for a in auths if a["type"] == "http_digest")
    assert entry["realm"] == "Protected Area"
    assert entry["nonce"].startswith("MTcw")
    assert entry["password"] == ""


def test_extract_http_ntlm_challenge():
    text = "WWW-Authenticate: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="
    auths = extract_credentials_from_text(text)
    entry = next(a for a in auths if a["type"] == "http_ntlm")
    assert entry["challenge_present"] is True
    assert entry["password"] == ""


def test_extract_auth_no_false_positive_on_basic():
    text = "WWW-Authenticate: Basic realm=test"
    creds = extract_credentials_from_text(text)
    assert not any(c["type"] in ("http_digest", "http_ntlm") for c in creds)


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


def test_creds_tools_digest_metadata_kept(monkeypatch, tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x" * 24)
    tools = CredsTools(audit=AuditLog())
    payload = b'WWW-Authenticate: Digest realm="Area", nonce="abc123", qop="auth"'
    monkeypatch.setattr(tools.tshark, "_run", lambda cmd: payload.hex())
    out = tools.extract_credentials(str(p))
    cred = out["data"]["credentials"][0]
    assert cred["type"] == "http_digest"
    assert cred["realm"] == "Area"
    assert cred["nonce"] == "abc123"
    assert cred["password"] == ""


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
