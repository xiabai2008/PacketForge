"""Tests for audit report export tool."""

from packetforge.core.security import validate_output_path


def test_validate_output_path_allows_json(tmp_path):
    target = tmp_path / "report.json"
    assert validate_output_path(str(target), allowed_exts={".json"}) == str(
        target.resolve()
    )


def test_validate_output_path_default_still_pcap_only(tmp_path):
    import pytest

    from packetforge.core.security import SecurityError

    with pytest.raises(SecurityError):
        validate_output_path(str(tmp_path / "x.json"))


def test_save_audit_report_tool(tmp_path, monkeypatch):
    import asyncio

    from mcp_server.server import build_server

    mcp = build_server()
    # record something in the server's audit log first

    tools = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "save_audit_report" in tools
