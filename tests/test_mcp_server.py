"""Tests for MCP server registration."""

import asyncio

from mcp_server.server import build_server, parse_args


def test_build_server_registers_tools():
    mcp = build_server()
    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    assert "capture_live" in names
    assert "analyze_pcap_file" in names
    assert "nmap_port_scan" in names
    assert "nmap_vulnerability_scan" in names
    assert "extract_credentials" in names
    assert "check_ip_threat_intel" in names


def test_parse_args_defaults_to_stdio():
    args = parse_args([])
    assert args.transport == "stdio"


def test_parse_args_http_transport():
    args = parse_args(["--transport", "http", "--host", "0.0.0.0", "--port", "9000"])
    assert args.transport == "http"
    assert args.host == "0.0.0.0"
    assert args.port == 9000


def test_parse_args_rejects_unknown_transport():
    import pytest

    with pytest.raises(SystemExit):
        parse_args(["--transport", "carrier-pigeon"])
