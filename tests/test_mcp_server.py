"""Tests for MCP server registration."""

import asyncio

from mcp_server.server import build_server


def test_build_server_registers_tools():
    mcp = build_server()
    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    assert "capture_live" in names
    assert "analyze_pcap_file" in names
    assert "nmap_port_scan" in names
    assert "extract_credentials" in names
    assert "check_ip_threat_intel" in names
