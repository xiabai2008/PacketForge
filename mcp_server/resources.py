"""MCP resources for network context and audit reporting."""

import json

from fastmcp import FastMCP

from packetforge.core.audit import AuditLog


def register_resources(mcp: FastMCP, audit: AuditLog | None = None) -> None:
    @mcp.resource("network://help")
    def help_doc() -> str:
        return (
            "PacketForge MCP. Tools: capture_live, analyze_pcap_file, "
            "get_protocol_statistics, follow_tcp_stream, export_packets_json, "
            "nmap_port_scan, nmap_service_detection, nmap_vulnerability_scan, "
            "extract_credentials, check_ip_threat_intel, "
            "scan_capture_for_threats. "
            "All scans are rate-limited. Use only in authorized environments."
        )

    @mcp.resource("audit://report")
    def audit_report() -> str:
        """Live compliance report over the server's audit hash-chain."""
        log = audit or AuditLog()
        return json.dumps(log.report(), ensure_ascii=False)
