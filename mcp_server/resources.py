"""MCP resources for network context."""

from fastmcp import FastMCP


def register_resources(mcp: FastMCP) -> None:
    @mcp.resource("network://help")
    def help_doc() -> str:
        return (
            "PacketForge MCP. Tools: capture_live, analyze_pcap_file, "
            "get_protocol_statistics, follow_tcp_stream, export_packets_json, "
            "nmap_port_scan, nmap_service_detection, extract_credentials, "
            "check_ip_threat_intel, scan_capture_for_threats. "
            "All scans are rate-limited. Use only in authorized environments."
        )
