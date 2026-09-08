"""FastMCP adapter exposing PacketForge tools to AI clients."""

import argparse

from fastmcp import FastMCP

from mcp_server.prompts import register_prompts
from mcp_server.resources import register_resources
from packetforge.core.audit import AuditLog
from packetforge.core.security import RateLimiter
from packetforge.tools.capture import CaptureTools
from packetforge.tools.creds import CredsTools
from packetforge.tools.export import ExportTools
from packetforge.tools.nmap_scan import NmapScanTools
from packetforge.tools.streams import StreamTools
from packetforge.tools.threat import ThreatTools


def build_server() -> FastMCP:
    mcp = FastMCP("packetforge")
    audit = AuditLog()
    limiter = RateLimiter(max_calls=10, window_seconds=3600)

    capture = CaptureTools(audit, limiter)
    streams = StreamTools(audit)
    export = ExportTools(audit)
    creds = CredsTools(audit)
    nmap = NmapScanTools(audit, limiter)
    threat = ThreatTools(audit)

    @mcp.tool()
    def capture_live(
        interface: str,
        count: int = 50,
        capture_filter: str = "",
        timeout: int = 30,
        fmt: str = "json",
    ) -> dict:
        return capture.capture_live(interface, count, capture_filter, timeout, fmt)

    @mcp.tool()
    def analyze_pcap_file(
        filepath: str, display_filter: str = "", max_packets: int = 100
    ) -> dict:
        return capture.analyze_pcap_file(filepath, display_filter, max_packets)

    @mcp.tool()
    def get_protocol_statistics(filepath: str) -> dict:
        return capture.get_protocol_statistics(filepath)

    @mcp.tool()
    def follow_tcp_stream(filepath: str, stream_index: int, fmt: str = "ascii") -> dict:
        return streams.follow_tcp_stream(filepath, stream_index, fmt)

    @mcp.tool()
    def export_packets_json(
        filepath: str, display_filter: str = "", max_packets: int = 100
    ) -> dict:
        return export.export_packets_json(filepath, display_filter, max_packets)

    @mcp.tool()
    def nmap_port_scan(
        target: str, ports: str = "1-1000", scan_type: str = "connect"
    ) -> dict:
        return nmap.nmap_port_scan(target, ports, scan_type)

    @mcp.tool()
    def nmap_service_detection(target: str, ports: str = "") -> dict:
        return nmap.nmap_service_detection(target, ports)

    @mcp.tool()
    def nmap_vulnerability_scan(target: str, ports: str = "") -> dict:
        return nmap.nmap_vulnerability_scan(target, ports)

    @mcp.tool()
    def nmap_nse_scan(target: str, ports: str = "", scripts: str = "default") -> dict:
        return nmap.nmap_nse_scan(target, ports, scripts)

    @mcp.tool()
    def extract_credentials(filepath: str) -> dict:
        return creds.extract_credentials(filepath)

    @mcp.tool()
    def check_ip_threat_intel(ip: str) -> dict:
        return threat.check_ip_threat_intel(ip)

    @mcp.tool()
    def scan_capture_for_threats(filepath: str) -> dict:
        return threat.scan_capture_for_threats(filepath)

    register_resources(mcp, audit)
    register_prompts(mcp)
    return mcp


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PacketForge MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http", "sse"],
        default="stdio",
        help="MCP transport (default: stdio for local clients)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host")
    parser.add_argument("--port", type=int, default=8000, help="HTTP bind port")
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    server = build_server()
    if args.transport == "stdio":
        server.run()
    else:
        server.run(transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
