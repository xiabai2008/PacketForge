"""Network interface and capture tools."""

from packetforge.core.audit import AuditLog
from packetforge.core.output_formatter import format_error, format_result
from packetforge.core.security import RateLimiter, validate_file_path
from packetforge.interfaces.tshark_interface import TsharkError, TsharkInterface


class CaptureTools:
    """Tools for listing interfaces and capturing/analyzing packets."""

    def __init__(
        self,
        audit: AuditLog,
        limiter: RateLimiter,
        tshark: TsharkInterface | None = None,
    ) -> None:
        self.audit = audit
        self.limiter = limiter
        # capture is not rate-limited; only nmap is
        self.tshark = tshark or TsharkInterface()

    def get_network_interfaces(self):
        try:
            raw = self.tshark._run([self.tshark.binary, "-D"])
            interfaces = [
                line.split(".")[-1].strip() for line in raw.splitlines() if line.strip()
            ]
            aid = self.audit.record("get_network_interfaces", {})
            return format_result(
                "get_network_interfaces", {"interfaces": interfaces}, aid
            )
        except (TsharkError, Exception) as e:
            aid = self.audit.record("get_network_interfaces_error", {"error": str(e)})
            return format_error("get_network_interfaces", str(e), aid)

    def capture_live(
        self,
        interface: str,
        count: int = 50,
        capture_filter: str = "",
        timeout: int = 30,
        fmt: str = "json",
    ):
        if not interface:
            aid = self.audit.record(
                "capture_live_error", {"error": "interface required"}
            )
            return format_error("capture_live", "interface is required", aid)
        try:
            raw = self.tshark.capture_live(
                interface, count, capture_filter, timeout, fmt
            )
            aid = self.audit.record(
                "capture_live", {"interface": interface, "count": count}
            )
            return format_result(
                "capture_live", {"raw": raw, "interface": interface}, aid
            )
        except Exception as e:
            aid = self.audit.record("capture_live_error", {"error": str(e)})
            return format_error("capture_live", str(e), aid)

    def analyze_pcap_file(
        self, filepath: str, display_filter: str = "", max_packets: int = 100
    ):
        try:
            path = validate_file_path(filepath)
            raw = self.tshark.analyze_pcap(path, display_filter, max_packets)
            aid = self.audit.record("analyze_pcap_file", {"filepath": path})
            return format_result("analyze_pcap_file", {"raw": raw}, aid)
        except Exception as e:
            aid = self.audit.record("analyze_pcap_file_error", {"error": str(e)})
            return format_error("analyze_pcap_file", str(e), aid)

    def get_protocol_statistics(self, filepath: str):
        try:
            path = validate_file_path(filepath)
            raw = self.tshark.protocol_stats(path)
            aid = self.audit.record("get_protocol_statistics", {"filepath": path})
            return format_result("get_protocol_statistics", {"stats": raw}, aid)
        except Exception as e:
            aid = self.audit.record("get_protocol_statistics_error", {"error": str(e)})
            return format_error("get_protocol_statistics", str(e), aid)
