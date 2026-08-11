"""TCP/UDP stream reassembly tools."""

from packetforge.core.audit import AuditLog
from packetforge.core.output_formatter import format_error, format_result
from packetforge.core.security import validate_file_path
from packetforge.interfaces.tshark_interface import TsharkInterface


class StreamTools:
    """Follow and list TCP/UDP streams."""

    def __init__(self, audit: AuditLog, tshark: TsharkInterface | None = None) -> None:
        self.audit = audit
        self.tshark = tshark or TsharkInterface()

    def follow_tcp_stream(self, filepath: str, stream_index: int, fmt: str = "ascii"):
        try:
            path = validate_file_path(filepath)
            raw = self.tshark.follow_stream(path, stream_index, "tcp", fmt)
            aid = self.audit.record(
                "follow_tcp_stream", {"filepath": path, "index": stream_index}
            )
            return format_result("follow_tcp_stream", {"stream": raw}, aid)
        except Exception as e:
            aid = self.audit.record("follow_tcp_stream_error", {"error": str(e)})
            return format_error("follow_tcp_stream", str(e), aid)

    def follow_udp_stream(self, filepath: str, stream_index: int, fmt: str = "ascii"):
        try:
            path = validate_file_path(filepath)
            raw = self.tshark.follow_stream(path, stream_index, "udp", fmt)
            aid = self.audit.record(
                "follow_udp_stream", {"filepath": path, "index": stream_index}
            )
            return format_result("follow_udp_stream", {"stream": raw}, aid)
        except Exception as e:
            aid = self.audit.record("follow_udp_stream_error", {"error": str(e)})
            return format_error("follow_udp_stream", str(e), aid)

    def list_tcp_streams(self, filepath: str):
        try:
            path = validate_file_path(filepath)
            raw = self.tshark.list_streams(path)
            aid = self.audit.record("list_tcp_streams", {"filepath": path})
            return format_result("list_tcp_streams", {"streams": raw}, aid)
        except Exception as e:
            aid = self.audit.record("list_tcp_streams_error", {"error": str(e)})
            return format_error("list_tcp_streams", str(e), aid)
