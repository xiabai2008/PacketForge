"""Packet export tools (JSON/CSV)."""

from packetforge.core.audit import AuditLog
from packetforge.core.output_formatter import format_error, format_result
from packetforge.core.security import validate_file_path
from packetforge.interfaces.tshark_interface import TsharkInterface


class ExportTools:
    """Export packet data to JSON/CSV."""

    def __init__(self, audit: AuditLog, tshark: TsharkInterface | None = None) -> None:
        self.audit = audit
        self.tshark = tshark or TsharkInterface()

    def export_packets_json(
        self, filepath: str, display_filter: str = "", max_packets: int = 100
    ):
        try:
            path = validate_file_path(filepath)
            raw = self.tshark.analyze_pcap(path, display_filter, max_packets)
            aid = self.audit.record("export_packets_json", {"filepath": path})
            return format_result("export_packets_json", {"packets": raw}, aid)
        except Exception as e:
            aid = self.audit.record("export_packets_json_error", {"error": str(e)})
            return format_error("export_packets_json", str(e), aid)

    def export_packets_csv(
        self,
        filepath: str,
        fields: str = "frame.number,ip.src,ip.dst",
        display_filter: str = "",
    ):
        try:
            path = validate_file_path(filepath)
            field_list = [f.strip() for f in fields.split(",") if f.strip()]
            cmd = [
                self.tshark.binary,
                "-r",
                path,
                "-T",
                "fields",
                "-E",
                "header=y",
                "-E",
                "separator=,",
            ]
            for f in field_list:
                cmd += ["-e", f]
            if display_filter:
                cmd += ["-Y", display_filter]
            raw = self.tshark._run(cmd)
            aid = self.audit.record(
                "export_packets_csv", {"filepath": path, "fields": field_list}
            )
            return format_result("export_packets_csv", {"csv": raw}, aid)
        except Exception as e:
            aid = self.audit.record("export_packets_csv_error", {"error": str(e)})
            return format_error("export_packets_csv", str(e), aid)
