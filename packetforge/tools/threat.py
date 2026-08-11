"""Threat-intel linkage tools."""

from packetforge.core.audit import AuditLog
from packetforge.core.output_formatter import format_error, format_result
from packetforge.core.security import validate_file_path
from packetforge.interfaces.threat_intel import ThreatIntelInterface
from packetforge.interfaces.tshark_interface import TsharkInterface


class ThreatTools:
    """Check IPs and captures against threat feeds."""

    def __init__(
        self,
        audit: AuditLog,
        intel: ThreatIntelInterface | None = None,
        tshark: TsharkInterface | None = None,
    ) -> None:
        self.audit = audit
        self.intel = intel or ThreatIntelInterface()
        self.tshark = tshark or TsharkInterface()

    def check_ip_threat_intel(self, ip: str):
        result = self.intel.check_ip(ip)
        aid = self.audit.record(
            "check_ip_threat_intel", {"ip": ip, "status": result.get("status")}
        )
        result["audit_id"] = aid
        return result

    def scan_capture_for_threats(self, filepath: str):
        try:
            path = validate_file_path(filepath)
            raw = self.tshark._run(
                [
                    self.tshark.binary,
                    "-r",
                    path,
                    "-T",
                    "fields",
                    "-e",
                    "ip.src",
                    "-e",
                    "ip.dst",
                    "-E",
                    "separator=,",
                ]
            )
            ips = sorted(
                {
                    part.strip()
                    for line in raw.splitlines()
                    if line.strip()
                    for part in line.split(",")
                    if part.strip()
                }
            )
            findings = []
            for ip in ips:
                res = self.intel.check_ip(ip)
                if res.get("status") == "ok":
                    findings.append({"ip": ip, "status": res.get("urlhaus")})
            aid = self.audit.record(
                "scan_capture_for_threats", {"filepath": path, "ips": len(ips)}
            )
            return format_result(
                "scan_capture_for_threats", {"ips": ips, "findings": findings}, aid
            )
        except Exception as e:
            aid = self.audit.record("scan_capture_for_threats_error", {"error": str(e)})
            return format_error("scan_capture_for_threats", str(e), aid)
