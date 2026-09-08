"""Nmap active scanning tools with rate limiting."""

from packetforge.core.audit import AuditLog
from packetforge.core.output_formatter import format_error, format_result
from packetforge.core.security import (
    RateLimiter,
    validate_ip_or_cidr,
    validate_nse_script_spec,
    validate_port_spec,
)
from packetforge.interfaces.nmap_interface import NmapInterface, parse_nmap_xml


class NmapScanTools:
    """Nmap scanning tools. Rate-limited to prevent abuse."""

    def __init__(
        self, audit: AuditLog, limiter: RateLimiter, nmap: NmapInterface | None = None
    ) -> None:
        self.audit = audit
        self.limiter = limiter
        self.nmap = nmap or NmapInterface()

    def _guard(self) -> bool:
        return self.limiter.allow("nmap")

    @staticmethod
    def _with_structured(raw: str) -> dict:
        """Build result data: structured hosts when output is Nmap XML."""
        data: dict = {"raw": raw}
        structured = parse_nmap_xml(raw)
        if structured is not None:
            data["structured"] = structured
        return data

    def nmap_port_scan(
        self, target: str, ports: str = "1-1000", scan_type: str = "connect"
    ):
        if not self._guard():
            return format_error(
                "nmap_port_scan",
                "rate limit exceeded",
                self.audit.record("nmap_rate_limited", {}),
            )
        try:
            validate_ip_or_cidr(target)
            validate_port_spec(ports)
            raw = self.nmap.port_scan(target, ports, scan_type)
            aid = self.audit.record(
                "nmap_port_scan",
                {"target": target, "ports": ports, "scan_type": scan_type},
            )
            return format_result("nmap_port_scan", self._with_structured(raw), aid)
        except Exception as e:
            aid = self.audit.record("nmap_port_scan_error", {"error": str(e)})
            return format_error("nmap_port_scan", str(e), aid)

    def nmap_service_detection(self, target: str, ports: str = ""):
        if not self._guard():
            return format_error(
                "nmap_service_detection",
                "rate limit exceeded",
                self.audit.record("nmap_rate_limited", {}),
            )
        try:
            validate_ip_or_cidr(target)
            if ports:
                validate_port_spec(ports)
            raw = self.nmap.service_detection(target, ports)
            aid = self.audit.record(
                "nmap_service_detection", {"target": target, "ports": ports}
            )
            return format_result(
                "nmap_service_detection", self._with_structured(raw), aid
            )
        except Exception as e:
            aid = self.audit.record("nmap_service_detection_error", {"error": str(e)})
            return format_error("nmap_service_detection", str(e), aid)

    def nmap_os_detection(self, target: str):
        if not self._guard():
            return format_error(
                "nmap_os_detection",
                "rate limit exceeded",
                self.audit.record("nmap_rate_limited", {}),
            )
        try:
            validate_ip_or_cidr(target)
            raw = self.nmap.os_detection(target)
            aid = self.audit.record("nmap_os_detection", {"target": target})
            return format_result("nmap_os_detection", self._with_structured(raw), aid)
        except Exception as e:
            aid = self.audit.record("nmap_os_detection_error", {"error": str(e)})
            return format_error("nmap_os_detection", str(e), aid)

    def nmap_quick_scan(self, target: str):
        if not self._guard():
            return format_error(
                "nmap_quick_scan",
                "rate limit exceeded",
                self.audit.record("nmap_rate_limited", {}),
            )
        try:
            validate_ip_or_cidr(target)
            raw = self.nmap.quick_scan(target)
            aid = self.audit.record("nmap_quick_scan", {"target": target})
            return format_result("nmap_quick_scan", self._with_structured(raw), aid)
        except Exception as e:
            aid = self.audit.record("nmap_quick_scan_error", {"error": str(e)})
            return format_error("nmap_quick_scan", str(e), aid)

    def nmap_vulnerability_scan(self, target: str, ports: str = ""):
        if not self._guard():
            return format_error(
                "nmap_vulnerability_scan",
                "rate limit exceeded",
                self.audit.record("nmap_rate_limited", {}),
            )
        try:
            validate_ip_or_cidr(target)
            if ports:
                validate_port_spec(ports)
            raw = self.nmap.vulnerability_scan(target, ports)
            aid = self.audit.record(
                "nmap_vulnerability_scan", {"target": target, "ports": ports}
            )
            return format_result(
                "nmap_vulnerability_scan", self._with_structured(raw), aid
            )
        except Exception as e:
            aid = self.audit.record("nmap_vulnerability_scan_error", {"error": str(e)})
            return format_error("nmap_vulnerability_scan", str(e), aid)

    def nmap_nse_scan(self, target: str, ports: str = "", scripts: str = "default"):
        if not self._guard():
            return format_error(
                "nmap_nse_scan",
                "rate limit exceeded",
                self.audit.record("nmap_rate_limited", {}),
            )
        try:
            validate_ip_or_cidr(target)
            if ports:
                validate_port_spec(ports)
            validate_nse_script_spec(scripts)
            raw = self.nmap.nse_scan(target, ports, scripts)
            aid = self.audit.record(
                "nmap_nse_scan", {"target": target, "ports": ports, "scripts": scripts}
            )
            return format_result("nmap_nse_scan", self._with_structured(raw), aid)
        except Exception as e:
            aid = self.audit.record("nmap_nse_scan_error", {"error": str(e)})
            return format_error("nmap_nse_scan", str(e), aid)
