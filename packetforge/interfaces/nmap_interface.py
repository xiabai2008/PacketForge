"""Nmap wrapper for active scanning."""

import locale
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any


class NmapError(RuntimeError):
    """Raised when an nmap operation fails."""


def parse_nmap_xml(xml_text: str) -> dict[str, Any] | None:
    """Parse Nmap XML output (-oX -) into a structured dict.

    Returns None when the text is not Nmap XML, so callers can fall back to
    the raw output instead of failing.
    """
    if not xml_text or "<nmaprun" not in xml_text:
        return None
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    if root.tag != "nmaprun":
        return None

    hosts: list[dict[str, Any]] = []
    for h in root.iter("host"):
        status_el = h.find("status")
        addr = h.find("address[@addrtype='ipv4']")
        hostname_el = h.find("hostnames/hostname")
        ports: list[dict[str, Any]] = []
        for p in h.iter("port"):
            state_el = p.find("state")
            svc_el = p.find("service")
            ports.append(
                {
                    "port": int(p.get("portid", "0")),
                    "protocol": p.get("protocol", "tcp"),
                    "state": state_el.get("state") if state_el is not None else None,
                    "service": svc_el.get("name") if svc_el is not None else None,
                    "product": svc_el.get("product") if svc_el is not None else None,
                    "version": svc_el.get("version") if svc_el is not None else None,
                }
            )
        hosts.append(
            {
                "ip": addr.get("addr") if addr is not None else None,
                "hostname": hostname_el.get("name")
                if hostname_el is not None
                else None,
                "status": status_el.get("state") if status_el is not None else None,
                "ports": ports,
            }
        )

    runstats_el = root.find("runstats/hosts")
    runstats = (
        {k: int(runstats_el.get(k, "0")) for k in ("up", "down", "total")}
        if runstats_el is not None
        else {}
    )
    return {"hosts": hosts, "runstats": runstats}


def _decode_output(raw: bytes) -> str:
    """Decode subprocess output. Prefer UTF-8, fall back to system locale."""
    for enc in ("utf-8", locale.getpreferredencoding(False)):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


class NmapInterface:
    """Thin wrapper around nmap. All subprocess calls use shell=False."""

    def __init__(self, binary: str = "nmap") -> None:
        self._binary_name = binary
        self.binary = shutil.which(binary) or binary

    def is_available(self) -> bool:
        return shutil.which(self._binary_name) is not None

    def _run(self, args: list[str]) -> str:
        try:
            proc = subprocess.run(args, capture_output=True, timeout=300, shell=False)
        except FileNotFoundError:
            raise NmapError("nmap not found. Install nmap and ensure it is in PATH.")
        except subprocess.TimeoutExpired:
            raise NmapError("nmap scan timed out.")
        if proc.returncode != 0:
            raise NmapError(_decode_output(proc.stderr).strip() or "nmap failed")
        return _decode_output(proc.stdout)

    def _build_scan_cmd(
        self, target: str, ports: str, scan_type: str, extra: list[str] | None = None
    ) -> list[str]:
        scan_flag = {"connect": "-sT", "syn": "-sS", "udp": "-sU"}.get(scan_type, "-sT")
        cmd = [self.binary, scan_flag, "-p", ports, target]
        if scan_flag == "-sS" or scan_flag == "-sU":
            cmd.append("-O")  # OS detection bundled for these
        if extra:
            cmd += extra
        return cmd

    def port_scan(self, target: str, ports: str, scan_type: str) -> str:
        return self._run(
            self._build_scan_cmd(target, ports, scan_type, extra=["-oX", "-"])
        )

    def service_detection(self, target: str, ports: str) -> str:
        return self._run([self.binary, "-sV", "-oX", "-", "-p", ports, target])

    def os_detection(self, target: str) -> str:
        return self._run([self.binary, "-O", "-oX", "-", target])

    def vulnerability_scan(self, target: str, ports: str) -> str:
        return self._run([self.binary, "--script", "vuln", "-p", ports, target])

    def quick_scan(self, target: str) -> str:
        return self._run([self.binary, "-F", target])

    def comprehensive_scan(self, target: str) -> str:
        return self._run(
            [self.binary, "-sS", "-sV", "-O", "--script", "default,vuln", target]
        )
