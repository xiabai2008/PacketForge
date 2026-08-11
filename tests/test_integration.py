"""End-to-end integration test. Skipped when tshark/nmap are unavailable."""

import shutil

import pytest

from packetforge.core.audit import AuditLog
from packetforge.core.security import RateLimiter
from packetforge.tools.capture import CaptureTools
from packetforge.tools.creds import CredsTools
from packetforge.tools.nmap_scan import NmapScanTools
from packetforge.tools.threat import ThreatTools

pytestmark = pytest.mark.skipif(
    shutil.which("tshark") is None and shutil.which("nmap") is None,
    reason="requires tshark and/or nmap installed",
)


def test_full_audit_chain_clean():
    """All tools share one audit log; exported chain verifies."""
    audit = AuditLog()
    limiter = RateLimiter(max_calls=10, window_seconds=3600)
    capture = CaptureTools(audit, limiter)
    creds = CredsTools(audit)
    nmap = NmapScanTools(audit, limiter)
    threat = ThreatTools(audit)

    # Exercise error paths (no real network calls) to populate the chain
    capture.capture_live(interface="", count=1)
    creds.extract_credentials("/nonexistent/nope.pcap")
    nmap.nmap_port_scan("192.0.2.1", "80")
    threat.check_ip_threat_intel("999.999.1.1")

    chain = audit.export()
    assert len(chain) >= 4
    assert audit.verify(chain) is True
