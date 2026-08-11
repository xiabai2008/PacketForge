"""Tests for audit compliance report generation."""

from packetforge.core.audit import AuditLog


def test_audit_report_generates_compliance_report():
    log = AuditLog()
    log.record("scan", {"target": "1.2.3.4"})
    log.record("capture", {"count": 10})
    log.record("scan", {"target": "5.6.7.8"})
    report = log.report()
    assert report["chain_valid"] is True
    assert report["entry_count"] == 3
    assert report["root_hash"] == log.export()[-1]["hash"]
    assert report["tool_stats"] == {"scan": 2, "capture": 1}
    assert len(report["entries"]) == 3
    assert "generated_at" in report


def test_audit_report_detects_tampering():
    log = AuditLog()
    log.record("scan", {"target": "1.2.3.4"})
    log.record("capture", {"count": 10})
    chain = log.export()
    chain[0]["tool"] = "tampered"
    report = log.report(chain)
    assert report["chain_valid"] is False


def test_audit_report_empty_log():
    report = AuditLog().report()
    assert report["entry_count"] == 0
    assert report["chain_valid"] is True
    assert report["tool_stats"] == {}
