"""Tests for output_formatter."""

from packetforge.core.output_formatter import format_error, format_result


def test_format_result_ok():
    out = format_result("capture", {"packets": 5}, "capture-ok")
    assert out["tool"] == "capture"
    assert out["status"] == "ok"
    assert out["data"]["packets"] == 5
    assert out["audit_id"] == "capture-ok"


def test_format_result_limits_fields():
    out = format_result(
        "scan", {"host": "1.2.3.4", "ports": [1, 2, 3], "secret": "x"}, "s1"
    )
    assert "secret" not in out["data"]


def test_format_error_has_audit_id():
    out = format_error("scan", "permission denied", "audit-1")
    assert out["status"] == "error"
    assert out["error"] == "permission denied"
    assert out["audit_id"] == "audit-1"
