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


def test_format_result_truncates_large_payload():
    big = "x" * 100_000
    out = format_result("capture", {"raw": big}, "a1")
    assert out["status"] == "ok"
    assert out["data"]["truncated"] is True
    assert out["data"]["original_size"] > 20_000
    assert len(out["data"]["preview"]) <= 20_000


def test_format_result_small_payload_untouched():
    out = format_result("scan", {"raw": "short"}, "a1")
    assert out["data"] == {"raw": "short"}
    assert "truncated" not in out["data"]


def test_format_result_custom_limit():
    out = format_result("scan", {"raw": "abcdef"}, "a1", max_chars=10)
    assert out["data"]["truncated"] is True
    assert out["data"]["preview"] == '{"raw": "a'  # prefix of serialized payload


def test_format_result_unserializable_value_falls_back_to_str():
    out = format_result("scan", {"raw": {1, 2}}, "a1")  # set is not JSON-serializable
    assert out["status"] == "ok"
