"""Tests for security validation."""

import pytest

from packetforge.core.security import (
    RateLimiter,
    SecurityError,
    validate_bpf_filter,
    validate_display_filter,
    validate_file_path,
    validate_ip_or_cidr,
    validate_port_spec,
)


def test_validate_ip_ok():
    validate_ip_or_cidr("192.168.1.1")
    validate_ip_or_cidr("10.0.0.0/24")


def test_validate_ip_rejects_injection():
    with pytest.raises(SecurityError):
        validate_ip_or_cidr("1.2.3.4; rm -rf /")
    with pytest.raises(SecurityError):
        validate_ip_or_cidr("localhost")


def test_validate_port_spec_ok():
    assert validate_port_spec("80,443,1-100") == [80, 443, 1, 2, 3]


def test_validate_port_spec_rejects_out_of_range():
    with pytest.raises(SecurityError):
        validate_port_spec("70000")
    with pytest.raises(SecurityError):
        validate_port_spec("80; id")


def test_validate_bpf_filter_rejects_metacharacters():
    validate_bpf_filter("tcp port 80")
    with pytest.raises(SecurityError):
        validate_bpf_filter("tcp port 80; rm -rf")
    with pytest.raises(SecurityError):
        validate_bpf_filter("$(whoami)")


def test_validate_display_filter_rejects_metacharacters():
    validate_display_filter("http.request")
    with pytest.raises(SecurityError):
        validate_display_filter("http.request && `id`")


def test_validate_file_path_ok(tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"x")
    assert validate_file_path(str(p)) == str(p.resolve())


def test_validate_file_path_rejects_escape(tmp_path):
    with pytest.raises(SecurityError):
        validate_file_path(str(tmp_path / ".." / "etc" / "passwd"))


def test_rate_limiter_blocks():
    rl = RateLimiter(max_calls=2, window_seconds=60)
    assert rl.allow("nmap")
    assert rl.allow("nmap")
    assert not rl.allow("nmap")
