"""Shared fixtures for PacketForge tests."""

import sys
from pathlib import Path

import pytest

# Ensure package root is importable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture
def sample_pcap(tmp_path):
    """Create a minimal valid pcap file for tests."""
    pcap = tmp_path / "sample.pcap"
    # Minimal pcap global header + dummy packet (relies on tshark not being called)
    pcap.write_bytes(b"\n" * 24)
    return str(pcap)
