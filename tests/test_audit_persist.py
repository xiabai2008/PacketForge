"""Tests for persistent audit log (JSONL file backing + replay verification)."""

import json

import pytest

from packetforge.core.audit import AuditLog
from packetforge.core.security import SecurityError


def test_persistent_log_roundtrip(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log1 = AuditLog(path=path)
    log1.record("scan", {"target": "1.2.3.4"})
    log1.record("capture", {"count": 10})

    log2 = AuditLog(path=path)
    assert len(log2.export()) == 2
    assert log2.verify(log2.export()) is True


def test_persistent_log_continues_chain(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log1 = AuditLog(path=path)
    log1.record("scan", {"target": "1.2.3.4"})

    log2 = AuditLog(path=path)
    id2 = log2.record("capture", {"count": 10})
    chain = log2.export()
    assert len(chain) == 2
    assert chain[1]["prev_hash"] == chain[0]["hash"]
    assert id2 == chain[1]["hash"]


def test_persistent_log_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    log1 = AuditLog(path=str(path))
    log1.record("scan", {"target": "1.2.3.4"})
    log1.record("capture", {"count": 10})

    # tamper with the persisted file
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["tool"] = "tampered"
    lines[0] = json.dumps(entry)
    path.write_text("\n".join(lines), encoding="utf-8")

    with pytest.raises(SecurityError):
        AuditLog(path=str(path))


def test_persistent_log_new_file(tmp_path):
    path = str(tmp_path / "fresh.jsonl")
    log = AuditLog(path=path)
    log.record("scan", {"target": "1.2.3.4"})
    assert (tmp_path / "fresh.jsonl").read_text(encoding="utf-8").count("\n") >= 1


def test_persistent_log_file_written_per_record(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path=str(path))
    log.record("a", {})
    content1 = path.read_text(encoding="utf-8")
    log.record("b", {})
    content2 = path.read_text(encoding="utf-8")
    assert content1.count("\n") == 1
    assert content2.count("\n") == 2


def test_persistent_log_report_from_reloaded(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log1 = AuditLog(path=path)
    log1.record("scan", {"target": "1.2.3.4"})
    log1.record("scan", {"target": "5.6.7.8"})

    log2 = AuditLog(path=path)
    report = log2.report()
    assert report["entry_count"] == 2
    assert report["chain_valid"] is True
    assert report["tool_stats"] == {"scan": 2}


def test_in_memory_log_unchanged():
    log = AuditLog()
    log.record("scan", {"target": "1.2.3.4"})
    assert len(log.export()) == 1
