"""Tests for audit hash-chain logging."""

from packetforge.core.audit import AuditLog


def test_audit_log_creates_hash_chain():
    log = AuditLog()
    id1 = log.record("scan", {"target": "1.2.3.4"})
    id2 = log.record("capture", {"count": 10})
    assert id1 != id2
    chain = log.export()
    assert len(chain) == 2
    # each entry must reference previous hash (except first)
    assert chain[1]["prev_hash"] == chain[0]["hash"]
    assert chain[0]["prev_hash"] == "0" * 64


def test_audit_log_tamper_detection():
    log = AuditLog()
    log.record("scan", {"target": "1.2.3.4"})
    log.record("capture", {"count": 10})
    chain = log.export()
    # tamper with first entry
    chain[0]["tool"] = "tampered"
    assert log.verify(chain) is False


def test_audit_log_verify_clean():
    log = AuditLog()
    log.record("scan", {"target": "1.2.3.4"})
    log.record("capture", {"count": 10})
    assert log.verify(log.export()) is True
