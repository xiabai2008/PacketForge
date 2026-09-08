"""Thread-safety tests for AuditLog and RateLimiter."""

from concurrent.futures import ThreadPoolExecutor

from packetforge.core.audit import AuditLog
from packetforge.core.security import RateLimiter


def test_audit_log_concurrent_records_keep_chain_intact():
    log = AuditLog()

    def record(i: int) -> str:
        return log.record("tool", {"i": i})

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(record, range(200)))

    chain = log.export()
    assert len(chain) == 200
    assert log.verify(chain) is True


def test_audit_log_concurrent_persist(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path=path)

    def record(i: int) -> str:
        return log.record("tool", {"i": i})

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(record, range(100)))

    reloaded = AuditLog(path=path)
    assert len(reloaded.export()) == 100
    assert reloaded.verify(reloaded.export()) is True


def test_rate_limiter_concurrent_allows_exact_budget():
    rl = RateLimiter(max_calls=10, window_seconds=60)

    def attempt(_: int) -> bool:
        return rl.allow("nmap")

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(100)))

    assert sum(results) == 10
