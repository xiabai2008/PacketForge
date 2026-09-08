"""Hash-chain audit logging for compliance and forensics."""

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

from packetforge.core.security import SecurityError


class AuditLog:
    """Append-only, tamper-evident audit log using SHA-256 hash chaining.

    When ``path`` is given, the chain is persisted as JSONL (one entry per
    line). Loading an existing file replays and verifies the chain; a
    tampered file raises :class:`SecurityError` instead of being silently
    accepted. All mutations are serialized with a lock so concurrent tool
    calls cannot interleave chain entries or corrupt the persisted file.
    """

    def __init__(self, path: str | None = None) -> None:
        self._entries: list[dict[str, Any]] = []
        self._prev_hash = "0" * 64
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        if self._path is not None and self._path.is_file():
            self._load()

    def _load(self) -> None:
        entries: list[dict[str, Any]] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
        if entries and not self.verify(entries):
            raise SecurityError(
                f"Audit log integrity check failed (tampered or corrupt): {self._path}"
            )
        self._entries = entries
        self._prev_hash = entries[-1]["hash"] if entries else "0" * 64

    def _persist(self, entry: dict[str, Any]) -> None:
        if self._path is None:
            return
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")

    def _hash(self, payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def record(self, tool: str, params: dict[str, Any]) -> str:
        """Append an audit entry. Returns its audit_id (the entry hash)."""
        with self._lock:
            entry = {
                "ts": time.time(),
                "tool": tool,
                "params_hash": self._hash(params),
                "prev_hash": self._prev_hash,
            }
            entry["hash"] = self._hash(entry)
            self._entries.append(entry)
            self._prev_hash = entry["hash"]
            self._persist(entry)
            return entry["hash"]

    def export(self) -> list[dict[str, Any]]:
        """Return a copy of the audit chain."""
        return [dict(e) for e in self._entries]

    def verify(self, chain: list[dict[str, Any]]) -> bool:
        """Verify integrity of a hash chain (detects tampering)."""
        prev = "0" * 64
        for e in chain:
            # hash was computed over the entry without the "hash" field itself
            payload = {k: v for k, v in e.items() if k != "hash"}
            expected_hash = self._hash(payload)
            if e["hash"] != expected_hash:
                return False
            if e["prev_hash"] != prev:
                return False
            prev = e["hash"]
        return True

    def report(self, chain: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Generate a compliance report from the audit chain.

        The report includes integrity verification, entry count, tool usage
        statistics, and the chain root hash, satisfying the audit-report
        acceptance criterion of the design doc.
        """
        entries = self.export() if chain is None else [dict(e) for e in chain]
        tool_stats: dict[str, int] = {}
        for e in entries:
            tool = e.get("tool", "unknown")
            tool_stats[tool] = tool_stats.get(tool, 0) + 1
        return {
            "generated_at": time.time(),
            "entry_count": len(entries),
            "chain_valid": self.verify(entries),
            "root_hash": entries[-1]["hash"] if entries else "0" * 64,
            "tool_stats": tool_stats,
            "entries": entries,
        }
