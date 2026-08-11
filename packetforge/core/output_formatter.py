"""LLM-friendly result formatting."""

from typing import Any

# Fields never exposed to the LLM (audit/sanity)
_SENSITIVE_KEYS = {"secret", "password", "token", "api_key", "credential"}


def format_result(tool: str, data: dict[str, Any], audit_id: str) -> dict[str, Any]:
    """Wrap a successful tool result into an LLM-friendly envelope."""
    clean = {k: v for k, v in data.items() if k.lower() not in _SENSITIVE_KEYS}
    return {"tool": tool, "status": "ok", "data": clean, "audit_id": audit_id}


def format_error(tool: str, error: str, audit_id: str) -> dict[str, Any]:
    """Wrap an error into an LLM-friendly envelope."""
    return {"tool": tool, "status": "error", "error": error, "audit_id": audit_id}
