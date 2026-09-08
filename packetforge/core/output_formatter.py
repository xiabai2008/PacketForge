"""LLM-friendly result formatting with output size limiting."""

import json
from typing import Any

# Fields never exposed to the LLM (audit/sanity)
_SENSITIVE_KEYS = {"secret", "password", "token", "api_key", "credential"}

# Maximum serialized payload size handed to the LLM (protects context window)
MAX_OUTPUT_CHARS = 20_000


def _serialize(data: dict[str, Any]) -> str:
    try:
        return json.dumps(data, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(data)


def format_result(
    tool: str, data: dict[str, Any], audit_id: str, max_chars: int = MAX_OUTPUT_CHARS
) -> dict[str, Any]:
    """Wrap a successful tool result into an LLM-friendly envelope.

    Payloads serialized beyond ``max_chars`` are replaced with a truncated
    preview plus metadata, so large captures never blow up the model context.
    """
    clean = {k: v for k, v in data.items() if k.lower() not in _SENSITIVE_KEYS}
    serialized = _serialize(clean)
    if len(serialized) <= max_chars:
        return {"tool": tool, "status": "ok", "data": clean, "audit_id": audit_id}

    return {
        "tool": tool,
        "status": "ok",
        "data": {
            "truncated": True,
            "original_size": len(serialized),
            "max_chars": max_chars,
            "preview": serialized[:max_chars],
            "hint": "output exceeded max_chars; narrow the query or export to a file",
        },
        "audit_id": audit_id,
    }


def format_error(tool: str, error: str, audit_id: str) -> dict[str, Any]:
    """Wrap an error into an LLM-friendly envelope."""
    return {"tool": tool, "status": "error", "error": error, "audit_id": audit_id}
