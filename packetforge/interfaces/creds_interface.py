"""Cleartext credential extraction from packet payloads."""

import base64
import re
from typing import Any

_HTTP_BASIC = re.compile(r"[Aa]uthorization:\s*[Bb]asic\s+([A-Za-z0-9+/=]+)")
_FTP_USER = re.compile(r"\nUSER\s+(\S+)", re.IGNORECASE)
_FTP_PASS = re.compile(r"\nPASS\s+(\S+)", re.IGNORECASE)


def extract_credentials_from_text(text: str) -> list[dict[str, Any]]:
    """Extract cleartext credentials (HTTP Basic, FTP, Telnet) from text."""
    found: list[dict[str, Any]] = []

    # HTTP Basic Auth: base64 "user:pass"
    for m in _HTTP_BASIC.finditer(text):
        token = m.group(1)
        try:
            decoded = base64.b64decode(token).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if ":" in decoded:
            user, _, password = decoded.partition(":")
            found.append({"type": "http_basic", "user": user, "password": password})

    # FTP: USER/PASS pair
    users = _FTP_USER.findall(text)
    passes = _FTP_PASS.findall(text)
    for u, p in zip(users, passes):
        found.append({"type": "ftp", "user": u, "password": p})

    return found
