"""Cleartext credential extraction from packet payloads."""

import base64
import re
from typing import Any

_HTTP_BASIC = re.compile(r"[Aa]uthorization:\s*[Bb]asic\s+([A-Za-z0-9+/=]+)")
_FTP_USER = re.compile(r"(?:^|\n)\s*USER\s+(\S+)", re.IGNORECASE)
_FTP_PASS = re.compile(r"(?:^|\n)\s*PASS\s+(\S+)", re.IGNORECASE)
_TELNET_USER = re.compile(r"(?:^|\n)\s*(?:login|username):\s*(\S+)", re.IGNORECASE)
_TELNET_PASS = re.compile(r"(?:^|\n)\s*password:\s*(\S+)", re.IGNORECASE)
# Server-side auth challenges: they expose auth schemes, not credentials
_HTTP_DIGEST = re.compile(
    r"WWW-Authenticate:\s*Digest\s+realm=\"([^\"]*)\""
    r"(?:.*?nonce=\"([^\"]*)\")?",
    re.IGNORECASE,
)
_HTTP_NTLM = re.compile(
    r"WWW-Authenticate:\s*(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]+)", re.IGNORECASE
)
_HTTP_BASIC_CHALLENGE = re.compile(r"WWW-Authenticate:\s*Basic", re.IGNORECASE)


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

    # Telnet: login/username + password prompt pair
    users = _TELNET_USER.findall(text)
    passes = _TELNET_PASS.findall(text)
    for u, p in zip(users, passes):
        found.append({"type": "telnet", "user": u, "password": p})

    # HTTP auth scheme exposure (server challenges): no credentials, but
    # valuable for the pentest workflow (realm/nonce, NTLM challenge blob)
    for m in _HTTP_DIGEST.finditer(text):
        found.append(
            {
                "type": "http_digest",
                "user": "",
                "password": "",
                "realm": m.group(1),
                "nonce": m.group(2) or "",
            }
        )
    for m in _HTTP_NTLM.finditer(text):
        found.append(
            {
                "type": "http_ntlm",
                "user": "",
                "password": "",
                "challenge_present": bool(m.group(1)),
            }
        )
    for _ in _HTTP_BASIC_CHALLENGE.finditer(text):
        # Basic challenges are common noise; skip to keep the signal clean
        pass

    return found
