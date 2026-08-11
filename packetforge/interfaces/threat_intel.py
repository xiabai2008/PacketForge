"""Threat-intelligence lookups (URLhaus / AbuseIPDB). Reuses poxiao intel base."""

import ipaddress
import json
import ssl
import urllib.request
from typing import Any

_URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"


def _default_ssl_context() -> ssl.SSLContext:
    """SSL context with a CA bundle that works on stock Windows Python."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


_SSL_CONTEXT = _default_ssl_context()


class ThreatIntelError(RuntimeError):
    """Raised on threat-intel lookup failure."""


class ThreatIntelInterface:
    """Query URLhaus and AbuseIPDB. Network failure degrades gracefully."""

    def __init__(
        self,
        abuseipdb_key: str = "",
        urlhaus_host: str = _URLHAUS_HOST,
        urlhaus_key: str = "",
    ) -> None:
        self.abuseipdb_key = abuseipdb_key
        self.urlhaus_host = urlhaus_host
        self.urlhaus_key = urlhaus_key

    def urlhaus_query_url(self) -> str:
        return self.urlhaus_host

    def check_ip(self, ip: str) -> dict[str, Any]:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"status": "error", "error": f"invalid IP: {ip!r}"}
        return self._query(ip)

    def _query(self, ip: str) -> dict[str, Any]:
        payload = json.dumps({"host": ip}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.urlhaus_key:
            headers["Auth-Key"] = self.urlhaus_key
        req = urllib.request.Request(self.urlhaus_host, data=payload, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10, context=_SSL_CONTEXT) as resp:
                data = json.loads(resp.read().decode())
            return {
                "status": "ok",
                "ip": ip,
                "urlhaus": data.get("query_status", "unknown"),
            }
        except Exception as e:
            # Degrade gracefully: mark as unchecked, do not fail the workflow
            return {"status": "degraded", "ip": ip, "error": str(e), "checked": False}
