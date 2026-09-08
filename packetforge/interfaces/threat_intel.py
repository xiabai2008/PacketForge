"""Threat-intelligence lookups (URLhaus / AbuseIPDB). Reuses poxiao intel base."""

import ipaddress
import json
import ssl
import urllib.parse
import urllib.request
from typing import Any

_URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# AbuseIPDB confidence score at or above this is treated as malicious
_ABUSEIPDB_MALICIOUS_THRESHOLD = 50


def _compute_verdict(result: dict[str, Any]) -> str:
    """Merge per-source verdicts into one of: malicious / clean / degraded."""
    verdicts: list[str] = []
    urlhaus = result.get("urlhaus")
    if urlhaus is not None:
        verdicts.append("malicious" if urlhaus == "ok" else "clean")
    abuse = result.get("abuseipdb")
    if abuse and abuse.get("checked"):
        score = abuse.get("abuse_confidence_score")
        if score is None:
            verdicts.append("clean")
        else:
            verdicts.append(
                "malicious" if score >= _ABUSEIPDB_MALICIOUS_THRESHOLD else "clean"
            )
    if not verdicts:
        return "degraded"
    return "malicious" if "malicious" in verdicts else "clean"


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
        result = self._query(ip)
        abuse = self._query_abuseipdb(ip)
        if abuse is not None:
            result["abuseipdb"] = abuse
        result["sources"] = self.sources
        result["verdict"] = _compute_verdict(result)
        return result

    @property
    def sources(self) -> list[str]:
        """Names of the currently enabled intelligence sources."""
        names = ["urlhaus"]
        if self.abuseipdb_key:
            names.append("abuseipdb")
        return names

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

    def _query_abuseipdb(self, ip: str) -> dict[str, Any] | None:
        """Query AbuseIPDB. Returns None when no key is configured."""
        if not self.abuseipdb_key:
            return None
        url = (
            _ABUSEIPDB_URL
            + "?"
            + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        )
        req = urllib.request.Request(
            url,
            headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10, context=_SSL_CONTEXT) as resp:
                data = json.loads(resp.read().decode())
            d = data.get("data", {})
            return {
                "checked": True,
                "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "total_reports": d.get("totalReports"),
            }
        except Exception as e:
            # Degraded but do not break the main flow
            return {"checked": False, "error": str(e)}
