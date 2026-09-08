"""Credential extraction tool."""

from packetforge.core.audit import AuditLog
from packetforge.core.output_formatter import format_error, format_result
from packetforge.core.security import validate_file_path
from packetforge.interfaces.creds_interface import extract_credentials_from_text
from packetforge.interfaces.tshark_interface import TsharkInterface


class CredsTools:
    """Extract cleartext credentials from a capture file."""

    def __init__(self, audit: AuditLog, tshark: TsharkInterface | None = None) -> None:
        self.audit = audit
        self.tshark = tshark or TsharkInterface()

    def extract_credentials(self, filepath: str):
        try:
            path = validate_file_path(filepath)
            # dump all packet payloads as hex fields, then decode to text
            raw = self.tshark._run(
                [
                    self.tshark.binary,
                    "-r",
                    path,
                    "-T",
                    "fields",
                    "-e",
                    "tcp.payload",
                ]
            )
            text = ""
            for line in raw.splitlines():
                if line.strip():
                    try:
                        text += bytes.fromhex(line).decode("utf-8", errors="ignore")
                    except ValueError:
                        continue
            creds = extract_credentials_from_text(text)
            # Never echo raw passwords directly to LLM; report presence + redacted.
            # Non-credential auth-scheme entries (http_digest/http_ntlm) keep
            # their metadata fields (realm/nonce/challenge) since they contain
            # no secrets.
            redacted = []
            for c in creds:
                entry = {
                    "type": c["type"],
                    "user": c["user"],
                    "password": "***" if c["password"] else "",
                }
                for key in ("realm", "nonce", "challenge_present"):
                    if key in c:
                        entry[key] = c[key]
                redacted.append(entry)
            aid = self.audit.record(
                "extract_credentials", {"filepath": path, "found": len(creds)}
            )
            return format_result(
                "extract_credentials",
                {"credentials": redacted, "count": len(creds)},
                aid,
            )
        except Exception as e:
            aid = self.audit.record("extract_credentials_error", {"error": str(e)})
            return format_error("extract_credentials", str(e), aid)
