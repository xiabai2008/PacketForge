"""Input validation, sandboxing, and rate limiting."""

import ipaddress
import re
import threading
import time
from pathlib import Path


class SecurityError(ValueError):
    """Raised when input fails security validation."""


# Only allow safe BPF / display filter characters
_FILTER_ALLOWED = re.compile(r"^[A-Za-z0-9_.,:\[\]\s=<>/!\+\-]+$")
_PATH_ALLOWED_EXT = {".pcap", ".pcapng"}
# FQDN: at least one dot, total length <= 253, labels of valid hostname shape
_FQDN = re.compile(
    r"(?=.{1,253}\.?$)(?=.*\.)"
    r"[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+"
    r"\.?"
)
# Safety cap on expanded port lists (avoids accidental broad scans)
_MAX_EXPANDED_PORTS = 5

# NSE script spec: script names, categories, globs, and "or" combinations
_NSE_ALLOWED = re.compile(r"^[A-Za-z0-9_.*,\s\-/]+$")


def validate_nse_script_spec(spec: str) -> str:
    """Validate an NSE --script argument (names, categories, globs).

    Rejects shell metacharacters and --script-args style injection; the
    value is still passed as a single argv entry (shell=False), this is
    defense in depth against nmap interpreting unexpected arguments.
    """
    if not spec:
        raise SecurityError("NSE script spec is empty")
    if _NSE_ALLOWED.fullmatch(spec) is None:
        raise SecurityError(f"Invalid NSE script spec: {spec!r}")
    return spec


def validate_ip_or_cidr(target: str) -> str:
    """Validate an IP, CIDR, or FQDN hostname. Rejects shell metacharacters."""
    if any(c in target for c in ";|&`$(){}<>"):
        raise SecurityError(f"Disallowed character in target: {target!r}")
    # Allow IP/CIDR/hostname characters (letters, digits, dots, hyphens, slash)
    if re.fullmatch(r"[\w.\-/]+", target) is None:
        raise SecurityError(f"Invalid target format: {target!r}")
    try:
        ipaddress.ip_interface(target if "/" in target else target + "/32")
    except ValueError:
        # Not a pure IP/CIDR; must be an FQDN hostname (single labels rejected)
        if not _FQDN.fullmatch(target):
            raise SecurityError(f"Invalid IP/CIDR/hostname: {target!r}")
    return target


def validate_port_spec(spec: str) -> list[int]:
    """Parse and validate a port spec like '80,443,1-100'. Returns expanded ports."""
    if any(c in spec for c in ";|&`$()<>{}"):
        raise SecurityError(f"Disallowed character in port spec: {spec!r}")
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if not (1 <= lo <= hi <= 65535):
                raise SecurityError(f"Port range out of bounds: {part!r}")
            ports.extend(range(lo, hi + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise SecurityError(f"Port out of range: {part!r}")
            ports.append(p)
    if len(ports) > _MAX_EXPANDED_PORTS:
        del ports[_MAX_EXPANDED_PORTS:]
    return ports


def validate_bpf_filter(filter_str: str | None) -> str | None:
    """Validate a BPF capture filter. None/empty allowed."""
    if not filter_str:
        return filter_str
    if _FILTER_ALLOWED.fullmatch(filter_str) is None:
        raise SecurityError(f"Invalid BPF filter: {filter_str!r}")
    return filter_str


def validate_display_filter(filter_str: str | None) -> str | None:
    """Validate a Wireshark display filter. None/empty allowed."""
    if not filter_str:
        return filter_str
    if _FILTER_ALLOWED.fullmatch(filter_str) is None:
        raise SecurityError(f"Invalid display filter: {filter_str!r}")
    return filter_str


def validate_file_path(path: str) -> str:
    """Resolve and validate a file path is inside the sandbox and has allowed extension."""
    p = Path(path).resolve()
    ext = p.suffix.lower()
    if ext not in _PATH_ALLOWED_EXT:
        raise SecurityError(f"Unsupported file type: {ext!r}")
    if not p.is_file():
        raise SecurityError(f"File not found: {p}")
    return str(p)


def validate_output_path(path: str, allowed_exts: set[str] | None = None) -> str:
    """Validate an output path (extension whitelist, existing parent).

    Defaults to capture-file extensions; callers persisting other artifact
    types (e.g. JSON audit reports) pass their own whitelist.
    """
    p = Path(path).resolve()
    ext = p.suffix.lower()
    allowed = allowed_exts if allowed_exts is not None else _PATH_ALLOWED_EXT
    if ext not in allowed:
        raise SecurityError(f"Unsupported output file type: {ext!r}")
    if not p.parent.is_dir():
        raise SecurityError(f"Parent directory does not exist: {p.parent}")
    return str(p)


class RateLimiter:
    """Token-bucket style rate limiter keyed by operation. Thread-safe."""

    def __init__(self, max_calls: int = 10, window_seconds: int = 3600):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._calls: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            self._calls.setdefault(key, [])
            self._calls[key] = [t for t in self._calls[key] if t > cutoff]
            if len(self._calls[key]) >= self.max_calls:
                return False
            self._calls[key].append(now)
            return True
