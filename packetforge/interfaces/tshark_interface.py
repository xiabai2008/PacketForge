"""tshark wrapper for capture, analysis, and stream operations."""

import locale
import shutil
import subprocess


class TsharkError(RuntimeError):
    """Raised when a tshark operation fails."""


def _decode_output(raw: bytes) -> str:
    """Decode subprocess output. Prefer UTF-8, fall back to system locale."""
    for enc in ("utf-8", locale.getpreferredencoding(False)):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


class TsharkInterface:
    """Thin wrapper around the tshark binary. All subprocess calls use shell=False."""

    def __init__(self, binary: str = "tshark") -> None:
        self._binary_name = binary
        self.binary = shutil.which(binary) or binary
        if not shutil.which(binary):
            # Not fatal at construction; availability checked explicitly
            pass

    def is_available(self) -> bool:
        return shutil.which(self._binary_name) is not None

    def _run(self, args: list[str]) -> str:
        try:
            proc = subprocess.run(args, capture_output=True, timeout=60, shell=False)
        except FileNotFoundError:
            raise TsharkError(
                "tshark not found. Install Wireshark/tshark and ensure it is in PATH."
            )
        except subprocess.TimeoutExpired:
            raise TsharkError("tshark operation timed out.")
        if proc.returncode != 0:
            raise TsharkError(_decode_output(proc.stderr).strip() or "tshark failed")
        return _decode_output(proc.stdout)

    def _build_capture_cmd(
        self, interface: str, count: int, bpf: str | None, timeout: int, fmt: str
    ) -> list[str]:
        cmd = [self.binary, "-i", interface, "-c", str(count)]
        if bpf:
            cmd += ["-f", bpf]
        if timeout:
            cmd += ["-a", f"duration:{timeout}"]
        if fmt == "json":
            cmd += ["-T", "json"]
        else:
            cmd += ["-T", "text"]
        return cmd

    def _build_analyze_cmd(
        self, filepath: str, display_filter: str | None, max_packets: int
    ) -> list[str]:
        cmd = [self.binary, "-r", filepath, "-T", "json"]
        if display_filter:
            cmd += ["-Y", display_filter]
        if max_packets:
            cmd += ["-c", str(max_packets)]
        return cmd

    def capture_live(
        self, interface: str, count: int, bpf: str | None, timeout: int, fmt: str
    ) -> str:
        return self._run(self._build_capture_cmd(interface, count, bpf, timeout, fmt))

    def analyze_pcap(
        self, filepath: str, display_filter: str | None, max_packets: int
    ) -> str:
        return self._run(self._build_analyze_cmd(filepath, display_filter, max_packets))

    def protocol_stats(self, filepath: str) -> str:
        cmd = [self.binary, "-r", filepath, "-q", "-z", "io,phs"]
        return self._run(cmd)

    def list_streams(self, filepath: str) -> str:
        cmd = [self.binary, "-r", filepath, "-q", "-z", "follow,tcp,list"]
        return self._run(cmd)

    def follow_stream(
        self,
        filepath: str,
        stream_index: int,
        protocol: str = "tcp",
        fmt: str = "ascii",
    ) -> str:
        cmd = [
            self.binary,
            "-r",
            filepath,
            "-q",
            "-z",
            f"follow,{protocol},{stream_index},{fmt}",
        ]
        return self._run(cmd)
