"""Optional poxiao IPCollector adapter (IntelSource).

poxiao (D:\\HZR_PROJECTS\\poxiao) exposes its IP-enrichment engine as
``src.vernalequinox.ip_info.IPCollector`` (async, prints progress banners).
This adapter is fully optional: when poxiao is not importable,
``load_poxiao_source()`` returns None and nothing else changes.
"""

import asyncio
import contextlib
import importlib
import io
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from packetforge.interfaces.threat_intel import IntelSource

_DEFAULT_POXIAO_ROOT = Path(r"D:\HZR_PROJECTS\poxiao")


def load_poxiao_source(
    poxiao_root: Path | None = None,
    collector_factory: Callable[[], Any] | None = None,
) -> IntelSource | None:
    """Return a PoxiaoIPSource when poxiao is importable, else None.

    ``poxiao_root`` is temporarily added to sys.path for the ``src.*``
    package layout and removed after import (sys.modules caches the
    package for subsequent calls). ``collector_factory`` overrides
    collector construction (tests inject fakes without importing the
    real package).
    """
    if collector_factory is not None:
        return PoxiaoIPSource(collector_factory=collector_factory)
    root = Path(poxiao_root) if poxiao_root else _DEFAULT_POXIAO_ROOT
    added = root.is_dir() and str(root) not in sys.path
    if added:
        sys.path.insert(0, str(root))
    try:
        module = importlib.import_module("src.vernalequinox.ip_info")
        collector_cls = module.IPCollector
    except Exception:
        return None
    finally:
        if added:
            with contextlib.suppress(ValueError):
                sys.path.remove(str(root))
    return PoxiaoIPSource(collector_factory=lambda: collector_cls())


class PoxiaoIPSource:
    """IntelSource adapter over poxiao's IPCollector (ip-api/rDNS/Shodan/FOFA).

    IP enrichment carries no maliciousness signal by itself, so ``malicious``
    is always None and the merged verdict stays clean/degraded — the detail
    payload (country/ISP/ASN) is for the analyst, not the verdict engine.
    """

    name = "poxiao_ipinfo"

    def __init__(self, collector_factory: Callable[[], Any]) -> None:
        self._collector_factory = collector_factory

    def check(self, ip: str) -> dict[str, Any]:
        collector = self._collector_factory()
        try:
            # engines print progress banners; keep stdout clean
            with contextlib.redirect_stdout(io.StringIO()):
                info = asyncio.run(collector.collect(ip))
            detail = info.to_dict() if hasattr(info, "to_dict") else dict(info)
            return {"status": "ok", "malicious": None, "detail": detail}
        except Exception as e:
            return {
                "status": "degraded",
                "malicious": None,
                "checked": False,
                "error": str(e),
            }
