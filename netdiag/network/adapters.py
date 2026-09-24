# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""Network adapter and IP information."""

from __future__ import annotations

import platform
import socket
import time
from typing import Any

from netdiag.utils import process
from netdiag.utils.models import DiagnosticResult, Status


def _try_psutil_adapters() -> list[dict] | None:
    try:
        import psutil
        adapters: list[dict[str, Any]] = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            adapter: dict[str, Any] = {"name": name, "ipv4": [], "ipv6": [], "mac": "", "is_up": False, "speed": 0}
            for addr in addr_list:
                if addr.family == socket.AddressFamily.AF_INET:
                    adapter["ipv4"].append(addr.address)
                elif addr.family == socket.AddressFamily.AF_INET6:
                    adapter["ipv6"].append(addr.address)
                elif hasattr(socket, "AF_PACKET") and addr.family == socket.AF_PACKET:
                    adapter["mac"] = addr.address
                elif hasattr(socket, "AF_LINK") and addr.family == socket.AF_LINK:
                    adapter["mac"] = addr.address
            if name in stats:
                adapter["is_up"] = stats[name].isup
                adapter["speed"] = stats[name].speed
            adapters.append(adapter)
        return adapters
    except ImportError:
        return None


def _fallback_adapters() -> list[dict[str, Any]]:
    os_name = platform.system()
    adapters: list[dict[str, Any]] = []
    if os_name == "Windows":
        try:
            result = process.run(
                ["ipconfig", "/all"], capture_output=True, text=True,
                timeout=10, encoding="utf-8", errors="replace",
            )
            current: dict[str, Any] | None = None
            for line in result.stdout.split("\n"):
                line_s = line.strip()
                if line_s and not line.startswith(" ") and ":" in line_s:
                    current = {"name": line_s.rstrip(":"), "ipv4": [], "ipv6": [], "mac": "", "is_up": True, "speed": 0}
                    adapters.append(current)
                elif current:
                    if "IPv4" in line_s and ":" in line_s:
                        ip = line_s.split(":")[-1].strip().split("(")[0].strip()
                        current["ipv4"].append(ip)
                    elif "Physical Address" in line_s and ":" in line_s:
                        current["mac"] = line_s.split(":")[-1].strip()
        except Exception:
            pass
    elif os_name == "Linux":
        try:
            result = process.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split("\n"):
                parts = line.split()
                if len(parts) >= 4:
                    iface = parts[1]
                    found = False
                    for a in adapters:
                        if a["name"] == iface:
                            found = True
                            if "inet " in line and len(parts) > 3:
                                a["ipv4"].append(parts[3].split("/")[0])
                            break
                    if not found:
                        adapter: dict[str, Any] = {"name": iface, "ipv4": [], "ipv6": [], "mac": "", "is_up": "UP" in line, "speed": 0}
                        if "inet " in line and len(parts) > 3:
                            adapter["ipv4"].append(parts[3].split("/")[0])
                        adapters.append(adapter)
        except Exception:
            pass
    return adapters


def adapter_info() -> DiagnosticResult:
    start = time.monotonic()
    adapters = _try_psutil_adapters()
    if adapters is None:
        adapters = _fallback_adapters()
    duration_ms = (time.monotonic() - start) * 1000

    if adapters:
        active = [a for a in adapters if a.get("is_up") and a.get("ipv4")]
        return DiagnosticResult(
            test_name="adapter_info", target="localhost", status=Status.PASS,
            evidence=f"Found {len(adapters)} adapter(s), {len(active)} active with IPv4",
            duration_ms=duration_ms,
            details={"adapters": adapters, "active_count": len(active)},
        )
    return DiagnosticResult(
        test_name="adapter_info", target="localhost", status=Status.FAIL,
        evidence="Could not enumerate network adapters", duration_ms=duration_ms,
    )
