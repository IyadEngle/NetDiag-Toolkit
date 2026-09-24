# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Default per-step time budgets (seconds).

A budget is a backstop, not the normal timeout. Each diagnostic keeps its own
internal timeouts; the budget is set above that function's worst case so the
internal timeout fires first and produces its usual result. Only a step that
overruns its worst case is stopped by the runner (ERROR / StepTimeout).

Worst cases derive from the functions' current default timeouts.
"""

from __future__ import annotations

import math

# step id -> (worst case with default arguments, budget)
_TABLE: dict[str, tuple[float, float]] = {
    # diagnostics
    "dns": (5.0, 15.0),               # getaddrinfo: OS resolver timeout (no explicit timeout)
    "dns_compare": (20.0, 30.0),      # system lookup + 3 servers x 5 s subprocess timeout
    "ping": (19.0, 25.0),             # timeout_seconds 10 + count 4 + 5
    "https": (10.0, 20.0),            # urllib timeout 10 s
    "tcp": (5.0, 10.0),               # connect timeout (3 s CLI, 5 s default)
    "gateway": (11.0, 20.0),          # route/ip 5 s + gateway ping (3 s, 3 probes) + 5 s margin
    "mtu": (55.0, 75.0),              # ~11 binary-search probes x (3 + 2) s
    "traceroute": (60.0, 75.0),       # subprocess timeout 60 s
    "wifi": (10.0, 15.0),             # netsh 10 s
    "adapters": (10.0, 15.0),         # ipconfig / ip 10 s
    # security
    "tls.expiry": (10.0, 20.0),       # one handshake, timeout 10 s
    "tls.versions": (70.0, 90.0),     # probe (up to 2 x 10 s) + 5 versions x 10 s
    "tls.hostname": (20.0, 30.0),     # verified handshake + optional certificate fetch
    "http_headers": (10.0, 20.0),     # urllib timeout 10 s
    "dnssec": (30.0, 40.0),           # DNSKEY query + zone apex lookup + apex DNSKEY query
    "open_resolver": (10.0, 20.0),    # name lookup + resolver timeout 5 s
    "tcp_exposure": (9.0, 20.0),      # 21 ports / 10 workers x 3 s
}

WORST_CASE_S: dict[str, float] = {step_id: worst for step_id, (worst, _) in _TABLE.items()}
DEFAULT_BUDGETS_S: dict[str, float] = {step_id: budget for step_id, (_, budget) in _TABLE.items()}

# Margin applied to budgets computed from input size.
_MARGIN_S = 10.0


def port_scan_budget(port_count: int, timeout_s: float, concurrency: int) -> float:
    """Budget for a TCP port scan: waves of `concurrency` connects, each up to `timeout_s`."""
    waves = max(1, math.ceil(port_count / max(1, concurrency)))
    return waves * timeout_s + _MARGIN_S


def host_discovery_budget(host_count: int, timeout_s: float, concurrency: int) -> float:
    """Budget for an ICMP sweep: waves of pings, each up to `timeout_s + 2` (subprocess timeout)."""
    waves = max(1, math.ceil(host_count / max(1, concurrency)))
    return waves * (timeout_s + 2) + _MARGIN_S


def scaled_budget(step_id: str, worst_case_s: float) -> float:
    """Budget for `step_id` given the worst case of the arguments actually passed.

    Keeps the default headroom above the worst case: with default arguments this
    is exactly DEFAULT_BUDGETS_S[step_id]; larger timeouts (e.g. the GUI's probe
    timeout preference of up to 60 s) raise the budget by the same amount.
    """
    headroom = DEFAULT_BUDGETS_S[step_id] - WORST_CASE_S[step_id]
    return max(DEFAULT_BUDGETS_S[step_id], worst_case_s + headroom)


def ping_worst_case(count: int, timeout_s: float) -> float:
    """connectivity.ping: its subprocess timeout."""
    return timeout_s + count + 5


def mtu_worst_case(min_size: int, max_size: int, timeout_s: float = 3) -> float:
    """mtu.estimate_path_mtu: binary-search probes, each with a (timeout + 2) s subprocess timeout."""
    probes = max(1, math.ceil(math.log2(max(1, max_size - min_size + 2))))
    return probes * (timeout_s + 2)
