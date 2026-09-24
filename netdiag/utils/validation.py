# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Target validation shared by the CLI and GUI. Pure Python (no Qt, no network).

Two layers:
- `parse_target` checks syntax only and classifies a target as an IPv4
  address, an IPv6 address, or a hostname. It knows nothing about what the
  diagnostics support.
- `validate_target` applies the current support policy on top. IPv6 is
  recognised but not yet accepted (planned for 0.6); enabling it is a policy
  change (`IPV6_TARGETS_SUPPORTED` or `allow_ipv6=True`), not a parser change.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

# Flip when every diagnostic and security check handles IPv6 (roadmap 0.6).
IPV6_TARGETS_SUPPORTED = False

TargetKind = Literal["ipv4", "ipv6", "hostname"]

_HOST_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^{_HOST_LABEL}(\.{_HOST_LABEL})*$")
_NUMERIC_LABEL_RE = re.compile(r"^[0-9]+$")
_MAX_LENGTH = 253


class TargetError(ValueError):
    """A target that is syntactically invalid."""


@dataclass(frozen=True)
class Target:
    value: str          # normalized form to pass to diagnostics
    kind: TargetKind


def parse_target(raw: str) -> Target:
    """Parse and classify a target. Raises TargetError with a user-facing message."""
    target = raw.strip()
    if not target:
        raise TargetError("Enter a target hostname or IP address.")
    if target.startswith("-"):
        # Targets are passed as arguments to ping/traceroute/dig; a leading "-"
        # would be interpreted as a command-line option.
        raise TargetError("Target must not begin with '-'.")
    if any(ch.isspace() for ch in target):
        raise TargetError("Target must not contain whitespace.")
    if target.lower().startswith(("http://", "https://")):
        raise TargetError("Enter a hostname or IP address without the URL scheme.")

    # IP literals first: IPv6 legitimately contains ':' and, with a zone ID, '%'.
    literal = target[1:-1] if target.startswith("[") and target.endswith("]") else target
    try:
        ip = ipaddress.ip_address(literal)
    except ValueError:
        pass
    else:
        if ip.version == 4:
            return Target(value=str(ip), kind="ipv4")
        return Target(value=str(ip), kind="ipv6")

    if len(target) > _MAX_LENGTH:
        raise TargetError(f"Target is too long (max {_MAX_LENGTH} characters).")
    if any(ch in target for ch in "/\\?#%@[]"):
        raise TargetError("Enter a bare hostname or IP address (no path or query).")
    if ":" in target:
        raise TargetError("Invalid IP address or hostname (':' is only valid in IPv6 addresses).")
    if not _HOSTNAME_RE.match(target):
        raise TargetError("Invalid hostname format.")

    labels = target.split(".")
    if all(_NUMERIC_LABEL_RE.match(label) for label in labels):
        # Looks like an IPv4 address but is not one (e.g. 1.2.3.999, 01.2.3.4, 1234).
        raise TargetError(f"Invalid IPv4 address: {target}")
    if _NUMERIC_LABEL_RE.match(labels[-1]):
        # RFC 3696 §2: a top-level domain is never all-numeric.
        raise TargetError("Invalid hostname: the last label cannot be all-numeric.")
    return Target(value=target, kind="hostname")


def validate_target(raw: str, *, allow_ipv6: bool | None = None) -> tuple[bool, str]:
    """
    Validate a user-supplied target against the current support policy.

    Returns (is_valid, normalized_target_or_error_message).
    `allow_ipv6` defaults to IPV6_TARGETS_SUPPORTED.
    """
    try:
        parsed = parse_target(raw)
    except TargetError as exc:
        return False, str(exc)

    ipv6_allowed = IPV6_TARGETS_SUPPORTED if allow_ipv6 is None else allow_ipv6
    if parsed.kind == "ipv6" and not ipv6_allowed:
        return False, "IPv6 targets are not supported yet. Use an IPv4 address or hostname."
    return True, parsed.value
