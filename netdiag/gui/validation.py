# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Target validation. Pure Python — no Qt — so it can be tested without PySide6."""

from __future__ import annotations

import ipaddress
import re

_HOST_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^{_HOST_LABEL}(\.{_HOST_LABEL})*$")
_MAX_LENGTH = 253


def validate_target(raw: str) -> tuple[bool, str]:
    """
    Validate a user-supplied target.

    Returns (is_valid, normalized_target_or_error_message).
    Accepts IPv4 addresses and RFC-1123 hostnames. IPv6 is explicitly
    rejected because diagnostics do not support it.
    """
    target = raw.strip()
    if not target:
        return False, "Enter a target hostname or IP address."
    if len(target) > _MAX_LENGTH:
        return False, "Target is too long (max 253 characters)."
    if any(ch.isspace() for ch in target):
        return False, "Target must not contain whitespace."
    lowered = target.lower()
    if lowered.startswith(("http://", "https://")):
        return False, "Enter a hostname or IP address without the URL scheme."
    if any(ch in target for ch in "/\\?#%@"):
        return False, "Enter a bare hostname or IP address (no path or query)."

    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        if ip.version != 4:
            return False, "IPv6 targets are not supported. Use an IPv4 address or hostname."
        return True, target

    if not _HOSTNAME_RE.match(target):
        return False, "Invalid hostname format."
    return True, target
