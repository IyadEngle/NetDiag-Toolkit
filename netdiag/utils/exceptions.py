# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""Structured exceptions for NetDiag-Toolkit."""


class NetDiagError(Exception):
    """Base exception for all NetDiag errors."""

    def __init__(self, message: str, test_name: str = "", target: str = ""):
        self.message = message
        self.test_name = test_name
        self.target = target
        super().__init__(message)


class UnsupportedPlatformError(NetDiagError):
    """Raised when a feature is not supported on the current OS."""


class TimeoutError(NetDiagError):
    """Raised when a network operation times out."""


class ParseError(NetDiagError):
    """Raised when output from a system command cannot be parsed."""


class AuthorizationRequiredError(NetDiagError):
    """Raised when an operation requires admin/root privileges."""
