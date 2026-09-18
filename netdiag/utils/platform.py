# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Platform detection and OS-specific helpers."""

import platform
import sys

SUPPORTED_OS = {"Windows", "Linux"}


def get_os_name() -> str:
    return platform.system()


def is_windows() -> bool:
    return platform.system() == "Windows"


def is_linux() -> bool:
    return platform.system() == "Linux"


def is_macos() -> bool:
    return platform.system() == "Darwin"


def check_support(feature: str) -> None:
    os_name = get_os_name()
    if os_name not in SUPPORTED_OS:
        raise RuntimeError(
            f"Feature '{feature}' is not supported on {os_name}. "
            f"Supported platforms: {', '.join(SUPPORTED_OS)}"
        )


def python_version() -> str:
    return sys.version
