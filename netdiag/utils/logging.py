# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Logging configuration for NetDiag-Toolkit."""

import logging
import sys


def setup_logging(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("netdiag")
    logger.setLevel(logging.DEBUG if verbose else logging.WARNING)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
