# server/server_logging.py
# -*- coding: utf-8 -*-
"""
Small helper that gives each MixServer a dedicated logger.
It guarantees that the format placeholder %(server)s always exists
to avoid 'Formatting field not found in record: server'.
"""

import logging
import os
import sys
from typing import Optional

_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR":    logging.ERROR,
    "WARNING":  logging.WARNING,
    "INFO":     logging.INFO,
    "DEBUG":    logging.DEBUG,
}

def _env_level() -> int:
    lvl = os.environ.get("NOPE_LOG_LEVEL", "INFO").upper()
    return _LEVELS.get(lvl, logging.INFO)

_FMT = "%(asctime)s [%(levelname)s] [Server %(server)s] %(message)s"

class _InjectServerFilter(logging.Filter):
    """If a record has no 'server' attribute, inject the current server_id."""
    def __init__(self, server_id: str):
        super().__init__()
        self.server_id = server_id

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "server"):
            record.server = self.server_id
        return True

def get_server_logger(server_id: str, *, name: Optional[str] = None) -> logging.LoggerAdapter:
    """
    Return a logger adapter bound to this server_id.
    Safe to call multiple times; won't duplicate handlers.
    """
    base_name = name or f"mixnet.server.{server_id}"
    base = logging.getLogger(base_name)
    base.setLevel(_env_level())
    base.propagate = False

    if not base.handlers:
        # IMPORTANT: send logs to stdout to avoid PowerShell NativeCommandError on stderr
        h = logging.StreamHandler(stream=sys.stdout)
        h.setLevel(_env_level())
        h.setFormatter(logging.Formatter(_FMT, datefmt="%Y-%m-%d %H:%M:%S"))
        h.addFilter(_InjectServerFilter(server_id))
        base.addHandler(h)

    # Return an adapter so calls like .info(...) always have extra={'server': ...}
    return logging.LoggerAdapter(base, extra={"server": server_id})
