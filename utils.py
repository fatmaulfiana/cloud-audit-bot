"""
utils.py
Fungsi bantu yang dipakai lintas modul: logging, urutan severity,
emoji notifikasi, dan pembungkus request HTTP yang aman (timeout, error).
"""

import logging
import sys
from datetime import datetime, timezone

import requests

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------
def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


# ---------------------------------------------------------------------------
# SEVERITY HELPERS
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

SEVERITY_EMOJI = {
    "LOW": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
}


def severity_at_least(severity: str, minimum: str) -> bool:
    """True jika `severity` >= `minimum` berdasarkan urutan level."""
    return SEVERITY_ORDER.get(severity.upper(), 0) >= SEVERITY_ORDER.get(minimum.upper(), 0)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# HTTP REQUEST WRAPPER
# ---------------------------------------------------------------------------
def safe_get(url: str, timeout: int = 8, **kwargs):
    """
    Wrapper requests.get yang tidak pernah melempar exception ke pemanggil.
    Mengembalikan (response_or_None, error_message_or_None).
    """
    try:
        resp = requests.get(url, timeout=timeout, **kwargs)
        return resp, None
    except requests.exceptions.RequestException as e:
        return None, str(e)
