# SPDX-License-Identifier: GPL-3.0-or-later
"""Validated Base32 input and PyOTP-backed school dynamic passwords."""
import base64
import binascii
import hashlib
import math
import time

import pyotp

from .errors import ConfigurationError


_MAX_SECRET_CHARACTERS = 1024
_INVALID_SECRET = "The TOTP secret is invalid."
_INVALID_TIMESTAMP = "The TOTP timestamp is invalid."
_ASCII_WHITESPACE = " \t\n\r\v\f"
_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def normalize_secret(value: str) -> str:
    """Return a validated, uppercase, unpadded Base32 secret."""
    if type(value) is not str or len(value) > _MAX_SECRET_CHARACTERS:
        raise ConfigurationError(_INVALID_SECRET)
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise ConfigurationError(_INVALID_SECRET) from None

    compact = "".join(character for character in value if character not in _ASCII_WHITESPACE)
    compact = compact.upper()
    if not compact:
        raise ConfigurationError(_INVALID_SECRET)

    data = compact.rstrip("=")
    padding = compact[len(data):]
    if not data or "=" in data or any(character not in _BASE32_ALPHABET for character in data):
        raise ConfigurationError(_INVALID_SECRET)
    remainder = len(data) % 8
    if remainder not in (0, 2, 4, 5, 7):
        raise ConfigurationError(_INVALID_SECRET)
    expected_padding = (-len(data)) % 8
    if padding and (len(compact) % 8 != 0 or expected_padding == 0
                    or len(padding) != expected_padding):
        raise ConfigurationError(_INVALID_SECRET)

    padded = data + "=" * expected_padding
    try:
        decoded = base64.b32decode(padded)
    except (binascii.Error, ValueError):
        raise ConfigurationError(_INVALID_SECRET) from None
    canonical = base64.b32encode(decoded).decode("ascii").rstrip("=")
    if not decoded or canonical != data:
        raise ConfigurationError(_INVALID_SECRET)
    return canonical


def generate_code(secret: str, timestamp: float | None = None) -> str:
    """Generate a fresh six-digit SHA1 TOTP using PyOTP's 30-second interval."""
    normalized = normalize_secret(secret)
    if timestamp is None:
        timestamp = time.time()
    if (isinstance(timestamp, bool) or not isinstance(timestamp, (int, float))
            or timestamp < 0 or isinstance(timestamp, float) and not math.isfinite(timestamp)):
        raise ConfigurationError(_INVALID_TIMESTAMP)
    try:
        return pyotp.TOTP(normalized, digits=6, digest=hashlib.sha1, interval=30).at(int(timestamp))
    except (OverflowError, OSError, ValueError):
        raise ConfigurationError(_INVALID_TIMESTAMP) from None
