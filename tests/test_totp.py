# SPDX-License-Identifier: GPL-3.0-or-later
"""RFC 6238 tests using synthetic Base32 secrets only."""
import pytest

from icourse_dl.errors import ConfigurationError
from icourse_dl import totp


SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_normalize_secret_canonicalizes_case_whitespace_and_padding():
    assert totp.normalize_secret("my======") == "MY"
    assert totp.normalize_secret(" \tm y\n======\r") == "MY"
    assert totp.normalize_secret(SECRET.lower()) == SECRET


@pytest.mark.parametrize("value", [
    "", " \t\r\n", "M", "MZ", "MZ======", "MY=====", "MY========",
    "JBSWY3DPEHPK3PX!", "otpauth://totp/example?secret=MY", "A" * 1025,
])
def test_invalid_secrets_raise_static_configuration_error(value):
    with pytest.raises(ConfigurationError) as exc:
        totp.normalize_secret(value)
    assert "TOTP secret" in str(exc.value)
    if value:
        assert value not in str(exc.value)


def test_rfc_6238_sha1_vectors_use_six_digit_codes():
    vectors = [
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
        (20000000000, "353130"),
    ]
    assert [totp.generate_code(SECRET, timestamp) for timestamp, _ in vectors] == [
        code for _, code in vectors
    ]


def test_time_step_boundaries_roll_over_at_thirty_seconds():
    assert totp.generate_code(SECRET, 0) == totp.generate_code(SECRET, 29.999999)
    assert totp.generate_code(SECRET, 30) == totp.generate_code(SECRET, 59.999999)
    assert totp.generate_code(SECRET, 60) == totp.generate_code(SECRET, 89.999999)
    assert totp.generate_code(SECRET, 0) != totp.generate_code(SECRET, 30)
    assert totp.generate_code(SECRET, 30) != totp.generate_code(SECRET, 60)


def test_default_timestamp_is_read_fresh_for_each_call(monkeypatch):
    times = iter((59, 1111111109))
    monkeypatch.setattr(totp.time, "time", lambda: next(times))
    assert totp.generate_code(SECRET) == "287082"
    assert totp.generate_code(SECRET) == "081804"


@pytest.mark.parametrize("timestamp", [-1, float("nan"), float("inf"), True, "59"])
def test_invalid_timestamps_raise_configuration_error(timestamp):
    with pytest.raises(ConfigurationError, match="TOTP timestamp"):
        totp.generate_code(SECRET, timestamp)
