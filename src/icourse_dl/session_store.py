# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure, versioned necessary-session encoding; no credential backend access.

The Windows size is the complete JSON encoded as UTF-16LE, not a character
count. Measuring a record does not establish that restoring it authenticates,
nor that a system credential backend can store it. Callers must test both.
"""
from __future__ import annotations

import json
import time
from http.cookiejar import Cookie, CookieJar, DefaultCookiePolicy
from typing import TYPE_CHECKING

from .errors import StorageFailure

if TYPE_CHECKING:
    import requests

WINDOWS_LIMIT_BYTES = 2560
MAX_RECORD_BYTES = 64 * 1024
MAX_COOKIES = 64
_WEBVPN_HOST = "webvpn.fudan.edu.cn"
_REST_FIELDS = frozenset({"httponly", "samesite", "priority", "sameparty", "partitioned"})
# This order is the persistent v1 contract. Do not reorder or omit defaults.
COOKIE_FIELDS = (
    "version", "name", "value", "domain", "path", "expires", "secure",
    "discard", "domain_specified", "domain_initial_dot", "path_specified",
    "port", "port_specified", "rest",
)


def _fail() -> StorageFailure:
    return StorageFailure("Invalid or oversized session record.")


def _text(value: object, maximum: int, *, empty: bool = False) -> bool:
    return (isinstance(value, str) and (empty or bool(value))
            and len(value) <= maximum
            and not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF
                        for c in value))


def _scope(domain: str, specified: bool) -> bool:
    if domain != domain.lower():
        return False
    if not specified:
        return domain == _WEBVPN_HOST
    return domain in {_WEBVPN_HOST, "." + _WEBVPN_HOST, "fudan.edu.cn", ".fudan.edu.cn"}


def _jar() -> CookieJar:
    # In particular, a host-only cookie must never reach a subdomain.
    return CookieJar(DefaultCookiePolicy(
        strict_ns_domain=DefaultCookiePolicy.DomainStrictNonDomain,
    ))


def _row(cookie: Cookie) -> list:
    return [getattr(cookie, name) if name != "rest" else dict(cookie._rest)
            for name in COOKIE_FIELDS]


def _cookie(row: object) -> Cookie:
    if not isinstance(row, list) or len(row) != len(COOKIE_FIELDS):
        raise _fail()
    (version, name, value, domain, path, expires, secure, discard,
     domain_specified, domain_initial_dot, path_specified, port,
     port_specified, rest) = row
    if type(version) is not int or version not in (0, 1):
        raise _fail()
    if not _text(name, 1024) or any(c in name for c in "=;, \t"):
        raise _fail()
    if not _text(value, 32768, empty=True):
        raise _fail()
    if not _text(domain, 253) or not _text(path, 4096) or not path.startswith("/"):
        raise _fail()
    if any(type(flag) is not bool for flag in (
        secure, discard, domain_specified, domain_initial_dot,
        path_specified, port_specified,
    )):
        raise _fail()
    if not _scope(domain, domain_specified):
        raise _fail()
    if domain_initial_dot != domain.startswith("."):
        raise _fail()
    if expires is not None and (type(expires) is not int or not 0 <= expires <= 2**63 - 1):
        raise _fail()
    if port is not None:
        if not _text(port, 128) or any(
            not item.isascii() or not item.isdecimal() or not 1 <= int(item) <= 65535
            for item in port.split(",")
        ):
            raise _fail()
    elif port_specified:
        raise _fail()
    if not isinstance(rest, dict) or len(rest) > len(_REST_FIELDS):
        raise _fail()
    seen = set()
    for key, item in rest.items():
        if not isinstance(key, str) or key.lower() not in _REST_FIELDS or key.lower() in seen:
            raise _fail()
        seen.add(key.lower())
        if item is not None and not _text(item, 256, empty=True):
            raise _fail()
    return Cookie(version, name, value, port, port_specified, domain,
                  domain_specified, domain_initial_dot, path, path_specified,
                  secure, expires, discard, None, None, dict(rest))


def select_session_cookies(session: requests.Session) -> CookieJar:
    """Copy unexpired WebVPN-scoped candidates, without broadening scope.

    Parent-domain cookies for fudan.edu.cn qualify; public-suffix cookies and
    direct IDP cookies do not. Remote identity validation remains mandatory.
    """
    result = _jar()
    now = time.time()
    for cookie in session.cookies:
        if cookie.is_expired(now) or not _scope(cookie.domain, cookie.domain_specified):
            continue
        result.set_cookie(_cookie(_row(cookie)))
        if len(result) > MAX_COOKIES:
            raise _fail()
    return result


def _encode(record: dict) -> str:
    try:
        text = json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        if len(text.encode("utf-8")) > MAX_RECORD_BYTES:
            raise _fail()
        # Reject unpaired surrogates for both measurement encodings.
        text.encode("utf-16le")
        return text
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _fail() from None


def serialize_session(account: str, cookies: CookieJar) -> str:
    """Encode the complete v1 record, retaining all fourteen cookie fields.

    The 64 KiB codec bound is separate from backend capacity. Records larger
    than Windows' 2560-byte limit can still be measured without truncation.
    """
    if not _text(account, 1024) or account != account.strip():
        raise _fail()
    rows = []
    now = time.time()
    for cookie in cookies:
        checked = _cookie(_row(cookie))
        if checked.is_expired(now):
            continue
        rows.append(_row(checked))
        if len(rows) > MAX_COOKIES:
            raise _fail()
    return _encode({"v": 1, "account": account, "cookies": rows})


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _fail()
        result[key] = value
    return result


def deserialize_session(record: str) -> tuple[str, CookieJar]:
    """Strictly decode a bounded v1 record, rejecting corrupted scope/types."""
    if not isinstance(record, str):
        raise _fail()
    try:
        if len(record) > MAX_RECORD_BYTES or len(record.encode("utf-8")) > MAX_RECORD_BYTES:
            raise _fail()
        record.encode("utf-16le")
        data = json.loads(record, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise _fail() from None
    if not isinstance(data, dict) or set(data) != {"v", "account", "cookies"}:
        raise _fail()
    if type(data["v"]) is not int or data["v"] != 1:
        raise _fail()
    account = data["account"]
    if not _text(account, 1024) or account != account.strip():
        raise _fail()
    rows = data["cookies"]
    if not isinstance(rows, list) or len(rows) > MAX_COOKIES:
        raise _fail()
    result = _jar()
    seen = set()
    now = time.time()
    for row in rows:
        cookie = _cookie(row)
        key = (cookie.domain, cookie.path, cookie.name)
        if key in seen:
            raise _fail()
        seen.add(key)
        if not cookie.is_expired(now):
            result.set_cookie(cookie)
    return account, result


def measure_session(account: str, cookies: CookieJar) -> dict[str, int]:
    """Return only non-secret byte counts; never touch disk or a backend."""
    record = serialize_session(account, cookies)
    return {
        "session_utf8_bytes": len(record.encode("utf-8")),
        "session_utf16le_bytes": len(record.encode("utf-16le")),
        "windows_limit_bytes": WINDOWS_LIMIT_BYTES,
    }
