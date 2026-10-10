# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic cookie tests; no school requests or credential backend access."""
import builtins
import json
from http.cookiejar import Cookie, CookieJar
from types import SimpleNamespace
from urllib.request import Request

import pytest

from icourse_dl.errors import StorageFailure
from icourse_dl.session_store import (
    COOKIE_FIELDS, MAX_RECORD_BYTES, deserialize_session, measure_session,
    select_session_cookies, serialize_session,
)


def cookie(*, name="session", value="虚构😀", domain="webvpn.fudan.edu.cn",
           path="/", expires=None, secure=True, specified=False, rest=None):
    return Cookie(0, name, value, None, False, domain, specified,
                  domain.startswith("."), path, True, secure, expires,
                  expires is None, None, None,
                  {"HttpOnly": None, "SameSite": "Lax"} if rest is None else rest)


def jar(*cookies):
    result = CookieJar()
    for item in cookies:
        result.set_cookie(item)
    return result


def record():
    return json.loads(serialize_session("fictional", jar(cookie())))


def test_roundtrip_preserves_all_fields_and_duplicate_names():
    source = jar(cookie(), cookie(path="/course"),
                 cookie(domain=".fudan.edu.cn", specified=True))
    encoded = serialize_session("测试😀", source)
    account, restored = deserialize_session(encoded)
    assert account == "测试😀"
    assert len(restored) == 3
    assert len(COOKIE_FIELDS) == 14
    assert all(len(row) == 14 for row in json.loads(encoded)["cookies"])
    assert serialize_session(account, restored) == encoded
    assert "\\u" not in encoded
    assert ": " not in encoded
    for before, after in zip(source, restored):
        assert before.__dict__ == after.__dict__


def test_selector_filters_domains_and_expiration_without_mutation(monkeypatch):
    monkeypatch.setattr("icourse_dl.session_store.time.time", lambda: 100)
    original = jar(cookie(), cookie(name="parent", domain=".fudan.edu.cn", specified=True),
                   cookie(name="expired", expires=99),
                   cookie(name="idp", domain="id.fudan.edu.cn"),
                   cookie(name="evil", domain="webvpn.fudan.edu.cn.evil.test", specified=True),
                   cookie(name="public", domain=".edu.cn", specified=True),
                   cookie(name="hostparent", domain="fudan.edu.cn"))
    selected = select_session_cookies(SimpleNamespace(cookies=original))
    assert {c.name for c in selected} == {"session", "parent"}
    assert len(original) == 7
    next(iter(selected)).value = "changed"
    assert next(iter(original)).value == "虚构😀"


def test_host_only_secure_and_path_enforced():
    _, restored = deserialize_session(serialize_session("fictional", jar(cookie(value="abc", path="/course"))))
    for url in ("https://child.webvpn.fudan.edu.cn/course", "http://webvpn.fudan.edu.cn/course",
                "https://webvpn.fudan.edu.cn/elsewhere", "https://evil.test/course"):
        request = Request(url)
        restored.add_cookie_header(request)
        assert request.get_header("Cookie") is None
    request = Request("https://webvpn.fudan.edu.cn/course/video")
    restored.add_cookie_header(request)
    assert request.get_header("Cookie") == "session=abc"


def test_expired_filtered_by_encoder_and_decoder(monkeypatch):
    monkeypatch.setattr("icourse_dl.session_store.time.time", lambda: 100)
    assert json.loads(serialize_session("fictional", jar(cookie(expires=99))))["cookies"] == []
    data = record()
    data["cookies"][0][5] = 99
    assert len(deserialize_session(json.dumps(data))[1]) == 0


@pytest.mark.parametrize("index,value", [
    (0, True), (0, 2), (1, ""), (1, "a=b"), (2, None), (2, "bad\nvalue"),
    (3, "evil.test"), (3, ".edu.cn"), (3, ".fudan.edu.cn"),
    (4, "relative"), (5, True), (5, -1), (5, 1.5),
    (6, 1), (7, "true"), (8, 1), (9, True), (10, None),
    (11, "0"), (11, "65536"), (11, "443,bad"), (12, True),
    (13, []), (13, {"unknown": "value"}), (13, {"HttpOnly": True}),
    (13, {"HttpOnly": None, "httponly": None}),
])
def test_invalid_cookie_fields_rejected(index, value):
    data = record()
    data["cookies"][0][index] = value
    with pytest.raises(StorageFailure):
        deserialize_session(json.dumps(data))


@pytest.mark.parametrize("malformed", [
    "", "not-json", "[]", "null", "{}", '{"v":1,"v":1,"account":"a","cookies":[]}',
    '{"v":true,"account":"a","cookies":[]}',
    '{"v":1,"account":"","cookies":[]}',
    '{"v":1,"account":" a","cookies":[]}',
    '{"v":1,"account":"a","cookies":{},"extra":1}',
    '{"v":1,"account":"a","cookies":[] ,"extra":1}',
    '{"v":1,"account":"\\ud800","cookies":[]}',
])
def test_malformed_records_fail_closed(malformed):
    with pytest.raises(StorageFailure):
        deserialize_session(malformed)


def test_row_length_duplicate_cookie_and_record_count_rejected():
    for rows in ([record()["cookies"][0][:-1]], [record()["cookies"][0] + [None]],
                 record()["cookies"] * 2, record()["cookies"] * 65):
        with pytest.raises(StorageFailure):
            deserialize_session(json.dumps({"v": 1, "account": "fictional", "cookies": rows}))
    with pytest.raises(StorageFailure):
        serialize_session("fictional", jar(*(cookie(name=f"n{i}") for i in range(65))))


def test_encoding_and_decoding_size_limits():
    with pytest.raises(StorageFailure):
        deserialize_session(" " * (MAX_RECORD_BYTES + 1))
    with pytest.raises(StorageFailure):
        serialize_session("fictional", jar(cookie(value="中" * 25000)))
    with pytest.raises(StorageFailure):
        serialize_session("fictional", jar(cookie(value="\ud800")))


def test_measurement_counts_complete_unicode_record():
    cookies = jar(cookie())
    text = serialize_session("测试😀", cookies)
    assert measure_session("测试😀", cookies) == {
        "session_utf8_bytes": len(text.encode("utf-8")),
        "session_utf16le_bytes": len(text.encode("utf-16le")),
        "windows_limit_bytes": 2560,
    }
    assert len(text.encode("utf-16le")) != len(text) * 2


def test_windows_exact_boundary_and_overflow_not_truncated():
    cookies = jar(cookie(value=""))
    base = measure_session("fictional", cookies)["session_utf16le_bytes"]
    padding = (2560 - base) // 2
    item = next(iter(cookies))
    item.value = "a" * padding
    assert measure_session("fictional", cookies)["session_utf16le_bytes"] == 2560
    item.value += "a"
    assert measure_session("fictional", cookies)["session_utf16le_bytes"] == 2562
    assert next(iter(deserialize_session(serialize_session("fictional", cookies))[1])).value == item.value


def test_pure_functions_never_import_keyring_or_open_files(monkeypatch, capsys):
    original_import = builtins.__import__
    def guarded_import(name, *args, **kwargs):
        assert not name.startswith("keyring")
        return original_import(name, *args, **kwargs)
    def forbidden_open(*args, **kwargs):
        raise AssertionError("Pure codec opened a file")
    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(builtins, "open", forbidden_open)
    selected = select_session_cookies(SimpleNamespace(cookies=jar(cookie())))
    measure_session("fictional", selected)
    deserialize_session(serialize_session("fictional", selected))
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
