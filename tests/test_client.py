# SPDX-License-Identifier: GPL-3.0-or-later
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from icourse_dl import client
from icourse_dl.auth import Identity
from icourse_dl.errors import AuthenticationError, ConfigurationError, PermissionDenied, ProtocolError


def detail(items=None, year="2026", month="3", day="5"):
    if items is None:
        items = [{"id": "7", "sub_title": "2026-03-05中文课", "lecturer_name": "教师", "playback_status": 1}]
    return {"code": 0, "data": {"sub_list": {year: {month: {day: items}}}}}


class FakeHTTP:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        item = self.responses.pop(0)
        if isinstance(item, int):
            return SimpleNamespace(status_code=item, headers={}, content=b"", url=url, history=[])
        content = item if isinstance(item, bytes) else json.dumps(item).encode()
        return SimpleNamespace(status_code=200, headers={"Content-Type": "application/json"},
                               content=content, url=url, history=[])


def make_client(responses):
    instance = client.ICourseClient(requests.Session(), Identity("fake-account", "42", "222", "1234"))
    instance.http = FakeHTTP(responses)
    return instance


@pytest.mark.parametrize("url", [
    "http://icourse.fudan.edu.cn/coursedetail?course_id=1",
    "https://evil.example/coursedetail?course_id=1",
    "https://icourse.fudan.edu.cn.evil.example/coursedetail?course_id=1",
    "https://user@icourse.fudan.edu.cn/coursedetail?course_id=1",
    "https://icourse.fudan.edu.cn:444/coursedetail?course_id=1",
    "https://icourse.fudan.edu.cn/coursedetail?course_id=1&course_id=1",
    "https://icourse.fudan.edu.cn/coursedetail?course_id=1&tenant_code=223",
    "https://icourse.fudan.edu.cn/coursedetail?course_id=1&tenant_code=222&tenant_code=222",
    "https://icourse.fudan.edu.cn/coursedetail?course_id=1#",
    "https://icourse.fudan.edu.cn/lecture?course_id=1",
    "https://icourse.fudan.edu.cn/coursedetail?course_id=",
    "\nhttps://icourse.fudan.edu.cn/coursedetail?course_id=1",
])
def test_invalid_urls(url):
    with pytest.raises(ConfigurationError):
        client.parse_target(url, None, None)


@pytest.mark.parametrize("value", [None, "", "0", "000", "-1", "+1", " 1", "1,2", "１", "١", "1.0"])
def test_invalid_ids(value):
    with pytest.raises(ConfigurationError):
        client.parse_target(None, value, None)


def test_input_normalization():
    assert client.parse_target("https://icourse.fudan.edu.cn:443/coursedetail/?course_id=001&tenant_code=222", None, "007") == client.CourseTarget("1", "7")
    assert client.parse_target(None, "002", None) == client.CourseTarget("2")
    with pytest.raises(ConfigurationError):
        client.parse_target("https://icourse.fudan.edu.cn/coursedetail?course_id=1", "1", None)
    with pytest.raises(ConfigurationError):
        client.parse_target(None, "1", "0")


def test_listing_dates_duplicates_and_sorting():
    items = [{"id": "10", "sub_title": "bad date"}, {"id": "2", "sub_title": "2025-12-31课"}]
    instance = make_client([detail(items + [items[0]])])
    lectures = instance.get_lectures("001")
    assert [(x.sub_id, x.date) for x in lectures] == [("2", "2025-12-31"), ("10", "2026-03-05")]
    assert all(x.course_id == "1" for x in lectures)
    assert len(instance.http.calls) == 1
    assert instance.http.calls[0][2] == {"max_bytes": 16 * 1024 * 1024, "retry": True}
    assert "get-sub-info" not in instance.http.calls[0][1]


def test_unknown_date_and_empty_list():
    instance = make_client([detail([{"id": 7, "sub_title": "2026-02-30课"}], day="99"), detail([])])
    assert instance.get_lectures("1")[0].date == "日期未知"
    assert instance.get_lectures("1") == []


@pytest.mark.parametrize("data", [
    detail([{"id": "7", "sub_title": "a"}, {"id": "7", "sub_title": "b"}]),
    detail([{"id": True}]), detail([{"id": "7", "sub_title": None}]),
    {"code": 0, "data": {"sub_list": []}}, {"code": 0, "data": []},
    {"code": False, "data": {}}, {"code": "0", "data": {}}, b"<html>login</html>",
])
def test_malformed_protocol(data):
    with pytest.raises(ProtocolError):
        make_client([data]).get_lectures("1")


def test_membership_precedes_media_request():
    instance = make_client([detail()])
    with pytest.raises(PermissionDenied):
        instance.resolve_media("1", "8")
    assert len(instance.http.calls) == 1


@pytest.mark.parametrize("code", [7001, 500, 403])
def test_denied_payload_never_used(code):
    instance = make_client([detail(), {"code": code, "data": {"video_list": {"x": {"preview_url": "https://cdn.example/a.mp4"}}, "content": {"playback": {"url": "https://cdn.example/secret.mp4"}}}}])
    with patch.object(client, "vpn_url", side_effect=lambda url: url) as vpn:
        with pytest.raises(PermissionDenied):
            instance.resolve_media("1", "7")
    assert len(vpn.call_args_list) == 2
    assert all("get-sub-detail" not in call[0][1] for call in instance.http.calls)


def test_signing_preserves_query_and_uses_top_level_timestamp():
    instance = make_client([detail(), {"code": 0, "now": "00100", "data": {
        "now": 999, "video_list": {"a": {"preview_url": "http://10.1.2.3/video/a.mp4?secret=original%2Bvalue"}},
        "playurl": {"a": "https://cdn.example/second.mp4"}}}])
    with patch.object(client, "vpn_url", side_effect=lambda url: url):
        source = instance.resolve_media("1", "7")
    parsed = urlsplit(source.url)
    query = parse_qs(parsed.query)
    expected = hashlib.md5(b"/video/a.mp4422224321100").hexdigest()
    assert query["t"] == [f"42-100-{expected}"]
    assert query["secret"] == ["original+value"]
    assert "clientUUID" in query
    assert parsed.hostname == "10.1.2.3"
    assert "secret" not in repr(source)
    assert source.course_id == "1" and source.sub_id == "7"


@pytest.mark.parametrize("now", [None, True, 1.2, "-1", "invalid", {}])
def test_bad_timestamp(now):
    instance = make_client([detail(), {"code": 0, "now": now, "data": {"playurl": {"x": "https://cdn.example/a.mp4"}}}])
    with pytest.raises(ProtocolError):
        instance.resolve_media("1", "7")


def test_playback_hint_not_authorization_and_no_hidden_fallback():
    instance = make_client([detail(), {"code": 0, "data": {"content": {"playback": {"url": "https://cdn.example/a.mp4"}}}}])
    with pytest.raises(PermissionDenied):
        instance.resolve_media("1", "7")
    assert len(instance.http.calls) == 2


def test_playurl_fallback_without_playback_hint_and_local_clock():
    instance = make_client([detail([{"id": "7", "playback_status": 0}]), {"code": 0, "data": {"playurl": {"now": "https://cdn.example/skip.mp4", "x": "https://cdn.example/actual.mp4?x=1"}}}])
    with patch.object(client, "vpn_url", side_effect=lambda url: url), patch.object(client.time, "time", return_value=123):
        source = instance.resolve_media("1", "7")
    assert "/actual.mp4" in source.url
    assert parse_qs(urlsplit(source.url).query)["t"][0].startswith("42-123-")


@pytest.mark.parametrize("url", ["https://cdn.example/a.m3u8", "https://cdn.example/a.mpd", "https://cdn.example/a/manifest"])
def test_manifest_rejected(url):
    instance = make_client([detail(), {"code": 0, "data": {"playurl": {"x": url}}}])
    with pytest.raises(PermissionDenied, match="格式不支持"):
        instance.resolve_media("1", "7")


@pytest.mark.parametrize("url", [
    "file:///a.mp4", "https://user:secret@cdn.example/a.mp4", "https://cdn.example/a.mp4#secret",
    "https://localhost/a.mp4", "https://localhost./a.mp4", "http://127.0.0.1/a.mp4",
    "http://127.1/a.mp4", "http://2130706433/a.mp4", "http://169.254.1.2/a.mp4",
    "http://224.0.0.1/a.mp4", "http://[::1]/a.mp4", "http://[::ffff:127.0.0.1]/a.mp4",
    "http://cdn.example:bad/a.mp4", "http://cdn.example/a\n.mp4",
])
def test_unsafe_media_rejected(url):
    instance = make_client([detail(), {"code": 0, "data": {"playurl": {"x": url}}}])
    with pytest.raises(ProtocolError):
        instance.resolve_media("1", "7")


@pytest.mark.parametrize("status", [401, 403])
def test_http_permission_probes_identity(status):
    instance = make_client([status])
    with patch.object(client.Authenticator, "probe_identity", return_value=instance.identity) as probe:
        with pytest.raises(PermissionDenied):
            instance.get_lectures("1")
        probe.assert_called_once_with("fake-account")
    instance = make_client([status])
    with patch.object(client.Authenticator, "probe_identity", side_effect=AuthenticationError("expired")):
        with pytest.raises(AuthenticationError):
            instance.get_lectures("1")


def test_refresh_rechecks_course_membership():
    instance = make_client([detail(), {"code": 0, "data": {"playurl": {"x": "https://cdn.example/a.mp4"}}}, detail([])])
    instance.resolve_media("1", "7")
    with pytest.raises(PermissionDenied):
        instance.resolve_media("1", "7")
    assert len(instance.http.calls) == 3


def standalone_smoke():
    """Offline complete course-to-authorized-MP4 protocol smoke."""
    test_input_normalization()
    test_signing_preserves_query_and_uses_top_level_timestamp()
    test_membership_precedes_media_request()
    test_playback_hint_not_authorization_and_no_hidden_fallback()
    print("client protocol smoke: passed (fake HTTP only)")


if __name__ == "__main__":
    standalone_smoke()
