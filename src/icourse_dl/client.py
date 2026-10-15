# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict course inputs and authorized, single-stream MP4 resolution."""
from dataclasses import dataclass, field
from datetime import date
import hashlib
import ipaddress
import re
import time
from urllib.parse import urlencode, urlsplit, urlunsplit
from uuid import uuid4

import requests

from .auth import Authenticator, ICOURSE, Identity, SafeHTTP, parse_json, vpn_url
from .errors import ConfigurationError, PermissionDenied, ProtocolError


@dataclass(frozen=True)
class CourseTarget:
    course_id: str
    lecture_id: str | None = None


@dataclass(frozen=True)
class Course:
    course_id: str
    title: str
    course_code: str
    term_name: str
    term_ids: tuple[str, ...]


@dataclass(frozen=True)
class Lecture:
    course_id: str
    sub_id: str
    title: str
    lecturer: str
    date: str
    has_playback: bool


@dataclass(frozen=True)
class MediaSource:
    course_id: str
    sub_id: str
    url: str = field(repr=False)


def _id(value: object, error: type[Exception] = ConfigurationError) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value):
        raise error("课程和课次 ID 必须是正十进制整数。")
    normalized = value.lstrip("0")
    if not normalized:
        raise error("课程和课次 ID 必须大于零。")
    return normalized


def parse_target(course_id: str | None, lecture_id: str | None) -> CourseTarget:
    """Validate and normalize explicitly supplied course and lecture IDs."""
    return CourseTarget(_id(course_id), None if lecture_id is None else _id(lecture_id))


def _lecture_date(title: str, year: str, month: str, day: str) -> str:
    prefix = re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}", title)
    if prefix:
        try:
            return date.fromisoformat(prefix.group()).isoformat()
        except ValueError:
            pass
    try:
        if not all(re.fullmatch(r"[0-9]+", part) for part in (year, month, day)):
            raise ValueError
        return date(int(year), int(month), int(day)).isoformat()
    except (ValueError, OverflowError):
        return "日期未知"


def _mapping(value: object) -> dict:
    if not isinstance(value, dict):
        raise ProtocolError("课程响应结构不兼容。")
    return value


def _text(item: dict, key: str) -> str:
    value = item.get(key, "")
    if not isinstance(value, str):
        raise ProtocolError("课次文本字段不兼容。")
    return value


def _course(record: dict) -> Course:
    course_id = _id(str(record.get('id', '')), ProtocolError)
    fields = [record.get(key) for key in ('title', 'course_code', 'term_name', 'term')]
    if not all(isinstance(value, str) and value.strip() for value in fields):
        raise ProtocolError('Incomplete course catalog record.')
    name, code, term_name, membership = fields
    if not re.fullmatch(r'_(?:[1-9][0-9]*_)+', membership):
        raise ProtocolError('Invalid course semester membership.')
    term_ids = tuple(dict.fromkeys(membership.strip('_').split('_')))
    return Course(course_id, name, code, term_name, term_ids)


def _media_parts(url: str):
    try:
        parts = urlsplit(url)
        host = parts.hostname
        if (parts.scheme not in ("http", "https") or not host
                or parts.username is not None or parts.password is not None
                or "#" in url or "\\" in url
                or any(ord(c) <= 32 or ord(c) == 127 for c in url)
                or parts.port == 0):
            raise ValueError
        host = host.rstrip(".").lower()
        if host == "localhost" or host.endswith(".localhost") or "%" in host:
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            # Reject ambiguous numeric host spellings, e.g. 127.1 or 2130706433.
            if re.fullmatch(r"[0-9.]+", host) or host.startswith("0x"):
                raise ValueError
            if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                       for label in host.split(".")):
                raise ValueError
        else:
            if address.version == 6 and address.ipv4_mapped:
                address = address.ipv4_mapped
            if (address.is_loopback or address.is_link_local
                    or address.is_multicast or address.is_unspecified):
                raise ValueError
        return parts
    except ValueError:
        raise ProtocolError("服务器返回不安全或无效的媒体地址。") from None


class ICourseClient:
    def __init__(self, session: requests.Session, identity: Identity):
        self.session = session
        self.identity = identity
        self.http = SafeHTTP(session)

    def _get(self, path: str, **params: str) -> dict:
        response = self.http.request(
            "GET", vpn_url(f"{ICOURSE}{path}?{urlencode(params)}"),
            max_bytes=16 * 1024 * 1024, retry=True,
        )
        if response.status_code in (401, 403):
            Authenticator(self.session).probe_identity(self.identity.account)
            raise PermissionDenied("当前账户无权访问该课程或课次。")
        if not 200 <= response.status_code < 300:
            raise ProtocolError("课程接口返回异常 HTTP 状态。")
        body = _mapping(parse_json(response))
        code = body.get("code")
        if isinstance(code, bool) or not isinstance(code, int):
            raise ProtocolError("课程接口业务状态字段不兼容。")
        if code == 7001:
            raise PermissionDenied("该课次尚未开放。")
        if code != 0:
            raise PermissionDenied("课程接口拒绝当前请求。")
        _mapping(body.get("data"))
        return body

    def search_courses(self, title: str, term: str | None = None) -> list[Course]:
        filters = {} if term is None else {'term': _id(term)}
        title = title.strip()
        if not title:
            raise ConfigurationError('A nonempty course name or keyword is required.')
        courses: dict[str, Course] = {}
        total = None
        page = 1
        while True:
            data = self._get('/portal/courseapi/v3/multi-search/get-course-list',
                             tenant='222', title=title, **filters,
                             page=str(page), per_page='100')['data']
            count = data.get('total')
            if type(count) not in (str, int) or not re.fullmatch(r'[0-9]+', str(count)):
                raise ProtocolError('Invalid course catalog total.')
            count = int(count)
            if total is not None and count != total:
                raise ProtocolError('Course catalog changed during pagination; repeat the search.')
            total = count
            rows = data.get('list')
            if not isinstance(rows, list):
                raise ProtocolError('Invalid course catalog list.')
            before = len(courses)
            for row in rows:
                course = _course(_mapping(row))
                if term is not None and filters['term'] not in course.term_ids:
                    raise ProtocolError('Course catalog returned a different semester.')
                if course.course_id in courses and courses[course.course_id] != course:
                    raise ProtocolError('Conflicting course catalog records.')
                courses[course.course_id] = course
            if len(courses) > total:
                raise ProtocolError('Course catalog exceeded its declared total.')
            if len(courses) == total:
                return list(courses.values())
            if len(courses) == before:
                raise ProtocolError('Course catalog pagination stopped before all results were received.')
            page += 1

    def get_course(self, course_id: str) -> Course:
        course_id = _id(course_id)
        course = _course(self._get('/courseapi/v3/multi-search/get-course-detail',
                                  course_id=course_id)['data'])
        if course.course_id != course_id:
            raise ProtocolError('Course detail returned a different course.')
        return course

    def get_lectures(self, course_id: str) -> list[Lecture]:
        course_id = _id(course_id)
        body = self._get("/courseapi/v3/multi-search/get-course-detail", course_id=course_id)
        years = _mapping(body["data"].get("sub_list", {}))
        lectures: dict[str, Lecture] = {}
        for year, months in years.items():
            for month, days in _mapping(months).items():
                for day, items in _mapping(days).items():
                    if not isinstance(items, list):
                        raise ProtocolError("课次列表结构不兼容。")
                    for item in items:
                        item = _mapping(item)
                        if "id" not in item:
                            continue
                        raw_id = item["id"]
                        if type(raw_id) is int:
                            raw_id = str(raw_id)
                        sub_id = _id(raw_id, ProtocolError)
                        title = _text(item, "sub_title")
                        lecture = Lecture(
                            course_id, sub_id, title, _text(item, "lecturer_name"),
                            _lecture_date(title, str(year), str(month), str(day)),
                            type(item.get("playback_status")) in (str, int)
                            and str(item["playback_status"]) == "1",
                        )
                        if sub_id in lectures and lectures[sub_id] != lecture:
                            raise ProtocolError("重复课次存在冲突字段。")
                        lectures[sub_id] = lecture
        return sorted(lectures.values(), key=lambda item: (item.date, len(item.sub_id), item.sub_id))

    def resolve_media(self, course_id: str, sub_id: str) -> MediaSource:
        course_id, sub_id = _id(course_id), _id(sub_id)
        # Do not cache this authorization context across a signature refresh.
        if not any(item.sub_id == sub_id for item in self.get_lectures(course_id)):
            raise PermissionDenied("该课次不属于所选课程。")
        body = self._get("/courseapi/v3/portal-home-setting/get-sub-info",
                         course_id=course_id, sub_id=sub_id)
        data = body["data"]
        candidates: list[str] = []
        videos = data.get("video_list", {})
        if isinstance(videos, dict):
            candidates.extend(value["preview_url"] for value in videos.values()
                              if isinstance(value, dict) and isinstance(value.get("preview_url"), str))
        playurls = data.get("playurl", {})
        if isinstance(playurls, dict):
            candidates.extend(value for key, value in playurls.items()
                              if key != "now" and isinstance(value, str))
        unsupported = False
        for candidate in candidates:
            if not candidate:
                continue
            parts = _media_parts(candidate)
            suffix = parts.path.lower()
            if suffix.endswith((".m3u8", ".mpd", ".ism", ".ismc")) or suffix.endswith("/manifest"):
                unsupported = True
            if not suffix.endswith(".mp4"):
                continue
            now = body.get("now", int(time.time()))
            if type(now) is int and now >= 0:
                timestamp = str(now)
            elif isinstance(now, str) and re.fullmatch(r"[0-9]+", now):
                timestamp = now.lstrip("0") or "0"
            else:
                raise ProtocolError("媒体签名时间字段不兼容。")
            identity = self.identity
            digest = hashlib.md5(
                (parts.path + identity.user_id + identity.tenant_id
                 + identity.phone[::-1] + timestamp).encode("utf-8")
            ).hexdigest()
            query = parts.query + ("&" if parts.query else "") + urlencode({
                "clientUUID": str(uuid4()), "t": f"{identity.user_id}-{timestamp}-{digest}",
            })
            signed = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
            return MediaSource(course_id, sub_id, vpn_url(signed))
        if unsupported:
            raise PermissionDenied("当前媒体格式不支持：仅支持普通 MP4，不支持 HLS/DASH。")
        raise PermissionDenied("该课次没有可下载的普通 MP4 视频。")
