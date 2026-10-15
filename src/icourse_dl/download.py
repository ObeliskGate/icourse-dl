# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded media validation around yt-dlp's native HTTP downloader.

Resume follows yt-dlp semantics, not entity validators. Use --restart when a
lecture's media changes. Compatible POSIX copying is not crash-atomic.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from dataclasses import dataclass
from http.cookiejar import DefaultCookiePolicy
import math
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time
from typing import Callable, TextIO, TYPE_CHECKING
from urllib.parse import urlsplit, urljoin
from uuid import uuid4

import requests
from urllib3.exceptions import HTTPError as UrllibHTTPError

from .errors import DownloadFailure, NetworkUnavailable, PermissionDenied

if TYPE_CHECKING:
    from .client import Lecture, MediaSource

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'


@dataclass(frozen=True)
class DownloadOptions:
    output: Path
    overwrite: bool = False
    restart: bool = False


@dataclass(frozen=True)
class MediaProbe:
    total_size: int | None


class _MediaDenied(Exception):
    pass


def _notice(message: str) -> None:
    print(message, file=sys.stderr)


def _regular(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(mode):
        raise DownloadFailure('下载路径不是普通文件；拒绝符号链接或目录。')
    return True


def _title(value: str) -> str:
    value = ''.join('_' if ord(c) < 32 or ord(c) == 127 or c in '<>:"/\\|?*' else c for c in value)
    value = value.strip(' .')[:80].rstrip(' .') or 'untitled'
    if re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', value):
        value = '_' + value
    return value


def _head_valid(data: bytes) -> bool:
    offset = 0
    while offset + 8 <= len(data):
        size = int.from_bytes(data[offset:offset + 4], 'big')
        kind = data[offset + 4:offset + 8]
        header = 8
        if size == 1:
            if offset + 16 > len(data):
                return False
            size = int.from_bytes(data[offset + 8:offset + 16], 'big')
            header = 16
        if size < header:
            return False
        if kind == b'ftyp':
            return size >= header + 8 and offset + header + 8 <= len(data)
        if kind not in (b'free', b'skip') or offset + size > len(data):
            return False
        offset += size
    return False


def _url(url: str) -> None:
    p = urlsplit(url)
    local = p.hostname in ('127.0.0.1', '::1', 'localhost')
    if p.username or p.password or p.fragment or not p.hostname or not (
        p.scheme == 'https' and p.hostname == 'webvpn.fudan.edu.cn'
        or p.scheme == 'http' and local
    ):
        raise DownloadFailure('媒体地址不符合安全传输要求。')


def _length(value: str | None) -> int | None:
    if value is None:
        return None
    if not re.fullmatch(r'[0-9]+', value):
        raise DownloadFailure('媒体长度声明无效。')
    return int(value)

def _media_cookies(session: requests.Session, url: str):
    from urllib.request import Request
    policy = DefaultCookiePolicy(strict_ns_domain=DefaultCookiePolicy.DomainStrictNonDomain)
    jar = copy.deepcopy(session.cookies)
    jar.set_policy(policy)
    request = Request(url)
    jar.add_cookie_header(request)
    for cookie in list(jar):
        if not (policy.return_ok(cookie, request) and policy.domain_return_ok(cookie.domain, request) and policy.path_return_ok(cookie.path, request)):
            jar.clear(cookie.domain, cookie.path, cookie.name)
    return jar


def _probe(session: requests.Session, url: str) -> MediaProbe:
    _url(url)
    # Use a clean session: no inherited Authorization, Origin, netrc or proxy.
    with requests.Session() as media:
        media.trust_env = False
        media.cookies = _media_cookies(session, url)
        current = url
        for _ in range(11):
            try:
                response = media.get(current, headers={'User-Agent': USER_AGENT, 'Range': 'bytes=0-4095', 'Accept-Encoding': 'identity'}, stream=True, timeout=(10, 30), allow_redirects=False)
                with response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        target = urljoin(current, response.headers.get('Location', ''))
                        _url(target)
                        if not response.headers.get('Location') or urlsplit(target).netloc != urlsplit(current).netloc:
                            raise DownloadFailure('媒体重定向目标不受信任。')
                        current = target
                        continue
                    if response.status_code in (401, 403):
                        raise _MediaDenied()
                    if response.status_code not in (200, 206):
                        raise DownloadFailure('媒体服务器未返回可下载内容。')
                    content_type = response.headers.get('Content-Type', '').lower()
                    if 'html' in content_type or 'json' in content_type or response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                        raise DownloadFailure('媒体服务器返回了非 MP4 内容。')
                    length = _length(response.headers.get('Content-Length'))
                    total = length
                    if response.status_code == 206:
                        match = re.fullmatch(r'bytes 0-([0-9]+)/([0-9]+)', response.headers.get('Content-Range', ''))
                        if not match:
                            raise DownloadFailure('媒体 Content-Range 无效。')
                        end, total = map(int, match.groups())
                        if end >= total or end > 4095 or length is not None and length != end + 1:
                            raise DownloadFailure('媒体长度声明互相矛盾。')
                    elif response.headers.get('Content-Range'):
                        raise DownloadFailure('媒体长度声明互相矛盾。')
                    data = response.raw.read(4096, decode_content=False)
                    if not _head_valid(data):
                        raise DownloadFailure('媒体头检查失败，不是可识别的 MP4。')
                    if length is not None and len(data) != min(length, 4096):
                        raise DownloadFailure('媒体探测响应不完整。')
                    return MediaProbe(total)
            except requests.RequestException:
                raise NetworkUnavailable('媒体网络暂不可达。') from None
            except (OSError, UrllibHTTPError):
                raise NetworkUnavailable('媒体网络读取失败。') from None
    raise DownloadFailure('媒体重定向过多。')


@contextmanager
def _lock(path: Path):
    _regular(path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    handle = os.fdopen(fd, 'r+b')
    locked = False
    try:
        if os.name == 'nt':
            import msvcrt
            if os.fstat(fd).st_size == 0:
                handle.write(b'0')
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError:
                raise DownloadFailure('该课次正在由另一个进程下载。') from None
        else:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise DownloadFailure('该课次正在由另一个进程下载。') from None
        locked = True
        yield
    finally:
        if locked and os.name == 'nt':
            handle.seek(0)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        handle.close()
        # Keep the stable lock inode: deleting it introduces a lock race.


def _commit(work: Path, final: Path, mode: str) -> None:
    if mode == 'replace':
        os.replace(work, final)
    elif mode == 'rename':
        os.rename(work, final)
    elif mode == 'link':
        os.link(work, final)
        work.unlink()
    else:
        created = False
        try:
            with final.open('xb') as target:
                created = True
                with work.open('rb') as source:
                    shutil.copyfileobj(source, target, 1024 * 1024)
            if final.stat().st_size != work.stat().st_size:
                raise OSError('copy length mismatch')
        except BaseException:
            if created:
                final.unlink(missing_ok=True)
            raise
        work.unlink()


def _preflight(output: Path, overwrite: bool) -> str:
    first = output / ('.icourse-dl-probe-' + uuid4().hex)
    second = output / ('.icourse-dl-probe-' + uuid4().hex)
    mode = 'replace' if overwrite else 'rename' if os.name == 'nt' else 'link'
    try:
        first.write_bytes(b'1')
        second.write_bytes(b'2')
        if mode == 'replace':
            _commit(first, second, mode)
            if second.read_bytes() != b'1':
                raise OSError('replace unavailable')
        else:
            try:
                _commit(first, second, mode)
            except FileExistsError:
                pass
            except OSError:
                if mode != 'link':
                    raise
                mode = 'copy'
            else:
                raise OSError('no-overwrite operation overwrote a file')
            if first.read_bytes() != b'1' or second.read_bytes() != b'2':
                raise OSError('preflight changed destination')
            second.unlink()
            try:
                _commit(first, second, mode)
            except OSError:
                if mode != 'link':
                    raise
                mode = 'copy'
                _commit(first, second, mode)
            if second.read_bytes() != b'1':
                raise OSError('commit unavailable')
        second.unlink()
        return mode
    finally:
        first.unlink(missing_ok=True)
        second.unlink(missing_ok=True)


class _QuietLogger:
    def debug(self, message):
        pass
    def warning(self, message):
        pass
    def error(self, message):
        pass

class _DownloadProgress:
    """Render only bounded numeric hook fields, never yt-dlp strings or metadata."""

    def __init__(self, stream: TextIO | None = None, *, clock: Callable[[], float] = time.monotonic):
        self.stream = sys.stderr if stream is None else stream
        self.clock = clock
        self.tty = self.stream.isatty()
        self.last_update: float | None = None
        self.width = 0
        self.started = False
        self.ended = False

    @staticmethod
    def _number(value) -> float | None:
        if type(value) not in (int, float) or not 0 <= value <= 1e30:
            return None
        return float(value) if math.isfinite(value) else None

    @staticmethod
    def _bytes(value: float | None) -> str:
        if value is None:
            return '?'
        for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'):
            if value < 1024 or unit == 'PiB':
                return f'{value:.0f} B' if unit == 'B' else f'{value:.1f} {unit}'
            value /= 1024
        raise AssertionError('unreachable byte unit')

    def __call__(self, event: dict) -> None:
        status = event.get('status')
        if self.ended or status not in ('downloading', 'finished', 'error'):
            return
        now = self.clock()
        final = status != 'downloading'
        if not final and self.started and (
            not self.tty or self.last_update is not None and now - self.last_update < 0.2
        ):
            return
        downloaded = self._number(event.get('downloaded_bytes'))
        total = self._number(event.get('total_bytes'))
        estimated = False
        if total is None:
            total = self._number(event.get('total_bytes_estimate'))
            estimated = total is not None
        speed = self._number(event.get('speed'))
        eta = self._number(event.get('eta'))
        if eta is None:
            remaining = '?'
        elif eta >= 86400:
            remaining = f'{eta / 86400:.1f}d'
        else:
            minutes, seconds = divmod(int(eta), 60)
            remaining = f'{minutes:02d}:{seconds:02d}'
        label = {'downloading': 'Download', 'finished': 'Transfer complete', 'error': 'Transfer failed'}[status]
        line = (f'{label}: {self._bytes(downloaded)} / '
                f'{"~" if estimated else ""}{self._bytes(total)}'
                f' | {self._bytes(speed)}/s | ETA {remaining}')
        if self.tty:
            columns = max(1, shutil.get_terminal_size(fallback=(80, 24)).columns - 1)
            line = line[:columns]
            self.stream.write('\r' + line + ' ' * max(0, self.width - len(line)))
            self.width = len(line)
            if final:
                self.stream.write('\n')
                self.width = 0
        else:
            self.stream.write(line + '\n')
        self.stream.flush()
        self.last_update = now
        self.started = True
        self.ended = final

    def close(self) -> None:
        # Also terminate an in-place line when a transfer raises or is cancelled.
        if self.width:
            self.stream.write('\n')
            self.stream.flush()
            self.width = 0



def _http_status(error: BaseException) -> int | None:
    pending = [error]
    seen = set()
    while pending:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        status = getattr(item, 'status', None) or getattr(item, 'code', None)
        if isinstance(status, int) and status in (401, 403):
            return status
        pending.extend(e for e in (getattr(item, '__cause__', None), getattr(item, '__context__', None)) if isinstance(e, BaseException))
        exc_info = getattr(item, 'exc_info', None)
        if isinstance(exc_info, tuple) and len(exc_info) > 1 and isinstance(exc_info[1], BaseException):
            pending.append(exc_info[1])
    return None


def _transfer(source: MediaSource, lecture: Lecture, session: requests.Session, work: Path, restart: bool) -> None:
    os.environ['YTDLP_NO_PLUGINS'] = '1'
    from yt_dlp import YoutubeDL
    from yt_dlp.utils import DownloadError
    progress = _DownloadProgress()
    options = {
        'continuedl': not restart, 'retries': 2, 'nopart': False,
        'http_chunk_size': 0, 'socket_timeout': 30,
        'retry_sleep_functions': {'http': lambda n: min(2, 2 ** (n - 1))},
        'quiet': True, 'noprogress': True, 'logger': _QuietLogger(),
        'outtmpl': str(work).replace('%', '%%'), 'overwrites': False,
        'cookiefile': None, 'cookiesfrombrowser': None, 'cachedir': False,
        'writeinfojson': False, 'writedescription': False, 'writethumbnail': False,
        'writesubtitles': False, 'writeautomaticsub': False, 'postprocessors': [],
        'fixup': 'never', 'verbose': False, 'debug_printtraffic': False,
        'download_archive': None, 'external_downloader': None,
        'file_access_retries': 1, 'usenetrc': False, 'proxy': '',
        'http_headers': {'User-Agent': USER_AGENT}, 'progress_hooks': [progress],
    }
    try:
        with YoutubeDL(options, auto_init=False) as ydl:
            policy = DefaultCookiePolicy(strict_ns_domain=DefaultCookiePolicy.DomainStrictNonDomain)
            ydl.cookiejar.set_policy(policy)
            # CookieJar performs path/domain/Secure/expiry checks on every request,
            # including redirects. Copy only cookies eligible for this media URL.
            for cookie in _media_cookies(session, source.url):
                ydl.cookiejar.set_cookie(copy.copy(cookie))
            ydl.process_ie_result({'_type': 'video', 'id': str(lecture.sub_id), 'title': _title(lecture.title), 'url': source.url, 'ext': 'mp4', 'protocol': urlsplit(source.url).scheme}, download=True)
    except DownloadError as error:
        if _http_status(error) in (401, 403):
            raise _MediaDenied() from None
        raise DownloadFailure('下载未完成；可恢复的部分文件已保留。') from None
    except (OSError, requests.RequestException):
        raise DownloadFailure('下载传输或文件写入失败；部分文件已保留。') from None
    finally:
        progress.close()


def _validate(work: Path, total: int | None) -> None:
    if not _regular(work) or work.stat().st_size == 0:
        raise DownloadFailure('下载器没有生成非空媒体文件。')
    with work.open('rb') as stream:
        valid = _head_valid(stream.read(4096))
    if not valid:
        work.unlink()
        raise DownloadFailure('下载结果不是 MP4；已移除无效工作文件。')
    if total is not None and work.stat().st_size != total:
        raise DownloadFailure('下载结果长度不符；请使用 --restart 重新下载。')


def download_lecture(source: MediaSource, lecture: Lecture, session: requests.Session,
                     options: DownloadOptions, *, refresh_media: Callable[[], MediaSource]) -> Path:
    for value in (lecture.course_id, lecture.sub_id):
        if not re.fullmatch(r'[1-9][0-9]*', str(value)):
            raise DownloadFailure('课次标识无效。')
    if (source.course_id, source.sub_id) != (lecture.course_id, lecture.sub_id):
        raise DownloadFailure('媒体与选定课次不一致。')
    date = lecture.date if re.fullmatch(r'\d{4}-\d{2}-\d{2}', lecture.date) else 'unknown-date'
    output = Path(options.output).absolute()
    final = output / f'{date}_{lecture.sub_id}_{_title(lecture.title)}.mp4'
    work = output / f'.icourse-dl-{lecture.course_id}-{lecture.sub_id}.work.mp4'
    part = Path(str(work) + '.part')
    refreshed = False
    known_total = None

    def fresh():
        nonlocal source, refreshed
        if refreshed:
            raise PermissionDenied('媒体访问被拒绝，已停止刷新。')
        refreshed = True
        source = refresh_media()
        if (source.course_id, source.sub_id) != (lecture.course_id, lecture.sub_id):
            raise DownloadFailure('刷新后的媒体与课次不一致。')
        _url(source.url)

    try:
        output.mkdir(parents=True, exist_ok=True)
        with _lock(Path(str(work) + '.lock')):
            if _regular(final) and final.stat().st_size > 0 and not options.overwrite:
                _notice('跳过已有非空文件；未验证其完整性。')
                return final
            if final.exists() and not options.overwrite:
                raise DownloadFailure('已有零字节目标；请明确使用 --overwrite。')
            for path in (work, part):
                if _regular(path) and options.restart:
                    path.unlink()
            mode = _preflight(output, options.overwrite)
            if mode == 'copy':
                _notice('兼容保存，完成后需一次本地复制及额外空间；复制不具备崩溃原子性。')
            while True:
                try:
                    probe = _probe(session, source.url)
                    if known_total is not None and probe.total_size is not None and known_total != probe.total_size:
                        raise DownloadFailure('媒体长度已改变；请使用 --restart。')
                    if probe.total_size is not None:
                        known_total = probe.total_size
                        present = work.stat().st_size if work.exists() else part.stat().st_size if part.exists() else 0
                        required = max(0, known_total - present) + (known_total if mode == 'copy' else 0)
                        if shutil.disk_usage(output).free < required:
                            raise DownloadFailure('保存目录剩余空间不足。')
                    else:
                        _notice('媒体总长度未知，无法预判完整容量。')
                    if not work.exists():
                        _transfer(source, lecture, session, work, options.restart and not refreshed)
                    _validate(work, known_total)
                    after = _probe(session, source.url)
                    if known_total is not None and after.total_size is not None and known_total != after.total_size:
                        raise DownloadFailure('媒体长度已改变；请使用 --restart。')
                    _validate(work, after.total_size if after.total_size is not None else known_total)
                    break
                except _MediaDenied:
                    fresh()
            _commit(work, final, mode)
            if known_total is None:
                _notice('下载正常结束，基本媒体检查通过；未做已知总长度校验。')
            return final
    except OSError:
        raise DownloadFailure('保存目录、锁或文件提交失败；已验证工作文件会保留。') from None
