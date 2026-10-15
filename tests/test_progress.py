# SPDX-License-Identifier: GPL-3.0-or-later
from http.cookiejar import CookieJar
from io import StringIO
from types import SimpleNamespace

import pytest
import requests
from yt_dlp.utils import DownloadError

from icourse_dl import download as d
from icourse_dl.errors import DownloadFailure

SECRET_URL = 'https://webvpn.fudan.edu.cn/video?signature=SIGNED_URL_SECRET'


class ProgressStream(StringIO):
    def __init__(self, tty=False):
        super().__init__()
        self.tty = tty

    def isatty(self):
        return self.tty


def event(status='downloading', **values):
    return {
        'status': status, 'downloaded_bytes': 1024, 'total_bytes': 2048,
        'speed': 512, 'eta': 2,
        'filename': SECRET_URL, 'info_dict': {'url': SECRET_URL, 'password': 'PASSWORD_SECRET'},
        '_percent_str': SECRET_URL, '_speed_str': SECRET_URL, 'error': SECRET_URL,
        'http_headers': {'Cookie': 'COOKIE_SECRET'},
        **values,
    }


def assert_no_secrets(text):
    for secret in ('https://', 'SIGNED_URL_SECRET', 'PASSWORD_SECRET', 'COOKIE_SECRET', 'signature='):
        assert secret not in text


def test_nonterminal_progress_emits_only_start_and_completion():
    stream = ProgressStream()
    progress = d._DownloadProgress(stream)
    for count in range(100):
        progress(event(downloaded_bytes=count))
    progress(event('finished', downloaded_bytes=2048))
    progress(event('finished'))
    progress.close()
    lines = stream.getvalue().splitlines()
    assert len(lines) == 2
    assert 'Download: 0 B / 2.0 KiB' in lines[0]
    assert 'Transfer complete: 2.0 KiB / 2.0 KiB' in lines[1]
    assert '512 B/s' in lines[0] and 'ETA 00:02' in lines[0]
    assert '\r' not in stream.getvalue()
    assert_no_secrets(stream.getvalue())


def test_terminal_progress_throttles_redraw_and_finishes_line(monkeypatch):
    stream = ProgressStream(tty=True)
    now = [0.0]
    monkeypatch.setattr(d.shutil, 'get_terminal_size', lambda **kwargs: SimpleNamespace(columns=120))
    progress = d._DownloadProgress(stream, clock=lambda: now[0])
    progress(event())
    now[0] = 0.1
    progress(event(downloaded_bytes=1536))
    assert stream.getvalue().count('\r') == 1
    now[0] = 0.3
    progress(event(downloaded_bytes=1536))
    assert stream.getvalue().count('\r') == 2
    progress(event('finished', downloaded_bytes=2048))
    progress.close()
    assert stream.getvalue().count('\r') == 3
    assert stream.getvalue().count('\n') == 1
    assert stream.getvalue().endswith('\n')
    assert_no_secrets(stream.getvalue())


def test_terminal_interruption_closes_line_once():
    stream = ProgressStream(tty=True)
    progress = d._DownloadProgress(stream)
    progress(event())
    progress.close()
    progress.close()
    assert stream.getvalue().count('\n') == 1


def test_unknown_total_and_speed():
    stream = ProgressStream()
    progress = d._DownloadProgress(stream)
    progress(event(total_bytes=None, speed=None, eta=None))
    assert '1.0 KiB / ? | ?/s | ETA ?' in stream.getvalue()


def test_estimated_total_is_distinct():
    stream = ProgressStream()
    d._DownloadProgress(stream)(event(total_bytes=None, total_bytes_estimate=4096))
    assert '/ ~4.0 KiB' in stream.getvalue()


@pytest.mark.parametrize('invalid', [None, -1, float('nan'), float('inf'), float('-inf'), True,
                                   '123', SECRET_URL, 10 ** 500, [], {}])
def test_invalid_numeric_fields_are_not_interpreted_or_logged(invalid):
    stream = ProgressStream()
    d._DownloadProgress(stream)(event(downloaded_bytes=invalid, total_bytes=invalid,
                                      speed=invalid, eta=invalid))
    assert 'Download: ? / ? | ?/s | ETA ?' in stream.getvalue()
    assert_no_secrets(stream.getvalue())


@pytest.mark.parametrize(('size', 'expected'), [(0, '0 B'), (1023, '1023 B'), (1024, '1.0 KiB'),
                                               (1024 ** 2, '1.0 MiB'), (1024 ** 3, '1.0 GiB')])
def test_byte_unit_boundaries(size, expected):
    stream = ProgressStream()
    d._DownloadProgress(stream)(event(downloaded_bytes=size, total_bytes=size, speed=0, eta=0))
    assert f'{expected} / {expected}' in stream.getvalue()
    assert '0 B/s | ETA 00:00' in stream.getvalue()


def test_large_eta_stays_bounded():
    stream = ProgressStream()
    d._DownloadProgress(stream)(event(eta=172800))
    assert 'ETA 2.0d' in stream.getvalue()


def test_unknown_status_ignored_and_error_text_not_leaked():
    stream = ProgressStream()
    progress = d._DownloadProgress(stream)
    progress(event(SECRET_URL))
    assert stream.getvalue() == ''
    progress(event('error'))
    assert 'Transfer failed:' in stream.getvalue()
    assert_no_secrets(stream.getvalue())


def test_small_terminal_redraw_does_not_wrap(monkeypatch):
    monkeypatch.setattr(d.shutil, 'get_terminal_size', lambda **kwargs: SimpleNamespace(columns=32))
    stream = ProgressStream(tty=True)
    d._DownloadProgress(stream)(event())
    assert len(stream.getvalue().removeprefix('\r')) <= 31


@pytest.mark.parametrize('outcome', ['success', 'failure', 'denied', 'cancel'])
def test_transfer_installs_safe_hook_and_preserves_failure_behavior(tmp_path, monkeypatch, outcome):
    stream = ProgressStream(tty=True)
    monkeypatch.setattr(d.sys, 'stderr', stream)
    captured = {}

    class FakeDownloader:
        def __init__(self, options, auto_init):
            captured.update(options)
            assert auto_init is False
            self.cookiejar = CookieJar()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def process_ie_result(self, info, download):
            assert download is True
            assert info['url'] == SECRET_URL
            for level in ('debug', 'warning', 'error'):
                getattr(captured['logger'], level)(SECRET_URL)
            for hook in captured['progress_hooks']:
                hook(event())
            if outcome == 'cancel':
                raise KeyboardInterrupt()
            if outcome in ('failure', 'denied'):
                error = DownloadError(SECRET_URL)
                if outcome == 'denied':
                    error.status = 403
                raise error
            for hook in captured['progress_hooks']:
                hook(event('finished', downloaded_bytes=2048))

    monkeypatch.setattr('yt_dlp.YoutubeDL', FakeDownloader)
    source = SimpleNamespace(url=SECRET_URL)
    lecture = SimpleNamespace(sub_id=22, title='测试课程')
    with requests.Session() as session:
        if outcome == 'success':
            d._transfer(source, lecture, session, tmp_path / 'work.mp4', False)
        else:
            error_type = {'failure': DownloadFailure, 'denied': d._MediaDenied, 'cancel': KeyboardInterrupt}[outcome]
            with pytest.raises(error_type) as caught:
                d._transfer(source, lecture, session, tmp_path / 'work.mp4', False)
            assert_no_secrets(str(caught.value))
    assert len(captured['progress_hooks']) == 1
    assert captured['quiet'] is True and captured['noprogress'] is True
    assert captured['continuedl'] is True and captured['cookiefile'] is None
    assert stream.getvalue().endswith('\n')
    assert_no_secrets(stream.getvalue())
