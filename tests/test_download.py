# SPDX-License-Identifier: GPL-3.0-or-later
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import os

import pytest
import requests

from icourse_dl import download as d
from icourse_dl.errors import DownloadFailure, PermissionDenied
from media_fixture import MEDIA, server
from smoke_download import Lecture, Source, run_one, verify


@pytest.mark.parametrize('mode', ['html', 'json', 'empty', 'invalid'])
def test_reject_bad_media(tmp_path, mode):
    with server(mode) as (url, _), pytest.raises(DownloadFailure):
        run_one(url, tmp_path)
    assert not list(tmp_path.glob('2026*.mp4'))


def test_exact_416_length(tmp_path):
    part = tmp_path / '.icourse-dl-11-22.work.mp4.part'
    part.write_bytes(MEDIA[:-30])
    with server('416') as (url, _), pytest.raises(DownloadFailure):
        run_one(url, tmp_path)
    assert not list(tmp_path.glob('2026*.mp4'))
    work = tmp_path / 'short.work.mp4'
    work.write_bytes(MEDIA[:-30])
    with pytest.raises(DownloadFailure, match='长度'):
        d._validate(work, len(MEDIA))


def test_skip_and_zero(tmp_path, capsys):
    final = tmp_path / '2026-01-02_22_中文 100% 视频.mp4'
    final.write_bytes(b'existing')
    assert run_one('http://127.0.0.1:1/no', tmp_path) == final
    assert '未验证' in capsys.readouterr().err
    final.write_bytes(b'')
    with pytest.raises(DownloadFailure, match='零字节'):
        run_one('http://127.0.0.1:1/no', tmp_path)


def test_restart_and_overwrite(tmp_path):
    part = tmp_path / '.icourse-dl-11-22.work.mp4.part'
    part.write_bytes(b'bad stale part')
    with server() as (url, state):
        verify(run_one(url, tmp_path, restart=True))
        assert all(not r or r == 'bytes=0-4095' for _, r, _ in state['requests'])
        verify(run_one(url, tmp_path, overwrite=True))


def test_space_before_transfer(tmp_path):
    with server() as (url, state), patch.object(d.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)):
        with pytest.raises(DownloadFailure, match='空间'):
            run_one(url, tmp_path)
        assert all(r == 'bytes=0-4095' for _, r, _ in state['requests'])
    assert not list(tmp_path.glob('.icourse-dl-probe-*'))


def test_preflight_before_network(tmp_path):
    with server() as (url, state), patch.object(d, '_preflight', side_effect=OSError('SECRET')):
        with pytest.raises(DownloadFailure) as error:
            run_one(url, tmp_path)
        assert 'SECRET' not in str(error.value)
        assert not state['requests']


def test_copy_failure_preserves_work(tmp_path):
    work, final = tmp_path / 'work', tmp_path / 'final'
    work.write_bytes(MEDIA)
    for error in (OSError('full'), KeyboardInterrupt()):
        with patch.object(d.shutil, 'copyfileobj', side_effect=error):
            with pytest.raises(type(error)):
                d._commit(work, final, 'copy')
        assert not final.exists()
        assert work.read_bytes() == MEDIA
    final.write_bytes(b'original')
    with pytest.raises(FileExistsError):
        d._commit(work, final, 'copy')
    assert final.read_bytes() == b'original'


def test_preflight_fallback(tmp_path):
    with patch.object(d.os, 'link', side_effect=OSError('unsupported')):
        mode = d._preflight(tmp_path, False)
    assert mode == ('rename' if os.name == 'nt' else 'copy')
    assert not list(tmp_path.iterdir())


def test_length_change(tmp_path):
    with server() as (url, _), patch.object(d, '_probe', side_effect=[d.MediaProbe(len(MEDIA)), d.MediaProbe(len(MEDIA) + 1)]):
        with pytest.raises(DownloadFailure, match='改变'):
            run_one(url, tmp_path)
    assert (tmp_path / '.icourse-dl-11-22.work.mp4').exists()
    assert not list(tmp_path.glob('2026*.mp4'))


def test_denied_refresh_once(tmp_path):
    count = []
    with server('denied') as (url, _), requests.Session() as session:
        def refresh():
            count.append(1)
            return Source(url=url)
        with pytest.raises(PermissionDenied):
            d.download_lecture(Source(url=url), Lecture(), session, d.DownloadOptions(tmp_path), refresh_media=refresh)
    assert count == [1]


def test_cookie_scope_and_redaction(tmp_path, capsys):
    from http.cookiejar import Cookie
    with server() as (url, state), requests.Session() as session:
        session.cookies.set('wrong', 'SECRET_OTHER', domain='example.invalid', path='/')
        session.cookies.set_cookie(Cookie(0, 'right', 'SECRET_COOKIE', None, False, '127.0.0.1', False, False, '/', True, False, None, True, None, None, {}, False))
        path = d.download_lecture(Source(url=url + '?SECRET_QUERY=1'), Lecture(), session, d.DownloadOptions(tmp_path), refresh_media=lambda: None)
        verify(path)
        assert all('SECRET_OTHER' not in cookie for _, _, cookie in state['requests'])
        assert any('SECRET_COOKIE' in cookie for _, _, cookie in state['requests'])
    capture = capsys.readouterr()
    assert 'SECRET' not in capture.out + capture.err
    for path in tmp_path.iterdir():
        if path.suffix not in ('.mp4', '.part'):
            assert b'SECRET' not in path.read_bytes()


def test_lock_conflict(tmp_path):
    path = tmp_path / 'lock'
    with d._lock(path), pytest.raises(DownloadFailure):
        with d._lock(path):
            pass


@pytest.mark.parametrize('name', ['../a', 'CON', 'LPT1.txt', 'a:bad?', '...'])
def test_safe_titles(name):
    title = d._title(name)
    assert title and not any(c in title for c in '/\\:<>?*')
    assert title == title.rstrip(' .')
    assert title not in ('CON', 'LPT1.txt')


def test_header_boxes():
    assert d._head_valid(MEDIA)
    assert d._head_valid(b'\0\0\0\x08free' + MEDIA)
    assert not d._head_valid(b'<html>ftyp</html>')
    assert not d._head_valid(b'\0\0\0\x04ftyp')


def test_symlink_rejected(tmp_path):
    real = tmp_path / 'real'
    real.write_bytes(MEDIA)
    part = tmp_path / '.icourse-dl-11-22.work.mp4.part'
    try:
        part.symlink_to(real)
    except OSError:
        pytest.skip('symlink privilege unavailable')
    with pytest.raises(DownloadFailure):
        run_one('http://127.0.0.1:1/no', tmp_path, restart=True)
    assert real.read_bytes() == MEDIA


def test_interruption_preserves_part(tmp_path):
    part = tmp_path / '.icourse-dl-11-22.work.mp4.part'
    def interrupted(*args):
        part.write_bytes(MEDIA[:4096])
        raise KeyboardInterrupt()
    with server() as (url, _), patch.object(d, '_transfer', side_effect=interrupted), pytest.raises(KeyboardInterrupt):
        run_one(url, tmp_path)
    assert part.exists()
    assert not list(tmp_path.glob('2026*.mp4'))


def test_copy_success_and_extra_space(tmp_path):
    work, final = tmp_path / 'work', tmp_path / 'final'
    work.write_bytes(MEDIA)
    d._commit(work, final, 'copy')
    assert final.read_bytes() == MEDIA and not work.exists()
    with server() as (url, state), patch.object(d, '_preflight', return_value='copy'), patch.object(d.shutil, 'disk_usage', return_value=SimpleNamespace(free=len(MEDIA))):
        with pytest.raises(DownloadFailure, match='空间'):
            run_one(url, tmp_path)
        assert all(r == 'bytes=0-4095' for _, r, _ in state['requests'])


def test_concurrent_destination_preserved(tmp_path):
    final = tmp_path / '2026-01-02_22_中文 100% 视频.mp4'
    transfer = d._transfer
    def concurrent(*args):
        transfer(*args)
        final.write_bytes(b'concurrent original')
    with server() as (url, _), patch.object(d, '_transfer', side_effect=concurrent), pytest.raises(DownloadFailure):
        run_one(url, tmp_path)
    assert final.read_bytes() == b'concurrent original'
    assert (tmp_path / '.icourse-dl-11-22.work.mp4').read_bytes() == MEDIA


def test_redirect_does_not_forward_unmatched_cookie(tmp_path):
    with server('redirect') as (url, state), requests.Session() as session:
        session.cookies.set('private', 'SECRET_COOKIE', domain='127.0.0.1', path='/')
        work = tmp_path / 'redirect.mp4'
        d._transfer(Source(url=url), Lecture(), session, work, False)
        assert work.read_bytes() == MEDIA
        destination = [cookie for path, _, cookie in state['requests'] if path == '/destination.mp4']
        assert destination and all('SECRET_COOKIE' not in cookie for cookie in destination)


def test_host_only_cookie_not_expanded():
    from http.cookiejar import Cookie
    with requests.Session() as session:
        session.cookies.set_cookie(Cookie(0, 'hostonly', 'SECRET', None, False, 'fudan.edu.cn', False, False, '/', True, True, None, True, None, None, {}, False))
        assert not list(d._media_cookies(session, 'https://webvpn.fudan.edu.cn/media.mp4'))
