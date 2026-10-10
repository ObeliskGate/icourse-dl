# SPDX-License-Identifier: GPL-3.0-or-later
"""Run against the installed package; never add source directories to sys.path."""
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch

import requests
from icourse_dl.download import DownloadOptions, download_lecture
from icourse_dl.errors import DownloadFailure
from media_fixture import MEDIA, server


@dataclass
class Source:
    course_id: str = '11'
    sub_id: str = '22'
    url: str = field(default='', repr=False)


@dataclass
class Lecture:
    course_id: str = '11'
    sub_id: str = '22'
    title: str = '中文 100% 视频'
    lecturer: str = ''
    date: str = '2026-01-02'
    has_playback: bool = True


def run_one(url, output, **kwargs):
    with requests.Session() as session:
        session.trust_env = False
        return download_lecture(Source(url=url), Lecture(), session, DownloadOptions(Path(output), **kwargs), refresh_media=lambda: Source(url=url + '?fresh=1'))


def verify(path):
    expected = hashlib.sha256(MEDIA).hexdigest()
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    assert actual == expected, (actual, expected)
    assert not any(p.suffix in ('.json', '.cookies', '.ytdl') for p in path.parent.iterdir())
    return actual


def main():
    for mode in ('normal', 'disconnect', 'ignore', 'unknown', 'refresh'):
        with TemporaryDirectory() as directory, server(mode) as (url, state):
            if mode == 'ignore':
                (Path(directory) / '.icourse-dl-11-22.work.mp4.part').write_bytes(MEDIA[:32768])
            result = run_one(url, directory)
            digest = verify(result)
            if mode == 'disconnect':
                assert any(r and r != 'bytes=0-4095' for _, r, _ in state['requests'])
            print(f'{mode}: sha256={digest} PASS')
    with TemporaryDirectory() as directory, server('always-disconnect') as (url, state):
        # Separate interpreter fails with a recoverable part, then a new one resumes.
        command = [sys.executable, str(Path(__file__).absolute()), '--child', url, directory]
        result = subprocess.run(command, capture_output=True, text=True)
        assert result.returncode == 5, result.stderr
        assert list(Path(directory).glob('*.part'))
        before = len(state['requests'])
        state['mode'] = 'normal'
        result = subprocess.run(command, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert any(r and r != 'bytes=0-4095' for _, r, _ in state['requests'][before:])
        print(f'new-process-resume: sha256={verify(next(Path(directory).glob("2026*.mp4")))} PASS')
    with TemporaryDirectory() as directory, server() as (url, _):
        with patch('icourse_dl.download.os.link', side_effect=OSError('unsupported')):
            result = run_one(url, directory)
        print(f'no-hardlinks: sha256={verify(result)} PASS')
    return 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--child':
        try:
            run_one(sys.argv[2], sys.argv[3])
        except DownloadFailure:
            sys.exit(5)
        sys.exit(0)
    sys.exit(main())
