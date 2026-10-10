# SPDX-License-Identifier: GPL-3.0-or-later
import json
import os
from pathlib import Path

import pytest

from icourse_dl.cli import main


@pytest.mark.parametrize('argv', [
    ['status', '--env-file', 'missing'],
    ['logout', '--course-id', '1'],
    ['--course-id', '1', '--refresh'],
    ['login', '--measure-session', '--remember-password'],
    ['login', '--output', 'out'],
])
def test_invalid_combinations(argv):
    assert main(argv) == 2


def test_explicit_broken_config_rejected_before_authentication(tmp_path, monkeypatch):
    from icourse_dl import auth
    path = tmp_path / 'config.env'
    path.write_text('StuId=fake\n', encoding='utf-8')
    monkeypatch.setattr(auth.Authenticator, 'login', lambda *_: pytest.fail('must not authenticate'))
    assert main(['login', '--env-file', str(path)]) == 2


def test_measure_is_memory_only(tmp_path, monkeypatch, capsys):
    from icourse_dl import auth
    from icourse_dl.session_store import serialize_session, select_session_cookies
    import requests
    path = tmp_path / 'input.env'
    contents = 'StuId=fake-user\nUISPsw=" test password "\n'
    path.write_text(contents, encoding='utf-8')
    identity = auth.Identity('fake-user', '1', '222', '')
    calls = []

    def login(self, credentials):
        assert credentials.account == 'fake-user'
        assert credentials.password == ' test password '
        calls.append('login')
        self.session.cookies.set('session', 'synthetic-secret', domain='webvpn.fudan.edu.cn', secure=True)
        return identity

    def probe(self, expected):
        assert expected == 'fake-user'
        assert self.session.cookies.get('session') == 'synthetic-secret'
        calls.append('probe')
        return identity

    monkeypatch.setattr(auth.Authenticator, 'login', login)
    monkeypatch.setattr(auth.Authenticator, 'probe_identity', probe)
    import builtins
    original_import = builtins.__import__

    def checked_import(name, *args, **kwargs):
        if name.startswith('keyring'):
            pytest.fail('capacity command must not import keyring')
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', checked_import)
    assert main(['--env-file', str(path), 'login', '--measure-session']) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert set(result) == {'session_utf8_bytes', 'session_utf16le_bytes', 'windows_limit_bytes'}
    assert result['windows_limit_bytes'] == 2560
    assert calls == ['login', 'probe']
    assert 'synthetic-secret' not in captured.out + captured.err
    assert list(tmp_path.iterdir()) == [path]
    assert path.read_text(encoding='utf-8') == contents


def test_noninteractive_no_environment_credentials(monkeypatch):
    monkeypatch.setenv('StuId', 'fake')
    monkeypatch.setenv('UISPsw', 'secret')
    monkeypatch.setattr('sys.stdin.isatty', lambda: False)
    assert main(['login']) == 2
