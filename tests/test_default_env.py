# SPDX-License-Identifier: GPL-3.0-or-later
from unittest.mock import patch

import pytest
from icourse_dl import auth
from icourse_dl.cli import main


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch, saved_credentials):
    monkeypatch.chdir(tmp_path)


@pytest.mark.parametrize('contents', ['StuId=file-user\nUISPsw=file-password\n', 'invalid'])
def test_local_env_ignored_for_interactive_login(tmp_path, contents):
    path = tmp_path / '.env'
    path.write_text(contents, encoding='utf-8')
    def authenticate(self, credentials):
        assert credentials.account == 'typed-user'
        assert credentials.password == ' typed-password '
        return auth.Identity('typed-user', '1', '222', '')
    with patch('sys.stdin.isatty', return_value=True), patch('sys.stderr.isatty', return_value=True), patch('builtins.input', return_value='typed-user'), patch('getpass.getpass', return_value=' typed-password '), patch.object(auth.Authenticator, 'login', authenticate):
        assert main(['login']) == 0
    assert path.read_text(encoding='utf-8') == contents


@pytest.mark.parametrize('filename', ['chosen.env', '.env'])
def test_explicit_file_used_readonly(tmp_path, filename):
    (tmp_path / '.env').write_text('invalid', encoding='utf-8')
    explicit = tmp_path / filename
    contents = 'StuId=chosen\nUISPsw=" space ${UNCHANGED} "\n'
    explicit.write_text(contents, encoding='utf-8')
    def authenticate(self, credentials):
        assert credentials.account == 'chosen'
        assert credentials.password == ' space ${UNCHANGED} '
        return auth.Identity('chosen', '1', '222', '')
    with patch.object(auth.Authenticator, 'login', authenticate), patch.object(auth, 'prompt_credentials', side_effect=AssertionError('Unexpected prompt')):
        argv = ['login', '--env'] + ([str(explicit)] if filename != '.env' else [])
        assert main(argv) == 0
    assert explicit.read_text(encoding='utf-8') == contents


def test_noninteractive_does_not_use_local_env(tmp_path):
    (tmp_path / '.env').write_text('StuId=synthetic\nUISPsw=synthetic\n', encoding='utf-8')
    with patch('sys.stdin.isatty', return_value=False), patch.object(auth.Authenticator, 'login', side_effect=AssertionError('Unexpected network')):
        assert main(['login']) == 2


def test_parent_env_not_searched(tmp_path, monkeypatch):
    (tmp_path / '.env').write_text('StuId=synthetic\nUISPsw=synthetic\n', encoding='utf-8')
    child = tmp_path / 'child'
    child.mkdir()
    monkeypatch.chdir(child)
    with patch('sys.stdin.isatty', return_value=False), patch.object(auth.Authenticator, 'login', side_effect=AssertionError('Unexpected network')):
        assert main(['login']) == 2
