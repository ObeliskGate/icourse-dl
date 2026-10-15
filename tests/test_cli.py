# SPDX-License-Identifier: GPL-3.0-or-later

import pytest

from icourse_dl.cli import main


@pytest.fixture(autouse=True)
def isolated_working_directory(tmp_path, monkeypatch, saved_credentials):
    # Never consume a developer's real project .env during CLI tests.
    monkeypatch.chdir(tmp_path)


@pytest.mark.parametrize('argv', [
    ['search', 'courses', '学习', '--term', '27', '--course-id', '1'],
    ['search', 'lectures', '--lecture-id', '7'],
    ['login', '--output', 'out'],
    ['login', '--clear', '--env'],
    ['download', '学习', '--course-id', '1'],
    ['download', '--course-id', '1', '--term', '27'],
    ['download', '学习', '--lecture-id', '7'],
])
def test_invalid_combinations(argv):
    try:
        code = main(argv)
    except SystemExit as error:
        code = error.code
    assert code == 2


def test_explicit_broken_config_rejected_before_authentication(tmp_path, monkeypatch):
    from icourse_dl import auth
    path = tmp_path / 'config.env'
    path.write_text('StuId=fake\n', encoding='utf-8')
    monkeypatch.setattr(auth.Authenticator, 'login', lambda *_: pytest.fail('must not authenticate'))
    assert main(['login', '--env', str(path)]) == 2


def test_noninteractive_no_environment_credentials(monkeypatch):
    monkeypatch.setenv('StuId', 'fake')
    monkeypatch.setenv('UISPsw', 'secret')
    monkeypatch.setattr('sys.stdin.isatty', lambda: False)
    assert main(['login']) == 2
