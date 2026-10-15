# SPDX-License-Identifier: GPL-3.0-or-later
from dataclasses import replace
from unittest.mock import patch

import pytest

from icourse_dl import auth, client, interaction
from icourse_dl.cli import main
from icourse_dl.errors import AuthenticationError, ConfigurationError


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def explicit_env(tmp_path):
    path = tmp_path / '.env'
    path.write_text('StuId=override\nUISPsw=" synthetic password "\nCOURSE_ID=37323\n', encoding='utf-8')
    return path


def identity(credentials):
    return auth.Identity(credentials.account, '1', '222', '')


def test_env_bypasses_unavailable_store_and_does_not_save(explicit_env, monkeypatch):
    from icourse_dl import credentials
    monkeypatch.setattr(credentials, 'CredentialStore', lambda: pytest.fail('Explicit env must bypass keyring'))
    monkeypatch.setattr(auth, 'prompt_credentials', lambda *_: pytest.fail('No hidden source fallback'))
    def login(self, value):
        assert (value.account, value.password) == ('override', ' synthetic password ')
        return identity(value)
    monkeypatch.setattr(auth.Authenticator, 'login', login)
    monkeypatch.setattr(client.ICourseClient, 'get_lectures', lambda self, course_id: [])
    assert main(['search', 'lectures', '--env']) == 0


def test_saved_source_ignores_implicit_env_and_never_prompts(explicit_env, saved_credentials, monkeypatch):
    saved_credentials.value = auth.Credentials('stored', 'saved-secret', 'keyring')
    def login(self, value):
        assert value.account == 'stored'
        return identity(value)
    monkeypatch.setattr(auth.Authenticator, 'login', login)
    monkeypatch.setattr(auth, 'prompt_credentials', lambda *_: pytest.fail('No prompt for search'))
    monkeypatch.setattr(client.ICourseClient, 'search_courses', lambda *args: [])
    assert main(['search', 'courses', '学习']) == 0
    assert saved_credentials.writes == 0


def test_missing_saved_credentials_do_not_fall_back_to_env(explicit_env, saved_credentials, monkeypatch):
    monkeypatch.setattr(auth.Authenticator, 'login', lambda *_: pytest.fail('Must not authenticate'))
    assert main(['search', 'courses', '学习']) == 6


def test_env_auth_failure_preserves_default_and_does_not_retry(explicit_env, saved_credentials, monkeypatch):
    original = auth.Credentials('stored', 'saved-secret', 'keyring')
    saved_credentials.value = original
    calls = []
    def reject(self, value):
        calls.append(value.account)
        raise AuthenticationError('Synthetic authentication refusal.')
    monkeypatch.setattr(auth.Authenticator, 'login', reject)
    assert main(['search', 'courses', '学习', '--env']) == 3
    assert calls == ['override']
    assert saved_credentials.value == original


def test_login_backend_failure_precedes_prompt(saved_credentials, monkeypatch):
    from icourse_dl.credentials import StorageFailure
    def unavailable():
        raise StorageFailure('Synthetic unavailable backend.')
    saved_credentials.check_writable = unavailable
    monkeypatch.setattr(auth, 'prompt_credentials', lambda *_: pytest.fail('Must check backend before input'))
    assert main(['login']) == 6


def test_login_refusal_never_overwrites_saved_password(explicit_env, saved_credentials, monkeypatch):
    original = auth.Credentials('override', 'old-secret', 'keyring')
    saved_credentials.value = original
    monkeypatch.setattr(auth.Authenticator, 'login', lambda *_: (_ for _ in ()).throw(AuthenticationError('Refused.')))
    assert main(['login', '--env']) == 3
    assert saved_credentials.value == original
    assert saved_credentials.writes == 0


def test_account_switch_cancel_does_not_authenticate_or_overwrite(explicit_env, saved_credentials, monkeypatch):
    original = auth.Credentials('other', 'old-secret', 'keyring')
    saved_credentials.value = original
    monkeypatch.setattr(interaction, 'choose', lambda *args, **kwargs: False)
    monkeypatch.setattr(auth.Authenticator, 'login', lambda *_: pytest.fail('Cancelled before login'))
    assert main(['login', '--env']) == 130
    assert saved_credentials.value == original


def test_login_saves_only_after_identity_success(explicit_env, saved_credentials, monkeypatch):
    events = []
    save = saved_credentials.save
    def authenticate(self, value):
        assert saved_credentials.checked
        assert saved_credentials.writes == 0
        events.append('verified')
        return identity(value)
    def record(value):
        assert events == ['verified']
        save(value)
    monkeypatch.setattr(auth.Authenticator, 'login', authenticate)
    saved_credentials.save = record
    assert main(['login', '--env']) == 0
    assert saved_credentials.value.account == 'override'


def test_clear_is_local_and_leaves_user_file(explicit_env, saved_credentials, monkeypatch):
    saved_credentials.value = auth.Credentials('stored', 'secret', 'keyring')
    contents = explicit_env.read_bytes()
    monkeypatch.setattr(auth.Authenticator, 'login', lambda *_: pytest.fail('No school request'))
    assert main(['login', '--clear']) == 0
    assert saved_credentials.value is None
    assert explicit_env.read_bytes() == contents


def test_noninteractive_download_requires_both_explicit_ids(explicit_env, monkeypatch):
    monkeypatch.setattr(interaction, 'terminal_available', lambda: False)
    monkeypatch.setattr(auth.Authenticator, 'login', lambda *_: pytest.fail('Fail before login'))
    for arguments in (['download', '学习'], ['download', '--course-id', '37323'], ['download', '--lecture-id', '7']):
        assert main(arguments + ['--env']) == 2


def test_three_stage_selection_downloads_chosen_class_and_lecture(explicit_env, monkeypatch):
    from icourse_dl import download
    newest = client.Course('30', '学习甲', 'A.01', '2026-20271', ('27',))
    older = client.Course('20', '学习乙', 'B.01', '2025-20261', ('24',))
    other_class = replace(older, course_id='21', course_code='B.02')
    lectures = [client.Lecture('21', '8', '课次甲', '教师', '2025-09-01', True),
                client.Lecture('21', '9', '课次乙', '教师', '2025-09-02', True)]
    monkeypatch.setattr(interaction, 'terminal_available', lambda: True)
    monkeypatch.setattr(auth.Authenticator, 'login', lambda self, value: identity(value))
    monkeypatch.setattr(client.ICourseClient, 'search_courses', lambda *args: [newest, older, other_class])
    def get_lectures(self, course_id):
        assert course_id == '21'
        return lectures
    monkeypatch.setattr(client.ICourseClient, 'get_lectures', get_lectures)
    selections = []
    def choose(title, options, **kwargs):
        selections.append(title)
        return options[-1][1]
    monkeypatch.setattr(interaction, 'choose', choose)
    def resolve(self, course_id, lecture_id):
        assert (course_id, lecture_id) == ('21', '9')
        return client.MediaSource(course_id, lecture_id, 'https://webvpn.fudan.edu.cn/synthetic.mp4')
    monkeypatch.setattr(client.ICourseClient, 'resolve_media', resolve)
    downloaded = []
    def transfer(source, lecture, session, options, **kwargs):
        downloaded.append((source.course_id, lecture.sub_id))
        return options.output / 'synthetic.mp4'
    monkeypatch.setattr(download, 'download_lecture', transfer)
    assert main(['download', '学习', '--env']) == 0
    assert selections == ['Select semester', 'Select course / teaching class', 'Select lecture']
    assert downloaded == [('21', '9')]


def test_search_lectures_outputs_lecture_ids_without_download(explicit_env, monkeypatch, capsys):
    monkeypatch.setattr(auth.Authenticator, 'login', lambda self, value: identity(value))
    monkeypatch.setattr(client.ICourseClient, 'get_lectures', lambda *_: [client.Lecture('37323', '456', '课次', '教师', '2026-09-01', True)])
    monkeypatch.setattr(client.ICourseClient, 'resolve_media', lambda *_: pytest.fail('Search must not resolve media'))
    assert main(['search', 'lectures', '--course-id', '37323', '--env']) == 0
    assert '1\t2026-09-01\t456\t课次\t教师\tTrue' in capsys.readouterr().out
