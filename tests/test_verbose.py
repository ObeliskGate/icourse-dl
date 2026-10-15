# SPDX-License-Identifier: GPL-3.0-or-later
from functools import partial

import pytest
import requests

from icourse_dl import auth
from icourse_dl.cli import main
from test_auth import FakeResponse
from test_webvpn_entry import EntryCookieAdapter


@pytest.fixture
def command(monkeypatch, tmp_path):
    env = tmp_path / 'synthetic.env'
    env.write_text('StuId=student-test\nUISPsw=VERBOSE_PASSWORD_SECRET\n', encoding='utf-8')
    adapter = EntryCookieAdapter()
    adapter.responses.append(FakeResponse({'code': 0, 'data': {'total': '1', 'list': [{
        'id': '42', 'title': 'Synthetic course', 'course_code': 'TEST.01',
        'term': '_27_', 'term_name': '2026-20271',
    }]}}))
    session = requests.Session()
    session.mount('https://', adapter)
    monkeypatch.setattr(requests, 'Session', lambda: session)
    monkeypatch.setattr(auth, 'Authenticator', partial(auth.Authenticator, sleep=lambda _: None))
    yield ['search', 'courses', 'Synthetic', '--env', str(env)], adapter
    session.close()


def fail_requests(adapter, count):
    send = adapter.send
    remaining = count

    def intermittent(request, **kwargs):
        nonlocal remaining
        if remaining:
            remaining -= 1
            raise requests.ReadTimeout('https://SECRET_URL/?ticket=VERBOSE_TICKET_SECRET')
        return send(request, **kwargs)

    adapter.send = intermittent


def assert_no_secrets(output):
    for secret in ('VERBOSE_PASSWORD_SECRET', 'VERBOSE_TICKET_SECRET', 'SECRET_URL',
                   'synthetic-context', 'ST-test', 'synthetic-token'):
        assert secret not in output


def test_default_success_has_results_without_internal_auth_diagnostics(command, capsys):
    arguments, _ = command
    assert main(arguments) == 0
    captured = capsys.readouterr()
    assert '42\tSynthetic course' in captured.out
    assert captured.err == ''
    assert_no_secrets(captured.out + captured.err)


def test_default_retry_is_visible_without_internal_fields(command, capsys):
    arguments, adapter = command
    fail_requests(adapter, 1)
    assert main(arguments) == 0
    captured = capsys.readouterr()
    assert '42\tSynthetic course' in captured.out
    assert len(captured.err.splitlines()) == 1
    assert '2/3' in captured.err
    assert 'stage=' not in captured.err and 'method=' not in captured.err
    assert_no_secrets(captured.out + captured.err)


@pytest.mark.parametrize('position', [0, 1, 2, -1])
def test_verbose_at_each_command_level_exposes_safe_stage_and_retry(command, capsys, position):
    arguments, adapter = command
    fail_requests(adapter, 1)
    if position == -1:
        arguments.append('--verbose')
    else:
        arguments.insert(position, '--verbose')
    assert main(arguments) == 0
    captured = capsys.readouterr()
    assert '42\tSynthetic course' in captured.out
    assert 'stage=webvpn:login-context' in captured.err
    assert 'stage=icourse:password-submit' in captured.err
    assert 'initial=timeout' in captured.err and 'next-round=2' in captured.err
    assert_no_secrets(captured.out + captured.err)


@pytest.mark.parametrize('verbose', [False, True])
def test_exhausted_authentication_preserves_exit_code_and_output_privacy(command, capsys, verbose):
    arguments, adapter = command
    fail_requests(adapter, 3)
    if verbose:
        arguments.append('--verbose')
    assert main(arguments) == 7
    captured = capsys.readouterr()
    assert captured.out == ''
    assert ('stage=webvpn:login-context' in captured.err) is verbose
    if not verbose:
        assert '--verbose' in captured.err
        assert len(captured.err.splitlines()) == 3  # Two retries and one final error.
    assert_no_secrets(captured.err)
