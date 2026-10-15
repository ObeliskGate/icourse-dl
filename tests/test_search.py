# SPDX-License-Identifier: GPL-3.0-or-later
from unittest.mock import patch

import pytest

from icourse_dl import auth
from icourse_dl.cli import main
from icourse_dl.errors import ConfigurationError, ProtocolError, PermissionDenied
from test_client import make_client


def row(identifier, term='27'):
    return {'id': str(identifier), 'title': '高级大数据解析',
            'course_code': '2026-20271CS50021.01', 'term': f'_{term}_',
            'term_name': '2026-20271'}


def page(total, rows):
    return {'code': 0, 'data': {'total': str(total), 'list': rows}}


def test_pagination_short_pages_and_overlap():
    client = make_client([page(3, [row(1), row(2)]), page(3, [row(2), row(3)])])
    assert [course.course_id for course in client.search_courses('学习', '27')] == ['1', '2', '3']


@pytest.mark.parametrize('responses', [
    [page(2, [row(1)]), page(2, [])],
    [page(2, [row(1)]), page(2, [row(1)])],
    [page(2, [row(1)]), page(3, [row(2)])],
    [page(1, [row(1), row(2)])],
    [page(1, [row(1, '24')])],
    [page(1, [{'id': '1'}])],
    [{'code': 0, 'data': {'total': True, 'list': []}}],
])
def test_inconsistent_catalog_never_returns_partial_results(responses):
    with pytest.raises(ProtocolError):
        make_client(responses).search_courses('学习', '27')


def test_empty_results():
    assert make_client([page(0, [])]).search_courses('不存在', '27') == []


def test_business_denial():
    with pytest.raises(PermissionDenied):
        make_client([{'code': 7001, 'data': {'list': [row(1)]}}]).search_courses('学习', '27')


@pytest.mark.parametrize('name,term', [('', '27'), ('  ', '27'), ('学习', '0'), ('学习', '2026-20271')])
def test_invalid_search_input(name, term):
    with pytest.raises(ConfigurationError):
        make_client([]).search_courses(name, term)


@pytest.mark.parametrize('arguments', [
    ['search', 'courses'], ['search', 'lectures', '--term', '27'],
    ['search', 'courses', '学习', '--term', '0'], ['search', 'courses', '学习', '--list'],
])
def test_invalid_command_before_credentials(arguments, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch.object(auth, 'prompt_credentials', side_effect=AssertionError('Unexpected prompt')):
        try:
            code = main(arguments)
        except SystemExit as error:
            code = error.code
        assert code == 2


@pytest.mark.parametrize('prefix,suffix', [(['--env'], []), ([], ['--env']), (['--env', './chosen.env'], [])])
def test_global_env_search_outputs_courses_not_lectures(prefix, suffix, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    for name in ('.env', 'chosen.env'):
        (tmp_path / name).write_text('StuId=synthetic\nUISPsw=synthetic\n', encoding='utf-8')
    from icourse_dl.client import ICourseClient
    identity = auth.Identity('synthetic', '1', '222', '')
    with patch.object(auth.Authenticator, 'login', return_value=identity), patch.object(ICourseClient, '_get', return_value=page(1, [row(37323)])), patch.object(ICourseClient, 'get_lectures', side_effect=AssertionError('Search must not select lectures')):
        assert main(prefix + ['search', 'courses', '高级大数据解析', '--term', '27'] + suffix) == 0
    output = capsys.readouterr().out
    assert '37323\t高级大数据解析\t2026-20271CS50021.01\t2026-2027 学年第一学期\t27' in output


def test_cross_semester_search_preserves_all_classes_and_omits_term_filter():
    from urllib.parse import parse_qs, urlsplit
    client = make_client([page(3, [row(1), row(2), row(3, '24')])])
    courses = client.search_courses('学习')
    assert [(course.course_id, course.term_ids) for course in courses] == [
        ('1', ('27',)), ('2', ('27',)), ('3', ('24',))]
    assert 'term' not in parse_qs(urlsplit(client.http.calls[0][1]).query)


def test_multi_semester_membership_does_not_merge_courses():
    first = row(1)
    first['term'] = '_24_27_'
    courses = make_client([page(2, [first, row(2)])]).search_courses('学习')
    assert courses[0].term_ids == ('24', '27')
    assert courses[1].course_id == '2'
