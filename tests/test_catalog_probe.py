# SPDX-License-Identifier: GPL-3.0-or-later
import json
from pathlib import Path
import runpy
from urllib.parse import parse_qs, urlsplit

import pytest
from test_auth import FakeResponse, FakeSession
from icourse_dl.errors import PermissionDenied, ProtocolError

probe = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/inspect_course_catalog.py'))


def test_catalog_probe_outputs_types_not_values():
    session = FakeSession([FakeResponse({'code': 0, 'data': {
        'total': 123, 'list': [{'id': 'SECRET_ID', 'title': 'SECRET_TITLE',
                              'unverified_field': 'SECRET_CODE', 'teacher': 'SECRET_PERSON'}]
    }})])
    result = probe['inspect_catalog'](session, '24')
    assert result['catalog_has_rows'] is True
    assert result['data_schema']['list']['first_item']['unverified_field'] == 'string'
    assert 'SECRET' not in json.dumps(result)
    assert len(session.calls) == 1
    assert parse_qs(urlsplit(session.calls[0][1]).query) == {
        'tenant': ['222'], 'term': ['24'], 'page': ['1'], 'per_page': ['1']}
    assert not session.calls[0][2].get('json')


def test_catalog_rejection_does_not_extract_nested_values():
    session = FakeSession([FakeResponse({'code': 7001, 'data': {'list': [{'secret': 'SECRET'}]}})])
    with pytest.raises(PermissionDenied):
        probe['inspect_catalog'](session, '24')


def test_empty_catalog_is_not_field_evidence():
    session = FakeSession([FakeResponse({'code': 0, 'data': {'total': 0, 'list': []}})])
    assert probe['inspect_catalog'](session, '24')['catalog_has_rows'] is False


if __name__ == '__main__':
    test_catalog_probe_outputs_types_not_values()
    test_catalog_rejection_does_not_extract_nested_values()
    test_empty_catalog_is_not_field_evidence()
    print('Read-only catalog probe: one page, no raw field values, rejection handling PASS')
