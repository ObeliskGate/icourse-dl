# SPDX-License-Identifier: GPL-3.0-or-later
"""User-run, read-only catalog schema probe. Never prints field values or saves responses."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlencode

import requests
from icourse_dl.auth import Authenticator, ICOURSE, SafeHTTP, load_env_config, parse_json, prompt_credentials, vpn_url
from icourse_dl.errors import ICourseError, ProtocolError, PermissionDenied


def _schema(value, depth=0):
    if depth > 5:
        return 'depth-limit'
    if isinstance(value, dict):
        if len(value) > 128:
            raise ProtocolError('Catalog has too many fields to inspect safely.')
        return {key: _schema(item, depth + 1) for key, item in value.items()
                if isinstance(key, str) and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,63}', key)}
    if isinstance(value, list):
        return {'type': 'array', 'first_item': _schema(value[0], depth + 1) if value else None}
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, str):
        return 'string'
    if isinstance(value, (int, float)):
        return 'number'
    raise ProtocolError('Unsupported catalog field type.')


def inspect_catalog(session, term):
    params = urlencode({'tenant': '222', 'term': term, 'page': 1, 'per_page': 1})
    response = SafeHTTP(session).request('GET', vpn_url(ICOURSE + '/portal/courseapi/v3/multi-search/get-course-list?' + params), max_bytes=16 * 1024 * 1024, retry=True)
    if response.status_code in (401, 403):
        raise PermissionDenied('Catalog access denied.')
    if response.status_code != 200:
        raise ProtocolError('Catalog returned an unexpected HTTP status.')
    payload = parse_json(response)
    if type(payload.get('code')) is not int or payload['code'] != 0:
        raise PermissionDenied('Catalog business request was refused.')
    data = payload.get('data')
    if not isinstance(data, dict) or not isinstance(data.get('list'), list):
        raise ProtocolError('Catalog list structure is incompatible.')
    return {'catalog_has_rows': bool(data['list']), 'data_schema': _schema(data)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--term', required=True, help='Official term ID; upstream uses 24 as an example, not a verified current term.')
    parser.add_argument('--env', type=Path, nargs='?', const=Path('.env'), help='Read credentials from PATH; --env alone uses ./.env.')
    args = parser.parse_args(argv)
    if not re.fullmatch(r'[0-9]+', args.term) or int(args.term) <= 0:
        parser.error('--term must be a positive decimal ID')
    try:
        path = args.env
        credentials = load_env_config(path).credentials if path else prompt_credentials(None)
        with requests.Session() as session:
            session.trust_env = False
            print('Authenticating; then inspecting one catalog row. No field values will be printed.', file=sys.stderr, flush=True)
            Authenticator(session).login(credentials)
            print(json.dumps(inspect_catalog(session, args.term), ensure_ascii=True, separators=(',', ':')))
        return 0
    except ICourseError as error:
        print(str(error), file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f'Catalog inspection failed ({type(error).__name__}); details suppressed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
