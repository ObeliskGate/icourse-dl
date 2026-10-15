# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic school transport; requests still owns redirects' Cookie handling."""
from email.message import Message
import io
from types import SimpleNamespace
from urllib.parse import urlsplit

import requests
from urllib3.response import HTTPResponse

from icourse_dl.auth import Authenticator, Credentials, WEBVPN
from test_auth import FakeResponse, make_login_fixture


class EntryCookieAdapter(requests.adapters.BaseAdapter):
    """Require the service-issued cookie when consuming the WebVPN ticket."""

    def __init__(self):
        super().__init__()
        _, fixture = make_login_fixture()
        self.responses = fixture.responses
        self.responses[0].headers['Set-Cookie'] = (
            'vpn-entry=synthetic-context; Path=/; Secure; HttpOnly'
        )
        self.requests = []
        self.ticket_cookies = []

    def send(self, request, **kwargs):
        self.requests.append(request)
        parsed = urlsplit(request.url)
        if len(self.requests) == 1 and request.url != WEBVPN + '/login?cas_login=true':
            item = FakeResponse(status=403)
        elif parsed.hostname == 'webvpn.fudan.edu.cn' and parsed.path == '/login' and 'ticket=' in parsed.query:
            cookie = request.headers.get('Cookie', '')
            self.ticket_cookies.append(cookie)
            item = (self.responses.pop(0) if 'vpn-entry=synthetic-context' in cookie
                    else FakeResponse(status=403))
        else:
            assert self.responses, 'Unexpected school request'
            item = self.responses.pop(0)
        headers = Message()
        for key, value in item.headers.items():
            headers[key] = value
        response = requests.Response()
        response.status_code = item.status_code
        response.headers.update(item.headers)
        response.url = request.url
        response.request = request
        response.raw = HTTPResponse(
            body=io.BytesIO(item.body), headers=item.headers, preload_content=False,
            original_response=SimpleNamespace(msg=headers, close=lambda: None, isclosed=lambda: True),
        )
        return response

    def close(self):
        pass


def test_service_entry_cookie_survives_two_stage_authentication_without_idp_leak():
    adapter = EntryCookieAdapter()
    with requests.Session() as session:
        session.mount('https://', adapter)
        identity = Authenticator(session).login(Credentials('student-test', 'synthetic-password', 'prompt'))
        assert identity.account == 'student-test'
        assert adapter.ticket_cookies == ['vpn-entry=synthetic-context']
        assert not adapter.responses
        for request in adapter.requests:
            if urlsplit(request.url).hostname == 'id.fudan.edu.cn':
                assert 'vpn-entry' not in request.headers.get('Cookie', '')
        submissions = [request for request in adapter.requests if 'authExecute' in request.url]
        assert len(submissions) == 2
        cookie = next(cookie for cookie in session.cookies if cookie.name == 'vpn-entry')
        assert cookie.secure and not cookie.domain_specified and cookie.path == '/'
