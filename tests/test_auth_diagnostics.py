# SPDX-License-Identifier: GPL-3.0-or-later
from test_auth import FakeResponse, FakeSession
from icourse_dl.auth import Authenticator, Credentials, IDP, vpn_url
from icourse_dl.errors import ProtocolError


def test_redirect_diagnostic_does_not_disclose_secrets():
    session = FakeSession([FakeResponse(status=302, headers={
        'Location': 'https://FAKE_ACCOUNT:FAKE_SECRET@id.fudan.edu.cn/ac/#FAKE_FRAGMENT'
    })])
    try:
        Authenticator(session).login(Credentials('FAKE_ACCOUNT', 'FAKE_PASSWORD', 'prompt'))
    except ProtocolError as error:
        message = str(error)
        assert 'stage=webvpn:login-context' in message
        assert 'hop=1 status=302' in message
        assert 'embedded-userinfo' in message
        assert 'FAKE_' not in message
        assert 'https://' not in message
        print(message)
        return
    raise AssertionError('Unsafe redirect accepted')


def test_official_redirect_fragment_is_not_sent():
    for proxied in (False, True):
        target = IDP + '/ac/?lck=FAKE_CONTEXT&encoded=%23retained'
        redirect = vpn_url(target) if proxied else target
        session = FakeSession([
            FakeResponse(status=302, headers={'Location': redirect + '#/login?tab=password'}),
            FakeResponse(body=b'<html></html>'),
        ])
        context = Authenticator(session)._context(
            vpn_url(IDP + '/start') if proxied else IDP + '/start', proxied=proxied)
        assert context == 'FAKE_CONTEXT'
        assert session.calls[1][1] == redirect
        assert len(session.calls) == 2


def test_foreign_host_with_fragment_remains_rejected():
    session = FakeSession([FakeResponse(status=302, headers={
        'Location': 'https://evil.example/ac/#https://id.fudan.edu.cn/'
    })])
    try:
        Authenticator(session)._context(IDP + '/start', proxied=False)
    except ProtocolError:
        assert len(session.calls) == 1
        return
    raise AssertionError('Foreign redirect accepted')


def test_fragment_context():
    for proxied in (False, True):
        target = vpn_url(IDP + '/ac/') if proxied else IDP + '/ac/'
        session = FakeSession([
            FakeResponse(status=302, headers={'Location': target + '#/login?lck=FAKE%2BCONTEXT'}),
            FakeResponse(body=b'<html></html>'),
        ])
        assert Authenticator(session)._context(IDP + '/start', proxied=proxied) == 'FAKE+CONTEXT'
        assert session.calls[1][1] == target


if __name__ == '__main__':
    test_redirect_diagnostic_does_not_disclose_secrets()
    test_official_redirect_fragment_is_not_sent()
    test_foreign_host_with_fragment_remains_rejected()
    test_fragment_context()
    print('Direct/proxied fragment redirect smoke passed; foreign origin rejected.')
