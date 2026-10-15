# SPDX-License-Identifier: GPL-3.0-or-later
import pytest
from test_auth import make_login_fixture, FakeResponse
from icourse_dl.auth import Authenticator, Credentials, IDP, WEBVPN, ICOURSE
from icourse_dl.errors import AuthenticationError


@pytest.mark.parametrize('sso', [False, True])
@pytest.mark.parametrize('destination', [WEBVPN + '/login', IDP + '/ac/', ICOURSE + '/casapi/index.php'])
def test_fresh_login_identity_rejection_does_not_replay_password(sso, destination):
    _, session = make_login_fixture(sso=sso)
    session.responses[-1:] = [
        FakeResponse(status=302, headers={'Location': destination + '?ticket=FAKE_PRIVATE_TICKET'}),
        FakeResponse(body=b'<html><input type="password"></html>'),
    ]
    with pytest.raises(AuthenticationError) as caught:
        Authenticator(session).login(Credentials('student-test', 'FAKE_PRIVATE_PASSWORD', 'env'))
    assert sum('/authExecute' in url for _, url, _ in session.calls) == (1 if sso else 2)
    assert not session.responses
    assert caught.value.exit_code == 3
    # Diagnostic privacy is part of the user-facing contract.
    assert 'FAKE_PRIVATE' not in str(caught.value)
    assert 'student-test' not in str(caught.value)
    assert 'https://' not in str(caught.value)


if __name__ == '__main__':
    for sso in (False, True):
        for destination in (WEBVPN + '/login', IDP + '/ac/', ICOURSE + '/casapi/index.php'):
            test_fresh_login_identity_rejection_does_not_replay_password(sso, destination)
    print('Fresh two-stage/SSO login rejection: no success, password replay or secret disclosure. PASS')
