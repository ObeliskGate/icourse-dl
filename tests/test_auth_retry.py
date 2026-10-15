# SPDX-License-Identifier: GPL-3.0-or-later
"""Consumer-visible authentication recovery; all traffic and clocks are fake."""
import logging

import pytest
import requests

from icourse_dl.auth import Authenticator, Credentials, IDP, WEBVPN
from icourse_dl.client import ICourseClient
from icourse_dl.errors import AuthenticationError, NetworkUnavailable, ProtocolError
from test_auth import FakeResponse, FakeSession, identity_response, make_login_fixture


CREDENTIALS = Credentials("student-test", "FAKE_PASSWORD", "prompt")


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, delay):
        self.sleeps.append(delay)
        self.now += delay


def authenticate(session, clock):
    return Authenticator(session, clock=clock, sleep=clock.sleep).login(CREDENTIALS)


@pytest.mark.parametrize("failure", [
    requests.ConnectTimeout("FAKE_TOKEN https://private/?password=FAKE_PASSWORD"),
    requests.ConnectionError("FAKE_COOKIE"),
    FakeResponse(status=503, body=b"FAKE_RESPONSE"),
])
def test_transient_entry_failure_starts_complete_new_round(failure):
    _, session = make_login_fixture(sso=True)
    session.responses.insert(0, failure)
    clock = FakeClock()
    assert authenticate(session, clock).account == CREDENTIALS.account
    assert clock.sleeps == [1]
    assert session.calls[0][1] == session.calls[1][1]
    assert sum("authExecute" in url for _, url, _ in session.calls) == 1
    assert not session.responses


def test_three_round_bound_preserves_safe_initial_cause(caplog):
    session = FakeSession([FakeResponse(status=503, body=b"FAKE_RESPONSE") for _ in range(3)])
    clock = FakeClock()
    caplog.set_level(logging.INFO, logger="icourse_dl.auth")
    with pytest.raises(NetworkUnavailable) as caught:
        authenticate(session, clock)
    assert len(session.calls) == 3
    assert clock.sleeps == [1, 2]
    assert caught.value.retryable and caught.value.status == 503
    assert caught.value.method == "GET"
    diagnostic = str(caught.value) + caplog.text
    assert "webvpn:login-context" in diagnostic
    assert "round=3" in diagnostic and "503" in diagnostic
    assert "FAKE_" not in diagnostic and CREDENTIALS.account not in diagnostic
    assert "https://" not in diagnostic
    assert not session.cookies


@pytest.mark.parametrize("step", [4, 5, 6])
def test_ambiguous_write_uses_three_read_attempts_without_replay(step, caplog):
    _, session = make_login_fixture(sso=True)
    session.responses[step] = requests.ReadTimeout("FAKE_PASSWORD")
    session.responses[step + 1:] = [requests.ReadTimeout("FAKE_COOKIE"),
                                    FakeResponse(status=503), identity_response()]
    clock = FakeClock()
    caplog.set_level(logging.INFO, logger="icourse_dl.auth")
    assert authenticate(session, clock).account == CREDENTIALS.account
    assert clock.sleeps == [1, 2]
    assert len(session.calls) == step + 4
    assert sum("authExecute" in url for _, url, _ in session.calls) == 1
    assert sum("infosimple" in url for _, url, _ in session.calls) == 3
    assert "verification=confirmed" in caplog.text
    assert "timeout" in caplog.text and "FAKE_" not in caplog.text


@pytest.mark.parametrize("probe", [
    FakeResponse({"code": 401}),
    FakeResponse(status=401),
    FakeResponse(body=b'<input type="password">'),
])
def test_uncertain_write_then_logged_out_reenters_with_new_context_and_ticket(probe):
    _, first = make_login_fixture(sso=True)
    _, second = make_login_fixture(sso=True)
    first.responses[6] = requests.ReadTimeout("FAKE_TICKET")
    second.responses[0] = FakeResponse(status=302, headers={"Location": IDP + "/ac/?lck=fresh-context"})
    second.responses[4] = FakeResponse({"code": 200, "loginToken": "fresh-token"})
    second.responses[5] = FakeResponse(body=(
        '<script>locationValue="' + WEBVPN + '/login?ticket=fresh-ticket";</script>'
    ).encode())
    session = FakeSession(first.responses[:7] + [probe] + second.responses)
    clock = FakeClock()
    assert authenticate(session, clock).account == CREDENTIALS.account
    assert clock.sleeps == [1]
    submissions = [kwargs["json"] for _, url, kwargs in session.calls if "authExecute" in url]
    assert [payload["lck"] for payload in submissions] == ["vpn-context", "fresh-context"]
    exchanges = [kwargs["data"] for _, url, kwargs in session.calls if "authnEngine" in url]
    assert [payload["loginToken"] for payload in exchanges] == ["synthetic-token", "fresh-token"]
    ticket_calls = [url for _, url, _ in session.calls if "ticket=" in url]
    assert len(ticket_calls) == len(set(ticket_calls)) == 2
    assert not session.responses


@pytest.mark.parametrize("probe,error", [
    (identity_response(account="FAKE_OTHER_ACCOUNT"), AuthenticationError),
    (FakeResponse(body=b"FAKE_MALFORMED_RESPONSE"), ProtocolError),
    (FakeResponse(status=404), ProtocolError),
    (requests.exceptions.SSLError("FAKE_TLS_SECRET"), NetworkUnavailable),
])
def test_uncertain_probe_nonretryable_result_stops_with_both_safe_causes(probe, error, caplog):
    _, session = make_login_fixture(sso=True)
    session.responses[4] = requests.ReadTimeout("FAKE_PASSWORD")
    session.responses[5:] = [probe]
    clock = FakeClock()
    with pytest.raises(error) as caught:
        authenticate(session, clock)
    assert len(session.calls) == 6
    assert not clock.sleeps
    diagnostic = str(caught.value) + caplog.text
    assert "webvpn:password-submit" in diagnostic and "identity-probe" in diagnostic
    assert "timeout" in diagnostic
    assert "FAKE_" not in diagnostic and "https://" not in diagnostic
    if isinstance(caught.value, NetworkUnavailable):
        assert not caught.value.retryable


@pytest.mark.parametrize("step", [0, 3, 4, 5, 6, 8])
def test_tls_failure_never_retries_or_attempts_uncertain_probe(step):
    _, session = make_login_fixture(sso=True)
    session.responses[step:] = [requests.exceptions.SSLError("FAKE_TLS_SECRET")]
    clock = FakeClock()
    with pytest.raises(NetworkUnavailable) as caught:
        authenticate(session, clock)
    assert len(session.calls) == step + 1
    assert not clock.sleeps
    assert not caught.value.retryable
    assert caught.value.reason == "tls-verification"
    assert "stage=" in str(caught.value) and "FAKE_" not in str(caught.value)


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
def test_permanent_http_failure_never_restarts(status):
    session = FakeSession([FakeResponse(status=status)])
    clock = FakeClock()
    with pytest.raises((AuthenticationError, ProtocolError)):
        authenticate(session, clock)
    assert len(session.calls) == 1 and not clock.sleeps


@pytest.mark.parametrize("replacement,step,error", [
    (FakeResponse({"code": 401, "message": "FAKE_PASSWORD"}), 4, AuthenticationError),
    (FakeResponse({"data": [{"moduleCode": "otp"}]}), 2, AuthenticationError),
    (FakeResponse({"code": 200}), 4, ProtocolError),
    (identity_response(account="FAKE_OTHER_ACCOUNT"), 8, AuthenticationError),
])
def test_explicit_rejection_mfa_malformed_or_mismatch_never_restarts(replacement, step, error):
    _, session = make_login_fixture(sso=True)
    session.responses[step:] = [replacement]
    clock = FakeClock()
    with pytest.raises(error):
        authenticate(session, clock)
    assert len(session.calls) == step + 1 and not clock.sleeps


def test_reset_discards_incomplete_cookies_but_preserves_original_session_for_client(monkeypatch):
    _, session = make_login_fixture(sso=True)
    session.responses.insert(0, requests.ConnectTimeout("FAKE_COOKIE"))
    session.responses.append(FakeResponse({"code": 0, "data": {
        "id": "12", "title": "Synthetic course", "course_code": "TEST",
        "term_name": "Synthetic term", "term": "_1_",
    }}))
    session.cookies.set("prior", "FAKE_PRIOR_COOKIE")
    cookie_snapshots = []
    original_request = session.request

    def request(method, url, **kwargs):
        cookie_snapshots.append(dict(session.cookies))
        try:
            response = original_request(method, url, **kwargs)
        except requests.ConnectTimeout:
            session.cookies.set("incomplete", "FAKE_INCOMPLETE_COOKIE")
            raise
        if "infosimple" in url:
            session.cookies.set("authenticated", "FAKE_AUTH_COOKIE")
        return response

    monkeypatch.setattr(session, "request", request)
    clock = FakeClock()
    identity = authenticate(session, clock)
    client = ICourseClient(session, identity)
    assert client.get_course("12").course_id == "12"
    assert cookie_snapshots[0] == cookie_snapshots[1] == {}
    assert cookie_snapshots[-1] == {"authenticated": "FAKE_AUTH_COOKIE"}
    assert not session.responses


def test_authentication_budget_caps_remaining_request_time_and_prevents_nested_rounds(monkeypatch):
    session = FakeSession([requests.ConnectTimeout("FAKE_SECRET") for _ in range(3)])
    clock = FakeClock()
    original_request = session.request

    def request(method, url, **kwargs):
        # The first failed operation consumes almost all of the shared budget.
        clock.now += 295 if not session.calls else 4
        return original_request(method, url, **kwargs)

    monkeypatch.setattr(session, "request", request)
    with pytest.raises(NetworkUnavailable) as caught:
        authenticate(session, clock)
    assert len(session.calls) == 2
    assert clock.sleeps == [1]
    assert sum(session.calls[1][2]["timeout"]) <= 4
    assert caught.value.reason == "authentication-budget"
    assert "webvpn:login-context" in str(caught.value)


def test_authentication_budget_is_shared_with_uncertain_read_retries(monkeypatch):
    _, session = make_login_fixture(sso=True)
    session.responses[4] = requests.ReadTimeout("FAKE_PASSWORD")
    session.responses[5:] = [requests.ReadTimeout("FAKE_COOKIE")]
    clock = FakeClock()
    original_request = session.request

    def request(method, url, **kwargs):
        if "authExecute" in url:
            clock.now = 299.5
        return original_request(method, url, **kwargs)

    monkeypatch.setattr(session, "request", request)
    with pytest.raises(NetworkUnavailable) as caught:
        authenticate(session, clock)
    assert len(session.calls) == 6
    assert not clock.sleeps
    assert sum(session.calls[-1][2]["timeout"]) <= 0.5
    assert caught.value.reason == "authentication-budget"
    assert "webvpn:password-submit" in str(caught.value)
    assert "identity-probe" in str(caught.value)


def test_exhausted_uncertain_read_budget_restarts_complete_authentication():
    _, first = make_login_fixture(sso=True)
    _, second = make_login_fixture(sso=True)
    first.responses[4] = requests.ReadTimeout("FAKE_PASSWORD")
    session = FakeSession(first.responses[:5] +
                          [FakeResponse(status=503) for _ in range(3)] +
                          second.responses)
    clock = FakeClock()
    assert authenticate(session, clock).account == CREDENTIALS.account
    assert clock.sleeps == [1, 2, 1]
    assert sum("infosimple" in url for _, url, _ in session.calls) == 4
    assert not session.responses


def test_final_uncertain_failure_keeps_initial_and_verification_statuses(caplog):
    _, fixture = make_login_fixture(sso=True)
    fixture.responses[4] = FakeResponse(status=502, body=b"FAKE_TOKEN")
    round_responses = fixture.responses[:5] + [FakeResponse(status=503) for _ in range(3)]
    session = FakeSession(round_responses * 3)
    clock = FakeClock()
    with pytest.raises(NetworkUnavailable) as caught:
        authenticate(session, clock)
    assert len(session.calls) == 24
    assert clock.sleeps == [1, 2, 1, 1, 2, 2, 1, 2]
    diagnostic = str(caught.value) + caplog.text
    assert "webvpn:password-submit" in diagnostic and "identity-probe" in diagnostic
    assert "502" in str(caught.value) and "503" in str(caught.value)
    assert "POST" in str(caught.value) and "GET" in str(caught.value)
    assert "FAKE_" not in diagnostic and "https://" not in diagnostic
