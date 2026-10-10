# SPDX-License-Identifier: GPL-3.0-or-later
"""All protocol responses and credentials below are synthetic; no school I/O."""
import base64
import getpass
import io
import json
import os
from pathlib import Path
from unittest.mock import patch

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import pytest
import requests

from icourse_dl.auth import (
    AUTH_LIMIT, ICOURSE, IDP, WEBVPN, Authenticator, Credentials,
    Identity, SafeHTTP, load_env_config, prompt_credentials,
    validate_official_url, vpn_url,
)
from icourse_dl.errors import AuthenticationError, ConfigurationError, NetworkUnavailable, ProtocolError


class FakeResponse:
    def __init__(self, payload=None, *, status=200, headers=None, body=None):
        self.status_code = status
        self.headers = headers or {}
        self.body = body if body is not None else json.dumps(payload).encode()
        self.closed = False

    def iter_content(self, chunk_size):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start:start + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}
        self.trust_env = True
        self.auth = ("unwanted", "credentials")
        self.cookies = requests.cookies.RequestsCookieJar()

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        assert kwargs["allow_redirects"] is False
        assert kwargs["stream"] is True
        assert kwargs["verify"] is True
        assert kwargs["timeout"] == (10, 30)
        assert self.responses, "Unexpected extra request"
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def identity_response(**changes):
    record = {"account": "student-test", "id": 7, "tenant_id": 222, "phone": "13800000000"}
    record.update(changes)
    return FakeResponse({"code": 0, "params": record})


def stage_responses(key, *, course=False):
    target = ICOURSE + "/casapi/index.php?r=auth/login" if course else WEBVPN + "/login?cas_login=true"
    return [
        FakeResponse({"data": [{"moduleCode": "userAndPwd", "authChainCode": "chain-test"}]}),
        FakeResponse({"data": base64.b64encode(key.public_key().export_key(format="DER")).decode()}),
        FakeResponse({"code": "200", "loginToken": "synthetic-token"}),
        FakeResponse(body=(f'<script>var locationValue = "{target}&amp;ticket=ST-test";</script>').encode()),
        FakeResponse(body=b"<html>OK</html>"),
    ]


def make_login_fixture(*, sso=False):
    """Also usable by a standalone smoke runner with actual Authenticator/RSA."""
    key = RSA.generate(1024)
    responses = [FakeResponse(status=302, headers={"Location": IDP + "/ac/?lck=vpn-context"}),
                 FakeResponse(body=b"<html>Login</html>"), *stage_responses(key)]
    if sso:
        responses.append(FakeResponse(body=b"<html>Course</html>"))
    else:
        responses.extend([
            FakeResponse(status=302, headers={"Location": IDP + "/ac/?lck=course-context"}),
            FakeResponse(body=b"<html>Login</html>"), *stage_responses(key, course=True),
        ])
    responses.append(identity_response())
    return key, FakeSession(responses)


def test_complete_two_stage_login_and_rsa():
    key, session = make_login_fixture()
    credentials = Credentials("student-test", " 空 格 ! ", "env")
    result = Authenticator(session).login(credentials)
    assert result == Identity("student-test", "7", "222", "13800000000")
    assert not session.responses
    assert session.trust_env is False and session.auth is None
    executions = [call for call in session.calls if "/authExecute" in call[1]]
    assert len(executions) == 2
    for index, (_, url, kwargs) in enumerate(executions):
        payload = kwargs["json"]
        assert payload["entityId"] == (WEBVPN if index == 0 else ICOURSE)
        assert payload["lck"] == ("vpn-context" if index == 0 else "course-context")
        assert payload["authPara"]["loginName"] == "student-test"
        ciphertext = base64.b64decode(payload["authPara"]["password"])
        assert PKCS1_v1_5.new(key).decrypt(ciphertext, None).decode() == credentials.password
        assert kwargs["headers"]["Origin"] == (IDP if index == 0 else WEBVPN)
        assert url.startswith(IDP if index == 0 else WEBVPN)


def test_valid_sso_avoids_second_password_submission():
    _, session = make_login_fixture(sso=True)
    assert Authenticator(session).login(Credentials("student-test", "pw", "prompt")).account == "student-test"
    assert sum("authExecute" in url for _, url, _ in session.calls) == 1


def test_env_bom_unicode_password_spaces_no_interpolation(tmp_path, monkeypatch):
    path = tmp_path / "中文.env"
    contents = '\ufeffStuId=" student-test "\nUISPsw=" 空 格 ${SECRET} "\nCOURSE_ID=00123\n'
    path.write_text(contents, encoding="utf-8")
    monkeypatch.setenv("SECRET", "DO-NOT-USE")
    before = dict(os.environ)
    before_bytes = path.read_bytes()
    config = load_env_config(path)
    assert config.credentials == Credentials("student-test", " 空 格 ${SECRET} ", "env")
    assert config.course_id_text == "00123"
    assert path.read_bytes() == before_bytes and dict(os.environ) == before
    assert "空 格" not in repr(config)


@pytest.mark.parametrize("contents", ["StuId=x", "UISPsw=x", "StuId=\nUISPsw=x", "StuId=x\nUISPsw=", "StuId='x\nUISPsw=secret", "StuId=x\nUISPsw=y\ninvalid line here"])
def test_invalid_env_fails_without_secret_output(tmp_path, contents, caplog, capsys):
    path = tmp_path / "own.env"
    path.write_text(contents)
    with pytest.raises(ConfigurationError):
        load_env_config(path)
    assert not caplog.text
    assert capsys.readouterr() == ("", "")


def test_env_does_not_fill_missing_password_from_process(tmp_path, monkeypatch):
    monkeypatch.setenv("UISPsw", "not-authorized")
    path = tmp_path / "own.env"
    path.write_text("StuId=x")
    with pytest.raises(ConfigurationError):
        load_env_config(path)


def test_whitespace_password_is_not_empty(tmp_path):
    path = tmp_path / "own.env"
    path.write_text('StuId=x\nUISPsw="   "')
    assert load_env_config(path).credentials.password == "   "


@pytest.mark.parametrize("kind", ["missing", "directory", "encoding"])
def test_unreadable_config(tmp_path, kind):
    path = tmp_path / "credentials"
    if kind == "directory":
        path.mkdir()
    elif kind == "encoding":
        path.write_bytes(b"\xff")
    with pytest.raises(ConfigurationError):
        load_env_config(path)


def test_nonterminal_never_prompts(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO())
    with patch("getpass.getpass") as hidden:
        with pytest.raises(ConfigurationError):
            prompt_credentials(None)
    hidden.assert_not_called()


def test_prompt_cannot_fall_back_to_echo(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stderr.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "student-test")
    def no_hidden(_):
        import warnings
        warnings.warn("no hidden input", getpass.GetPassWarning)
        pytest.fail("must not fall through to echoed input")
    monkeypatch.setattr("getpass.getpass", no_hidden)
    with pytest.raises(ConfigurationError):
        prompt_credentials("student-test")


def test_prompt_requires_complete_selected_account(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stderr.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "other")
    with patch("getpass.getpass") as hidden:
        with pytest.raises(ConfigurationError):
            prompt_credentials("student-test")
    hidden.assert_not_called()


def test_vpn_url_roundtrip_and_port():
    ordinary = ICOURSE + "/courseapi/test?x=a%20b"
    encoded = vpn_url(ordinary)
    assert encoded.startswith(WEBVPN + "/https/77726476706e69737468656265737421")
    assert validate_official_url(encoded) == ordinary
    assert vpn_url(encoded) == encoded
    assert "/http-8080/" in vpn_url("http://media.internal:8080/a.mp4?x=1")


@pytest.mark.parametrize("url", ["http://id.fudan.edu.cn/a", "https://id.fudan.edu.cn.evil/a", "https://user@id.fudan.edu.cn/a", "https://id.fudan.edu.cn:444/a", "https://id.fudan.edu.cn/a#x", "https://id.fudan.edu.cn/\\evil", "https://id.fudan.edu.cn/\nfoo", vpn_url("https://evil.example/a"), vpn_url("http://id.fudan.edu.cn/a")])
def test_unsafe_redirect_is_never_requested(url):
    session = FakeSession([FakeResponse(status=302, headers={"Location": url})])
    with pytest.raises(ProtocolError):
        SafeHTTP(session).request("GET", IDP + "/start")
    assert len(session.calls) == 1


def test_relative_redirect_and_limit():
    session = FakeSession([FakeResponse(status=302, headers={"Location": "/next"}), FakeResponse({"ok": True})])
    result = SafeHTTP(session).request("GET", IDP + "/start")
    assert result.url == IDP + "/next" and result.history == (IDP + "/start",)
    session = FakeSession([FakeResponse(status=302, headers={"Location": "/loop"}) for _ in range(11)])
    with pytest.raises(ProtocolError):
        SafeHTTP(session).request("GET", IDP + "/start")
    assert len(session.calls) == 11


@pytest.mark.parametrize("status", [307, 308])
def test_post_body_not_forwarded(status):
    session = FakeSession([FakeResponse(status=status, headers={"Location": ICOURSE + "/collect"})])
    with pytest.raises(ProtocolError):
        SafeHTTP(session).request("POST", IDP + "/auth", json={"password": "synthetic-secret"})
    assert len(session.calls) == 1


def test_get_retries_and_retry_after_limit():
    sleeps = []
    session = FakeSession([requests.ConnectTimeout("synthetic-secret"), FakeResponse(status=503), identity_response()])
    assert SafeHTTP(session, sleep=sleeps.append).request("GET", IDP + "/readonly", retry=True).status_code == 200
    assert sleeps == [1, 2]
    session = FakeSession([FakeResponse(status=429, headers={"Retry-After": "31"})])
    with pytest.raises(NetworkUnavailable):
        SafeHTTP(session, sleep=sleeps.append).request("GET", IDP + "/readonly", retry=True)
    assert len(session.calls) == 1


def test_retry_after_respected():
    sleeps = []
    session = FakeSession([FakeResponse(status=429, headers={"Retry-After": "3"}), identity_response()])
    SafeHTTP(session, sleep=sleeps.append).request("GET", IDP + "/readonly", retry=True)
    assert sleeps == [3]


def test_post_never_retries_and_errors_are_sanitized():
    session = FakeSession([requests.ReadTimeout("https://SECRET/?password=SECRET")])
    with pytest.raises(NetworkUnavailable) as caught:
        SafeHTTP(session).request("POST", IDP + "/auth", data={"secret": "value"})
    assert "SECRET" not in str(caught.value) and len(session.calls) == 1


def test_bounded_body_and_closed_response():
    response = FakeResponse(body=b"x" * (AUTH_LIMIT + 1))
    session = FakeSession([response])
    with pytest.raises(ProtocolError):
        SafeHTTP(session).request("GET", IDP + "/large")
    assert response.closed


@pytest.mark.parametrize("payload,error", [
    ({"code": 0, "data": {}}, ProtocolError),
    ({"code": 0, "data": {"id": 1, "tenant_id": 222, "username": "student-test"}}, ProtocolError),
    ({"code": 0, "data": {"id": True, "tenant_id": 222, "account": "student-test"}}, ProtocolError),
    ({"code": 0, "params": {"account": "student-test"}, "data": {"account": "other"}}, ProtocolError),
    ({"code": 0, "data": {"id": 1, "tenant_id": 222, "account": "other"}}, AuthenticationError),
    ({"code": 401}, AuthenticationError), ({"code": 7001}, ProtocolError),
    ({"code": False, "data": {"account": "student-test", "id": 1, "tenant_id": 222}}, ProtocolError),
])
def test_identity_strict_contract(payload, error):
    with pytest.raises(error):
        Authenticator(FakeSession([FakeResponse(payload)])).probe_identity("student-test")


def test_identity_params_fallback_and_redacted_phone():
    payload = {"code": 200, "params": {}, "data": {"account": "student-test", "id": "7", "tenant_id": 222}}
    identity = Authenticator(FakeSession([FakeResponse(payload)])).probe_identity("student-test")
    assert identity.phone == ""
    assert "13800000000" not in repr(Identity("a", "b", "c", "13800000000"))


@pytest.mark.parametrize("body,error", [(b'<input type="password">', AuthenticationError), (b"<html>not JSON</html>", ProtocolError), (b"[]", ProtocolError)])
def test_html_cannot_establish_identity(body, error):
    with pytest.raises(error):
        Authenticator(FakeSession([FakeResponse(body=body)])).probe_identity("student-test")


def test_timeout_after_password_does_not_replay_and_confirms_once():
    _, session = make_login_fixture()
    session.responses[4] = requests.ReadTimeout("SECRET")
    session.responses[5:] = [identity_response()]
    result = Authenticator(session).login(Credentials("student-test", "pw", "env"))
    assert result.account == "student-test"
    assert len([call for call in session.calls if "authExecute" in call[1]]) == 1
    assert len([call for call in session.calls if "infosimple" in call[1]]) == 1


def test_timeout_confirmation_failure_remains_network_error():
    _, session = make_login_fixture()
    session.responses[4] = requests.ReadTimeout("SECRET")
    session.responses[5:] = [FakeResponse({"code": 401})]
    with pytest.raises(NetworkUnavailable):
        Authenticator(session).login(Credentials("student-test", "pw", "env"))
    assert len(session.calls) == 6


@pytest.mark.parametrize("replacement,error", [
    (FakeResponse({"code": 500, "loginToken": "not-valid"}), AuthenticationError),
    (FakeResponse({"code": 200, "data": {"loginToken": "wrong-level"}}), ProtocolError),
    (FakeResponse(body=b"<html>error</html>"), ProtocolError),
])
def test_execute_response_must_succeed_explicitly(replacement, error):
    _, session = make_login_fixture()
    session.responses[4] = replacement
    with pytest.raises(error):
        Authenticator(session).login(Credentials("student-test", "pw", "env"))
    assert len(session.calls) == 5


def test_unrelated_ticket_link_is_not_followed():
    _, session = make_login_fixture()
    session.responses[5] = FakeResponse(body=b'<a href="https://webvpn.fudan.edu.cn/login?ticket=ST-test">not an approved script</a>')
    with pytest.raises(ProtocolError):
        Authenticator(session).login(Credentials("student-test", "pw", "env"))
    assert len(session.calls) == 6


def test_ticket_wrong_official_destination_is_not_followed():
    _, session = make_login_fixture()
    session.responses[5] = FakeResponse(body=b'<script>locationValue="https://id.fudan.edu.cn/collect?ticket=ST-test";</script>')
    with pytest.raises(ProtocolError):
        Authenticator(session).login(Credentials("student-test", "pw", "env"))
    assert len(session.calls) == 6


def test_unsupported_authentication_method_stops():
    _, session = make_login_fixture()
    session.responses[2] = FakeResponse({"data": [{"moduleCode": "otp"}]})
    with pytest.raises(AuthenticationError):
        Authenticator(session).login(Credentials("student-test", "pw", "env"))
    assert len(session.calls) == 3


def test_http_permission_status_remains_available_to_client():
    response = SafeHTTP(FakeSession([FakeResponse(status=403)])).request("GET", vpn_url(ICOURSE + "/courseapi/example"))
    assert response.status_code == 403


@pytest.mark.parametrize("step", [5, 6])
def test_engine_and_ticket_timeout_never_replays(step):
    _, session = make_login_fixture()
    session.responses[step] = requests.ReadTimeout("synthetic-secret")
    session.responses[step + 1:] = [FakeResponse({"code": 401})]
    with pytest.raises(NetworkUnavailable):
        Authenticator(session).login(Credentials("student-test", "pw", "env"))
    assert len(session.calls) == step + 2
    assert sum("infosimple" in url for _, url, _ in session.calls) == 1


def test_ticket_redirect_never_gets_read_only_retry_budget():
    session = FakeSession([
        FakeResponse(status=302, headers={"Location": WEBVPN + "/login?ticket=ST-test"}),
        requests.ReadTimeout("synthetic-secret"),
    ])
    with pytest.raises(NetworkUnavailable):
        SafeHTTP(session, sleep=lambda _: pytest.fail("must not retry ticket")).request("GET", IDP + "/readonly", retry=True)
    assert len(session.calls) == 2


def test_engine_location_header_supported():
    _, session = make_login_fixture(sso=True)
    session.responses[5] = FakeResponse(status=302, headers={"Location": WEBVPN + "/login?cas_login=true&ticket=ST-test"})
    assert Authenticator(session).login(Credentials("student-test", "pw", "env")).account == "student-test"


def test_proxied_literal_login_context():
    _, session = make_login_fixture()
    session.responses[7:9] = [FakeResponse(body=b'<script>var lck = "course-context";</script>')]
    assert Authenticator(session).login(Credentials("student-test", "pw", "env")).account == "student-test"
    assert sum("authExecute" in url for _, url, _ in session.calls) == 2


def test_script_expression_is_not_treated_as_literal_ticket():
    _, session = make_login_fixture()
    session.responses[5] = FakeResponse(body=b'<script>locationValue="https://webvpn.fudan.edu.cn/login?ticket=ST-test" + untrusted;</script>')
    with pytest.raises(ProtocolError):
        Authenticator(session).login(Credentials("student-test", "pw", "env"))
    assert len(session.calls) == 6


@pytest.mark.parametrize("url", [
    WEBVPN + "/%68ttps/77726476706e69737468656265737421aa/",
    vpn_url(ICOURSE + "/%2e%2e/%2e%2e/https/unknown"),
    WEBVPN + "/https/not-a-valid-host/",
])
def test_noncanonical_proxy_target_rejected(url):
    with pytest.raises(ProtocolError):
        validate_official_url(url)


def test_same_endpoint_307_does_not_replay_password():
    session = FakeSession([FakeResponse(status=307, headers={"Location": IDP + "/auth"})])
    with pytest.raises(ProtocolError):
        SafeHTTP(session).request("POST", IDP + "/auth", json={"password": "synthetic"})
    assert len(session.calls) == 1

