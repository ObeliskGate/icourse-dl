# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit credentials and the two-stage Fudan IDP/WebVPN protocol.

All messages are deliberately independent of response bodies and secret URLs.
SafeHTTP is shared by authentication and the read-only course API client.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import getpass
from html import unescape
from html.parser import HTMLParser
import io
import json
import logging
from pathlib import Path
import re
import sys
import time
from typing import Callable, Literal
from urllib.parse import parse_qs, quote, unquote, urljoin, urlsplit, urlunsplit
import warnings

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from dotenv import dotenv_values
import requests

from .errors import AuthenticationError, ConfigurationError, NetworkUnavailable, ProtocolError

WEBVPN = "https://webvpn.fudan.edu.cn"
IDP = "https://id.fudan.edu.cn"
ICOURSE = "https://icourse.fudan.edu.cn"
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/120.0.0.0 Safari/537.36")
AUTH_LIMIT = 1024 * 1024
BUSINESS_LIMIT = 16 * 1024 * 1024
_VPN_KEY = b"wrdvpnisthebest!"
_HOSTS = {"webvpn.fudan.edu.cn", "id.fudan.edu.cn", "icourse.fudan.edu.cn"}
_REDIRECTS = {301, 302, 303, 307, 308}
_TRANSIENT = {408, 429, 500, 502, 503, 504}


@dataclass(frozen=True)
class Credentials:
    account: str
    password: str = field(repr=False)
    source: Literal["env", "keyring", "prompt"]


@dataclass(frozen=True)
class Identity:
    account: str
    user_id: str
    tenant_id: str
    phone: str = field(repr=False)


@dataclass(frozen=True)
class ExplicitConfig:
    credentials: Credentials
    course_id_text: str | None


class _InvalidEnvFilter(logging.Filter):
    invalid = False

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.WARNING:
            self.invalid = True
            return False
        return True


def load_env_config(path: Path) -> ExplicitConfig:
    """Read only the explicitly named file, without environment interpolation."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError, ValueError):
        raise ConfigurationError("Cannot read the explicit UTF-8 credentials file.") from None
    logger = logging.getLogger("dotenv.main")
    capture = _InvalidEnvFilter()
    logger.addFilter(capture)
    try:
        values = dotenv_values(stream=io.StringIO(text), interpolate=False)
    finally:
        logger.removeFilter(capture)
    if capture.invalid:
        raise ConfigurationError("The explicit credentials file contains invalid syntax.")
    account, password = values.get("StuId"), values.get("UISPsw")
    if not isinstance(account, str) or not account.strip() or not isinstance(password, str) or password == "":
        raise ConfigurationError("The explicit file must contain both StuId and UISPsw.")
    return ExplicitConfig(Credentials(account.strip(), password, "env"), values.get("COURSE_ID"))


def prompt_credentials(expected_account: str | None = None) -> Credentials:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ConfigurationError("Credentials require a terminal or an explicit credentials file.")
    try:
        account = input("StuId: ").strip()
        if not account or (expected_account is not None and account != expected_account):
            raise ConfigurationError("Enter the complete credentials for the selected account.")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("UISPsw: ")
    except (getpass.GetPassWarning, EOFError, OSError):
        raise ConfigurationError("Hidden password input is unavailable.") from None
    if password == "":
        raise ConfigurationError("The password must not be empty.")
    return Credentials(account, password, "prompt")


def _url_parts(url: str):
    if not isinstance(url, str) or not url or any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in url:
        raise ProtocolError("Invalid URL in the server protocol.")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise ProtocolError("Invalid URL in the server protocol.") from None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ProtocolError("Invalid URL in the server protocol.")
    return parsed, port


def _redirect_url(base: str, location: str) -> str:
    # urljoin silently removes some controls: reject before normalization.
    if not location or any(ord(c) <= 32 or ord(c) == 127 for c in location) or "\\" in location:
        raise ProtocolError("The server returned an invalid redirect destination.")
    result = urljoin(base, location)
    validate_official_url(result)
    return result


def vpn_url(url: str) -> str:
    """Encode an already authorized origin URL; media hosts are not allowlisted here."""
    parsed, port = _url_parts(url)
    if parsed.hostname == "webvpn.fudan.edu.cn":
        if parsed.scheme != "https" or port not in (None, 443):
            raise ProtocolError("Invalid WebVPN origin.")
        return url
    host = parsed.hostname.encode("idna")
    encrypted = AES.new(_VPN_KEY, AES.MODE_CFB, iv=_VPN_KEY, segment_size=128).encrypt(host)
    suffix = "" if port is None or port == (443 if parsed.scheme == "https" else 80) else f"-{port}"
    path = f"/{parsed.scheme}{suffix}/{_VPN_KEY.hex()}{encrypted.hex()}{parsed.path}"
    return urlunsplit(("https", "webvpn.fudan.edu.cn", path, parsed.query, ""))


def _ordinary_url(url: str) -> str:
    parsed, _ = _url_parts(url)
    if parsed.hostname != "webvpn.fudan.edu.cn":
        return url
    parts = parsed.path.split("/", 3)
    if len(parts) < 2 or not parts[1].startswith(("http", "https")):
        return url
    if len(parts) < 3 or not re.fullmatch(r"https?(?:-[0-9]+)?", parts[1]):
        raise ProtocolError("Malformed WebVPN target.")
    token = parts[2]
    if not token.startswith(_VPN_KEY.hex()) or not re.fullmatch(r"[0-9a-fA-F]+", token[32:]):
        raise ProtocolError("Malformed WebVPN target.")
    try:
        host = AES.new(_VPN_KEY, AES.MODE_CFB, iv=_VPN_KEY, segment_size=128).decrypt(bytes.fromhex(token[32:])).decode("ascii")
    except (ValueError, UnicodeError):
        raise ProtocolError("Malformed WebVPN target.") from None
    scheme, _, port = parts[1].partition("-")
    authority = host + (f":{port}" if port else "")
    return urlunsplit((scheme, authority, "/" + parts[3] if len(parts) == 4 else "", parsed.query, ""))


def validate_official_url(url: str) -> str:
    """Validate both the outer HTTPS origin and any encrypted proxy target."""
    parsed, port = _url_parts(url)
    if parsed.scheme != "https" or parsed.hostname not in _HOSTS or port not in (None, 443):
        raise ProtocolError("An unapproved authentication or API redirect was refused.")
    if parsed.hostname == "webvpn.fudan.edu.cn":
        segments = parsed.path.split("/")
        if any("%" in segment for segment in segments[1:3]) or any(
            segment in {".", ".."} for segment in unquote(parsed.path).split("/")
        ):
            raise ProtocolError("A noncanonical WebVPN target was refused.")
    ordinary = _ordinary_url(url)
    target, target_port = _url_parts(ordinary)
    if target.scheme != "https" or target.hostname not in _HOSTS or target_port not in (None, 443):
        raise ProtocolError("An unapproved WebVPN authentication target was refused.")
    return ordinary


@dataclass(frozen=True)
class HTTPResponse:
    status_code: int
    headers: dict[str, str]
    content: bytes = field(repr=False)
    url: str = field(repr=False)
    history: tuple[str, ...] = field(default=(), repr=False)

    @property
    def text(self) -> str:
        try:
            return self.content.decode("utf-8-sig")
        except UnicodeError:
            raise ProtocolError("The server returned invalid text encoding.") from None


def parse_json(response: HTTPResponse) -> dict:
    try:
        value = json.loads(response.content)
    except (ValueError, UnicodeError):
        raise ProtocolError("The server did not return the expected JSON object.") from None
    if not isinstance(value, dict):
        raise ProtocolError("The server did not return the expected JSON object.")
    return value


class SafeHTTP:
    """Bounded, explicit redirects and opt-in retries for read-only requests.

    HTTP statuses are returned to callers except exhausted transient failures.
    POST bodies may never follow 307/308 to a different endpoint. Proxy mode
    keeps direct official redirect targets behind WebVPN. No response is logged.
    """
    def __init__(self, session: requests.Session, *, sleep: Callable[[float], None] = time.sleep):
        self.session = session
        self.sleep = sleep
        session.trust_env = False
        session.auth = None
        session.headers.update({"User-Agent": USER_AGENT})

    def _delay(self, headers: dict[str, str], attempt: int) -> float:
        value = headers.get("Retry-After")
        delay = float(attempt + 1)
        if value is not None:
            try:
                if re.fullmatch(r"[0-9]+", value.strip()):
                    delay = float(value)
                else:
                    when = parsedate_to_datetime(value)
                    if when.tzinfo is None:
                        when = when.replace(tzinfo=timezone.utc)
                    delay = max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
            except (ValueError, TypeError, OverflowError):
                pass
        if delay > 30:
            raise NetworkUnavailable("The server requested a longer retry delay; try again later.")
        return delay

    def request(self, method: str, url: str, *, max_bytes: int = AUTH_LIMIT,
                retry: bool = False, headers: dict[str, str] | None = None,
                json: dict | None = None, data: dict | None = None,
                follow_redirects: bool = True, proxy_redirects: bool = False) -> HTTPResponse:
        method = method.upper()
        if retry and method != "GET":
            raise ValueError("Only read-only GET requests may be retried")
        history: list[str] = []
        request_headers = dict(headers or {})
        for hop in range(11):
            validate_official_url(url)
            attempts = 3 if retry and _query_one(url, "ticket") is None else 1
            for attempt in range(attempts):
                response = None
                try:
                    response = self.session.request(method, url, headers=request_headers,
                        json=json, data=data, allow_redirects=False, stream=True,
                        timeout=(10, 30), verify=True)
                    status = response.status_code
                    response_headers = requests.structures.CaseInsensitiveDict(response.headers)
                    if status in _TRANSIENT:
                        if attempt + 1 >= attempts:
                            raise NetworkUnavailable("The school service is temporarily unavailable.")
                        delay = self._delay(response_headers, attempt) if status == 429 else attempt + 1
                        response.close()
                        self.sleep(delay)
                        continue
                    body = bytearray()
                    for chunk in response.iter_content(chunk_size=min(65536, max_bytes + 1)):
                        if len(body) + len(chunk) > max_bytes:
                            raise ProtocolError("The server response exceeded the protocol size limit.")
                        body.extend(chunk)
                    result = HTTPResponse(status, response_headers, bytes(body), url, tuple(history))
                except requests.exceptions.SSLError:
                    raise NetworkUnavailable("The secure connection to the school service failed.") from None
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError,
                        requests.exceptions.ChunkedEncodingError):
                    if attempt + 1 >= attempts:
                        raise NetworkUnavailable("The school service could not be reached reliably.") from None
                    self.sleep(attempt + 1)
                    continue
                except requests.exceptions.RequestException:
                    raise NetworkUnavailable("The request to the school service failed.") from None
                finally:
                    if response is not None:
                        response.close()
                break
            if result.status_code not in _REDIRECTS or not follow_redirects:
                return result
            location = result.headers.get("Location")
            if not location or hop == 10:
                raise ProtocolError("Invalid or excessive server redirects.")
            next_url = _redirect_url(url, location)
            if proxy_redirects:
                next_url = vpn_url(next_url)
            if method != "GET" and result.status_code in {307, 308}:
                raise ProtocolError("A redirect attempted to forward an authentication body.")
            history.append(url)
            if result.status_code == 303 or (result.status_code in {301, 302} and method == "POST"):
                method, json, data = "GET", None, None
                request_headers = {}
            elif urlsplit(url).netloc != urlsplit(next_url).netloc:
                request_headers = {}
            url = next_url
        raise ProtocolError("Excessive server redirects.")

    def get_json(self, url: str, *, max_bytes: int = BUSINESS_LIMIT, retry: bool = True) -> dict:
        response = self.request("GET", url, max_bytes=max_bytes, retry=retry, proxy_redirects=True)
        _require_success(response)
        return parse_json(response)


def _require_success(response: HTTPResponse) -> None:
    if response.status_code in {401, 403}:
        raise AuthenticationError("The school session is not authenticated.")
    if not 200 <= response.status_code < 300:
        raise ProtocolError("The school service returned an unexpected HTTP status.")


def _string(value, *, optional: bool = False) -> str:
    if optional and value is None:
        return ""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ProtocolError("The identity response has an unsupported field type.")
    text = str(value)
    if not optional and not text.strip():
        raise ProtocolError("The identity response is missing required fields.")
    return text


def _nonempty(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProtocolError("The authentication response is missing a required field.")
    return value


def _query_one(url: str, key: str) -> str | None:
    values = parse_qs(urlsplit(url).query, keep_blank_values=True).get(key)
    if values is None:
        return None
    if len(values) != 1 or not values[0]:
        raise ProtocolError("The authentication URL has an ambiguous context.")
    return values[0]


class _AuthHTML(HTMLParser):
    def __init__(self, text: str):
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self.in_script = False
        self.has_password = False
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.in_script = True
        if tag == "input" and dict(attrs).get("type", "").lower() == "password":
            self.has_password = True

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_script:
            self.scripts.append(data)

    def literal(self, name: str) -> str | None:
        # Accept only a literal assignment, never execute JS or scan arbitrary URLs.
        pattern = re.compile(r"(?<![\w.$])" + re.escape(name) + r"\s*[:=]\s*(['\"])([^'\"\\\r\n]*)\1(?=\s*(?:[;,}]|$))")
        values = {unescape(m.group(2)) for script in self.scripts for m in pattern.finditer(script)}
        if len(values) > 1:
            raise ProtocolError("The authentication page has conflicting context values.")
        return next(iter(values), None)


class _UncertainAuthentication(NetworkUnavailable):
    pass


class Authenticator:
    def __init__(self, session: requests.Session):
        self.session = session
        self.http = SafeHTTP(session)

    def _context(self, url: str, *, proxied: bool) -> str | None:
        response = self.http.request("GET", url, proxy_redirects=proxied)
        _require_success(response)
        contexts = set()
        for candidate in (*response.history, response.url):
            validate_official_url(candidate)
            context = _query_one(candidate, "lck")
            if context is not None:
                contexts.add(context)
        page_context = _AuthHTML(response.text).literal("lck")
        if page_context is not None:
            contexts.add(_nonempty(page_context))
        if len(contexts) > 1:
            raise ProtocolError("The authentication chain has conflicting context values.")
        return next(iter(contexts), None)

    def _side_effect(self, method: str, url: str, **kwargs) -> HTTPResponse:
        try:
            return self.http.request(method, url, **kwargs)
        except NetworkUnavailable:
            raise _UncertainAuthentication("The authentication result could not be confirmed.") from None

    def _authenticate_stage(self, credentials: Credentials, lck: str, *, proxied: bool) -> None:
        entity = ICOURSE if proxied else WEBVPN
        encode = vpn_url if proxied else lambda value: value
        headers = {"Origin": WEBVPN if proxied else IDP, "Referer": encode(IDP + "/ac/")}
        methods_response = self.http.request("POST", encode(IDP + "/idp/authn/queryAuthMethods"),
            json={"lck": lck, "entityId": entity}, headers=headers, proxy_redirects=proxied)
        _require_success(methods_response)
        methods = parse_json(methods_response)
        choices = methods.get("data")
        if not isinstance(choices, list) or not all(isinstance(item, dict) for item in choices):
            raise ProtocolError("The authentication methods response is incompatible.")
        selected = next((item for item in choices if item.get("moduleCode") == "userAndPwd"), None)
        if selected is None:
            raise AuthenticationError("Password authentication is unavailable; complete unsupported authentication locally.")
        chain = _nonempty(selected.get("authChainCode"))
        request_type = _nonempty(methods.get("requestType", "chain_type"))
        key_response = self.http.request("GET", encode(IDP + "/idp/authn/getJsPublicKey"),
            retry=True, headers=headers, proxy_redirects=proxied)
        _require_success(key_response)
        public_key = _nonempty(parse_json(key_response).get("data"))
        try:
            key_text = public_key if "-----BEGIN" in public_key else "-----BEGIN PUBLIC KEY-----\n" + public_key + "\n-----END PUBLIC KEY-----"
            key = RSA.import_key(key_text)
            encrypted = base64.b64encode(PKCS1_v1_5.new(key).encrypt(credentials.password.encode("utf-8"))).decode("ascii")
        except (ValueError, TypeError, IndexError):
            raise ProtocolError("The password encryption parameters are incompatible.") from None
        executed = self._side_effect("POST", encode(IDP + "/idp/authn/authExecute"),
            headers=headers, proxy_redirects=proxied,
            json={"authModuleCode": "userAndPwd", "authChainCode": chain,
                  "entityId": entity, "requestType": request_type, "lck": lck,
                  "authPara": {"loginName": credentials.account, "password": encrypted, "verifyCode": ""}})
        _require_success(executed)
        result = parse_json(executed)
        if result.get("code") not in (200, "200") or isinstance(result.get("code"), bool):
            raise AuthenticationError("Authentication was refused; check credentials or complete any challenge locally.")
        token = _nonempty(result.get("loginToken"))
        engine = self._side_effect("POST", encode(IDP + "/idp/authCenter/authnEngine"),
            data={"loginToken": token}, headers=headers, follow_redirects=False)
        if engine.status_code in _REDIRECTS:
            location = engine.headers.get("Location")
            if not location:
                raise ProtocolError("The ticket redirect is missing its destination.")
            ticket = _redirect_url(engine.url, location)
        else:
            _require_success(engine)
            ticket = _nonempty(_AuthHTML(engine.text).literal("locationValue"))
            ticket = _redirect_url(engine.url, ticket)
        original = validate_official_url(ticket)
        target = urlsplit(original)
        expected_host = "icourse.fudan.edu.cn" if proxied else "webvpn.fudan.edu.cn"
        expected_path = "/casapi/index.php" if proxied else "/login"
        if target.hostname != expected_host or target.path != expected_path or not _query_one(original, "ticket"):
            raise ProtocolError("The authentication ticket has an unapproved destination.")
        consumed = self._side_effect("GET", encode(ticket), proxy_redirects=proxied)
        _require_success(consumed)

    def login(self, credentials: Credentials) -> Identity:
        if not credentials.account or credentials.password == "":
            raise ConfigurationError("Complete credentials are required.")
        try:
            context = self._context(IDP + "/idp/authCenter/authenticate?service=" + quote(WEBVPN + "/login?cas_login=true", safe=""), proxied=False)
            if context is None:
                raise ProtocolError("WebVPN authentication did not return a login context.")
            self._authenticate_stage(credentials, context, proxied=False)
            course_login = ICOURSE + "/casapi/index.php?r=auth/login&school_login=1&tenant_code=222&forward=" + quote(ICOURSE + "/", safe="")
            context = self._context(vpn_url(course_login), proxied=True)
            if context is not None:
                self._authenticate_stage(credentials, context, proxied=True)
        except _UncertainAuthentication:
            # No password/ticket replay: a single read-only confirmation is allowed.
            try:
                return self._probe_identity(credentials.account, retry=False)
            except (AuthenticationError, ProtocolError, NetworkUnavailable):
                raise NetworkUnavailable("Authentication was interrupted; its result is unconfirmed. Try again later.") from None
        return self.probe_identity(credentials.account)

    def probe_identity(self, expected_account: str | None = None) -> Identity:
        return self._probe_identity(expected_account, retry=True)

    def _probe_identity(self, expected_account: str | None, *, retry: bool) -> Identity:
        response = self.http.request("GET", vpn_url(ICOURSE + "/userapi/v1/infosimple"), retry=retry, proxy_redirects=True)
        _require_success(response)
        ordinary = validate_official_url(response.url)
        parsed = urlsplit(ordinary)
        if parsed.hostname != "icourse.fudan.edu.cn" or parsed.path != "/userapi/v1/infosimple":
            if parsed.hostname in {"id.fudan.edu.cn", "webvpn.fudan.edu.cn"} or parsed.path.startswith("/casapi/"):
                raise AuthenticationError("The saved school session has expired.")
            raise ProtocolError("The identity endpoint redirected unexpectedly.")
        if response.content.lstrip().startswith(b"<"):
            if _AuthHTML(response.text).has_password:
                raise AuthenticationError("The school session requires login.")
            raise ProtocolError("The identity endpoint returned HTML instead of JSON.")
        payload = parse_json(response)
        code = payload.get("code")
        if code in (401, 403, "401", "403"):
            raise AuthenticationError("The school session is not authenticated.")
        if isinstance(code, bool) or code not in (0, 200, "0", "200"):
            raise ProtocolError("The identity endpoint returned an unrecognized business status.")
        params, data = payload.get("params"), payload.get("data")
        if params is not None and not isinstance(params, dict):
            raise ProtocolError("The identity response has invalid params.")
        if data is not None and not isinstance(data, dict):
            raise ProtocolError("The identity response has invalid data.")
        if params and data and _string(params.get("account")) != _string(data.get("account")):
            raise ProtocolError("The identity response contains conflicting accounts.")
        record = params or data
        if not record:
            raise ProtocolError("The identity response is empty.")
        identity = Identity(_string(record.get("account")), _string(record.get("id")),
                            _string(record.get("tenant_id")), _string(record.get("phone"), optional=True))
        if expected_account is not None and identity.account != expected_account:
            raise AuthenticationError("The authenticated account does not match the selected account.")
        return identity
