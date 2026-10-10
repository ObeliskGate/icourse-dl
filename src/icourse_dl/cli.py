# SPDX-License-Identifier: GPL-3.0-or-later
"""Command boundary: sanitized errors, explicit inputs, no implicit credentials."""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .errors import ConfigurationError, ICourseError, StorageFailure


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--env-file', type=Path, default=argparse.SUPPRESS)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='icourse-dl', description='Download authorized iCourse MP4 recordings.')
    p.add_argument('--version', action='version', version=__version__)
    _common(p)
    p.add_argument('--course-id')
    p.add_argument('--lecture-id')
    p.add_argument('--list', action='store_true')
    p.add_argument('--output', type=Path)
    p.add_argument('--overwrite', action='store_true')
    p.add_argument('--restart', action='store_true')
    # One positional keeps a course URL and named actions unambiguous.
    p.add_argument('target', nargs='?')
    p.add_argument('--refresh', action='store_true')
    p.add_argument('--remember-session', action='store_true')
    p.add_argument('--remember-password', action='store_true')
    p.add_argument('--measure-session', action='store_true')
    return p


def _validate(args: argparse.Namespace) -> str:
    action = args.target if args.target in ('login', 'status', 'logout') else 'course'
    download_options = (args.course_id, args.lecture_id, args.list, args.output, args.overwrite, args.restart)
    login_options = (args.refresh, args.remember_session, args.remember_password, args.measure_session)
    if action != 'course' and any(download_options):
        raise ConfigurationError('Course options cannot be used with this command.')
    if action != 'login' and any(login_options):
        raise ConfigurationError('Login options require the login command.')
    if action in ('status', 'logout') and hasattr(args, 'env_file'):
        raise ConfigurationError('This command does not accept --env-file.')
    if args.measure_session and (args.remember_session or args.remember_password):
        raise ConfigurationError('--measure-session cannot be combined with remember options.')
    if args.list and args.lecture_id:
        raise ConfigurationError('--list and --lecture-id are mutually exclusive.')
    return action


def _run(args: argparse.Namespace) -> int:
    action = _validate(args)
    if action in ('status', 'logout') or args.remember_session or args.remember_password:
        raise StorageFailure('Persistent storage is gated on the pending local session-capacity measurement. No records were read or changed; use login --measure-session first.')
    from .auth import Authenticator, load_env_config, prompt_credentials
    import requests

    config = load_env_config(args.env_file) if hasattr(args, 'env_file') else None
    target = None
    if action == 'course':
        from .client import parse_target
        course_id = args.course_id
        if not args.target and not course_id and config:
            course_id = config.course_id_text
        target = parse_target(args.target, course_id, args.lecture_id)
        if not args.list and not target.lecture_id and not sys.stdin.isatty():
            raise ConfigurationError('Non-interactive use requires --lecture-id or --list.')
    credentials = config.credentials if config else prompt_credentials(None)
    with requests.Session() as session:
        session.trust_env = False
        authenticator = Authenticator(session)
        identity = authenticator.login(credentials)
        if args.measure_session:
            from .session_store import select_session_cookies, serialize_session
            with requests.Session() as restored:
                restored.trust_env = False
                for cookie in select_session_cookies(session):
                    restored.cookies.set_cookie(copy.copy(cookie))
                Authenticator(restored).probe_identity(credentials.account)
                if config and config.course_id_text:
                    from .client import ICourseClient, parse_target
                    measured_target = parse_target(None, config.course_id_text, None)
                    ICourseClient(restored, identity).get_lectures(measured_target.course_id)
                record = serialize_session(identity.account, select_session_cookies(restored))
            sizes = {'session_utf8_bytes': len(record.encode('utf-8')), 'session_utf16le_bytes': len(record.encode('utf-16-le')), 'windows_limit_bytes': 2560}
            print(json.dumps(sizes, separators=(',', ':')))
            return 6 if sizes['session_utf16le_bytes'] > 2560 else 0
        if action == 'login':
            print('Login verified for this process only; the next command must authenticate again.')
            return 0
        from .client import ICourseClient
        from .download import DownloadOptions, download_lecture
        client = ICourseClient(session, identity)
        reauthenticated = False

        def authenticated_call(call):
            nonlocal reauthenticated
            from .errors import AuthenticationError
            try:
                return call()
            except AuthenticationError:
                if reauthenticated:
                    raise
                reauthenticated = True
                client.identity = authenticator.login(credentials)
                return call()

        lectures = authenticated_call(lambda: client.get_lectures(target.course_id))
        if args.list or not target.lecture_id:
            for index, lecture in enumerate(lectures, 1):
                print(f'{index}\t{lecture.date}\t{lecture.sub_id}\t{lecture.title}\t{lecture.lecturer}\tplayback={lecture.has_playback}')
            if not lectures:
                print('No lectures returned.')
                return 0
            if args.list:
                return 0
            selection = input('Lecture number or sub_id: ').strip()
            selected = next((lecture for lecture in lectures if lecture.sub_id == selection), None)
            if selected is None and selection.isascii() and selection.isdecimal() and 1 <= int(selection) <= len(lectures):
                selected = lectures[int(selection) - 1]
            if selected is None:
                raise ConfigurationError('Selection is not in this course.')
        else:
            selected = next((lecture for lecture in lectures if lecture.sub_id == target.lecture_id), None)
            if selected is None:
                from .errors import PermissionDenied
                raise PermissionDenied('Lecture is not in this course.')

        def refresh_media():
            def resolve():
                client.identity = authenticator.probe_identity(credentials.account)
                return client.resolve_media(target.course_id, selected.sub_id)
            return authenticated_call(resolve)

        source = authenticated_call(lambda: client.resolve_media(target.course_id, selected.sub_id))
        result = download_lecture(source, selected, session, DownloadOptions(args.output or Path.cwd(), args.overwrite, args.restart), refresh_media=refresh_media)
        print(f'Output: {result}')
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return _run(parser().parse_args(argv))
    except ICourseError as exc:
        print(str(exc), file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print('Interrupted; resumable media parts are retained.', file=sys.stderr)
        return 130
    except Exception as exc:
        print(f'Internal failure ({type(exc).__name__}); no diagnostic secrets printed.', file=sys.stderr)
        return 1
