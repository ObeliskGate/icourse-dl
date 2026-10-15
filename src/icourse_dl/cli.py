# SPDX-License-Identifier: GPL-3.0-or-later
"""Command boundary: explicit credential sources and separate query/download actions."""
from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .errors import AuthenticationError, ConfigurationError, ICourseError, NetworkUnavailable, PermissionDenied, ProtocolError


SEMESTER_HELP = '''Verified school semester IDs (observed records, not an exhaustive list):
  27 = 2026-2027 学年第一学期
  25 = 2025-2026 学年第二学期
  24 = 2025-2026 学年第一学期
  21 = 2024-2025 学年第二学期
  20 = 2024-2025 学年第一学期
  18 = 2023-2024 学年暑期
  14 = 2023-2024 学年第二学期
IDs are school identifiers, not an arithmetic encoding. Without --term,
name searches query all matching semesters, without scanning semester IDs.'''


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--verbose', action='store_true', default=argparse.SUPPRESS,
                        help='Show sanitized authentication stages and diagnostic details; never log credentials or tickets.')
    parser.add_argument('--env', type=Path, nargs='?', const=Path('.env'), default=argparse.SUPPRESS,
                        help='Override credentials for this invocation: --env uses ./.env; --env PATH uses that file. Only login saves credentials.')


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog='icourse-dl', description='Manage credentials, query courses/lectures, and download authorized recordings.')
    root.add_argument('--version', action='version', version=__version__)
    _common(root)
    commands = root.add_subparsers(dest='action', required=True, title='commands')
    login = commands.add_parser('login', help='Verify and save default credentials, or clear them.',
                                description='Verify school credentials and save them to a supported system keyring. No cookies are persisted. An unavailable or locked backend is an error; there is no plaintext fallback.')
    _common(login)
    login.add_argument('--clear', action='store_true', help='Delete only this tool\'s saved credentials, without contacting the school or deleting .env.')
    search = commands.add_parser('search', help='Query courses or lectures; never download.',
                                 description='Choose courses to find course IDs, or lectures to find lecture IDs.',
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=SEMESTER_HELP)
    _common(search)
    queries = search.add_subparsers(dest='search_kind', required=True, title='query objects')
    courses = queries.add_parser('courses', help='Find courses by name, optionally filtered by semester.',
                                 description='Return course IDs, titles, codes, and semesters. Does not return lecture IDs.',
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog='Example: icourse-dl search courses "高级大数据解析" --term 27 --env\n\n' + SEMESTER_HELP)
    _common(courses)
    courses.add_argument('name', help='Course name or keyword.')
    courses.add_argument('--term', help='Optional school semester ID; omit to search matching courses across semesters.')
    lectures = queries.add_parser('lectures', help='List lecture IDs for one course.',
                                  description='Return dates, titles, teachers, playback flags and lecture IDs; never download.')
    _common(lectures)
    lectures.add_argument('--course-id', help='Course ID; otherwise use COURSE_ID from an explicitly selected env file.')
    download = commands.add_parser('download', help='Select a course/lecture and download one recording.',
                                   description='A name starts semester, course and lecture selection. Arrow keys move, Enter selects, Esc/Ctrl+C cancels. Single candidates are selected automatically. Noninteractive use requires explicit --course-id and --lecture-id.')
    _common(download)
    download.add_argument('name', nargs='?', help='Course name or keyword; mutually exclusive with --course-id.')
    download.add_argument('--term', help='Optional semester filter when searching by name.')
    download.add_argument('--course-id', help='Skip course search; otherwise COURSE_ID from an explicit env file is a fallback.')
    download.add_argument('--lecture-id', help='Download this lecture; requires --course-id and skips interactive selection.')
    download.add_argument('--output', type=Path, default=Path.cwd(), help='Save directory (default: current directory).')
    download.add_argument('--overwrite', action='store_true', help='Allow replacement of an existing completed file.')
    download.add_argument('--restart', action='store_true', help='Discard this lecture\'s partial files and download again.')
    return root


def _clean(value: str) -> str:
    return ' '.join(''.join(char if char.isprintable() else ' ' for char in value).split())


def _semester_label(raw: str) -> str:
    match = re.fullmatch(r'(\d{4})-(\d{4})-?([12])', raw)
    if match:
        first, second, number = match.groups()
        return f'{first}-{second} 学年第{"一" if number == "1" else "二"}学期'
    match = re.fullmatch(r'(\d{4}-\d{4})暑期', raw)
    return f'{match[1]} 学年暑期' if match else _clean(raw)


def _validate(args: argparse.Namespace) -> None:
    if args.action == 'login':
        if args.clear and hasattr(args, 'env'):
            raise ConfigurationError('--clear cannot be combined with --env.')
        return
    name = getattr(args, 'name', None)
    term = getattr(args, 'term', None)
    if name is not None and not name.strip():
        raise ConfigurationError('A nonempty course name or keyword is required.')
    if term is not None and (not term.isascii() or not term.isdecimal() or int(term) <= 0):
        raise ConfigurationError('--term must be a positive school semester ID.')
    if args.action == 'download':
        if name is not None and args.course_id is not None:
            raise ConfigurationError('Use a course name or --course-id, not both.')
        if term is not None and name is None:
            raise ConfigurationError('--term requires a course name.')
        if args.lecture_id is not None and args.course_id is None:
            raise ConfigurationError('--lecture-id requires explicit --course-id.')
        from .interaction import terminal_available
        if not terminal_available() and (args.course_id is None or args.lecture_id is None):
            raise ConfigurationError('Noninteractive download requires --course-id and --lecture-id.')


def _login(args: argparse.Namespace) -> int:
    from .auth import Authenticator, load_env_config, prompt_credentials
    from .credentials import CredentialStore
    from .interaction import choose
    import requests

    store = CredentialStore()
    if args.clear:
        store.clear()
        print('Saved credentials cleared; server sessions and user env files were not changed.')
        return 0
    store.check_writable()
    previous = store.load()
    path = getattr(args, 'env', None)
    credentials = load_env_config(path).credentials if path is not None else prompt_credentials(None)
    if previous is not None and previous.account != credentials.account:
        replace = choose(f'Replace default account {_clean(previous.account)} with {_clean(credentials.account)}?',
                         [('Cancel', False), ('Replace default account', True)], auto_select=False)
        if not replace:
            raise KeyboardInterrupt
    with requests.Session() as session:
        Authenticator(session).login(credentials)
    try:
        store.save(credentials)
    except ICourseError as error:
        raise type(error)(f'Login verified, but credentials were not confirmed saved. {error}') from None
    print('Login verified; default credentials saved to the system keyring. No cookies saved.')
    return 0


def _print_courses(courses) -> None:
    if not courses:
        print('No courses found.')
        return
    print('Course ID\tCourse name\tCourse code\tSemester\tSemester ID')
    for course in courses:
        print('\t'.join(_clean(value) for value in (course.course_id, course.title,
                        course.course_code, _semester_label(course.term_name), ','.join(course.term_ids))))


def _lecture_label(lecture) -> str:
    return _clean(f'{lecture.date} | {lecture.title} | {lecture.lecturer} | playback={lecture.has_playback} | lecture ID {lecture.sub_id}')


def _choose_course(courses, term: str | None):
    from .interaction import choose
    if not courses:
        raise ConfigurationError('No courses found; nothing to download.')
    if term is None:
        semesters = {}
        for course in courses:
            for term_id in course.term_ids:
                semesters.setdefault(term_id, set()).add(_semester_label(course.term_name))
        options = [(' / '.join(sorted(semesters[key])) + f' | semester ID {key}', key)
                   for key in sorted(semesters, key=int, reverse=True)]
        term = choose('Select semester', options)
    else:
        term = str(int(term))
    matches = [course for course in courses if term in course.term_ids]
    return choose('Select course / teaching class',
                  [(f'{course.title} | {course.course_code} | course ID {course.course_id}', course) for course in matches])


def _run(args: argparse.Namespace) -> int:
    _validate(args)
    if args.action == 'login':
        return _login(args)
    from .auth import Authenticator, load_env_config
    from .client import ICourseClient, parse_target
    import requests

    path = getattr(args, 'env', None)
    config = load_env_config(path) if path is not None else None
    target = None
    name = getattr(args, 'name', None)
    if name is None:
        course_id = args.course_id if args.course_id is not None else config.course_id_text if config else None
        target = parse_target(course_id, getattr(args, 'lecture_id', None))
    if config is not None:
        credentials = config.credentials
    else:
        from .credentials import CredentialStore, StorageFailure
        credentials = CredentialStore().load()
        if credentials is None:
            raise StorageFailure('No saved credentials. Run login first, or use --env [PATH] for this invocation.')
    with requests.Session() as session:
        authenticator = Authenticator(session)
        if sys.stderr.isatty():
            print('Authenticating and verifying identity; waiting for the network.', file=sys.stderr, flush=True)
        client = ICourseClient(session, authenticator.login(credentials))
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

        if args.action == 'search':
            if args.search_kind == 'courses':
                _print_courses(authenticated_call(lambda: client.search_courses(args.name, args.term)))
            else:
                lectures = authenticated_call(lambda: client.get_lectures(target.course_id))
                if not lectures:
                    print('No lectures found.')
                else:
                    print('Number\tDate\tLecture ID\tTitle\tTeacher\tPlayback')
                    for index, lecture in enumerate(lectures, 1):
                        print('\t'.join(_clean(str(value)) for value in (index, lecture.date, lecture.sub_id,
                                        lecture.title, lecture.lecturer, lecture.has_playback)))
            return 0

        from .download import DownloadOptions, download_lecture
        from .interaction import choose
        if name is not None:
            courses = authenticated_call(lambda: client.search_courses(name, args.term))
            course = _choose_course(courses, args.term)
            target = parse_target(course.course_id, None)
        else:
            course = authenticated_call(lambda: client.get_course(target.course_id))
        print(f'Course: {_clean(course.title)} | course ID {course.course_id}', file=sys.stderr)
        print(f'Output directory: {_clean(str(args.output.absolute()))}', file=sys.stderr)
        lectures = authenticated_call(lambda: client.get_lectures(target.course_id))
        if target.lecture_id is None:
            selected = choose('Select lecture', [(_lecture_label(lecture), lecture) for lecture in lectures])
        else:
            selected = next((lecture for lecture in lectures if lecture.sub_id == target.lecture_id), None)
            if selected is None:
                raise PermissionDenied('Lecture is not in this course.')
        print(f'Lecture: {_lecture_label(selected)}', file=sys.stderr)

        def refresh_media():
            def resolve():
                client.identity = authenticator.probe_identity(credentials.account)
                return client.resolve_media(target.course_id, selected.sub_id)
            return authenticated_call(resolve)

        source = authenticated_call(lambda: client.resolve_media(target.course_id, selected.sub_id))
        result = download_lecture(source, selected, session,
                                  DownloadOptions(args.output, args.overwrite, args.restart), refresh_media=refresh_media)
        print(f'Output: {result}')
    return 0


class _RetryFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return (f'Authentication temporarily unavailable; retrying '
                f'({record.retry_round}/3) in {record.retry_delay}s...')


def _error_message(error: ICourseError, verbose: bool) -> str:
    if verbose or not str(error).startswith('Authentication '):
        return str(error)
    if isinstance(error, NetworkUnavailable):
        message = {
            'timeout': 'The school connection timed out.',
            'connection': 'Could not connect to the school service.',
            'response-interrupted': 'The school connection was interrupted.',
            'transient-http': 'The school service is temporarily unavailable.',
            'tls-verification': 'The secure connection to the school service failed.',
            'authentication-budget': 'Authentication exceeded its time budget.',
        }.get(error.reason, 'Authentication could not be completed.')
    elif isinstance(error, AuthenticationError):
        message = 'School authentication was not accepted.'
    elif isinstance(error, ProtocolError):
        message = 'The school returned an unexpected authentication response.'
    else:
        return str(error)
    return message + ' Use --verbose for details.'


def main(argv: Sequence[str] | None = None) -> int:
    verbose = False
    logger = logging.getLogger('icourse_dl.auth')
    previous_level, previous_propagation = logger.level, logger.propagate
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING)
    logger.propagate = False
    handler.addFilter(lambda record: verbose or hasattr(record, 'retry_round'))
    try:
        tokens = list(sys.argv[1:] if argv is None else argv)
        actions = {'login', 'search', 'courses', 'lectures', 'download'}
        # Reserved command names after bare --env are not file paths. Use ./NAME or --env=NAME for such files.
        tokens = ['--env=.env' if token == '--env' and index + 1 < len(tokens)
                  and tokens[index + 1] in actions else token for index, token in enumerate(tokens)]
        args = parser().parse_args(tokens)
        verbose = getattr(args, 'verbose', False)
        logger.setLevel(logging.INFO if verbose else logging.WARNING)
        if not verbose:
            handler.setFormatter(_RetryFormatter())
        return _run(args)
    except ICourseError as error:
        print(_error_message(error, verbose), file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        print('Cancelled; any resumable media parts are retained.', file=sys.stderr)
        return 130
    except Exception as error:
        print(f'Internal failure ({type(error).__name__}); no diagnostic secrets printed.', file=sys.stderr)
        return 1
    finally:
        logger.removeHandler(handler)
        handler.close()
        logger.setLevel(previous_level)
        logger.propagate = previous_propagation
