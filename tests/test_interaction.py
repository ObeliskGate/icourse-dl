# SPDX-License-Identifier: GPL-3.0-or-later
from io import StringIO

import pytest
from prompt_toolkit.data_structures import Size
from prompt_toolkit.input.defaults import create_pipe_input
from prompt_toolkit.output import DummyOutput

from icourse_dl import interaction
from icourse_dl.errors import ConfigurationError


class RecordingOutput(DummyOutput):
    def __init__(self):
        self.text = StringIO()

    def write(self, data):
        self.text.write(data)

    def write_raw(self, data):
        self.text.write(data)

    def get_size(self):
        return Size(rows=10, columns=44)


def select(keys, options, **kwargs):
    output = RecordingOutput()
    with create_pipe_input() as pipe:
        pipe.send_text(keys)
        value = interaction.choose('请选择课程', options, input=pipe, output=output, **kwargs)
    return value, output.text.getvalue()


@pytest.mark.parametrize(('keys', 'default', 'expected'), [
    ('\r', 0, 'first'),
    ('\x1b[B\r', 0, 'second'),
    ('\x1b[A\r', 1, 'first'),
    ('\x1b[B\x1b[A\r', 0, 'first'),
    ('\x1b[A\r', 0, 'first'),
    ('\x1b[B\r', 1, 'second'),
])
def test_real_arrow_and_enter_keys(keys, default, expected):
    result, rendered = select(keys, [('课程一', 'first'), ('课程二', 'second')], default_index=default)
    assert result == expected


@pytest.mark.parametrize('key', ['\x1b', '\x03'])
def test_escape_and_control_c_cancel(key):
    with pytest.raises(KeyboardInterrupt):
        select(key, [('取消', False), ('替换', True)])


def test_conflict_defaults_to_cancel():
    result, _ = select('\r', [('取消', False), ('替换', True)], auto_select=False)
    assert result is False


def test_single_option_can_require_confirmation():
    with pytest.raises(KeyboardInterrupt):
        select('\x03', [('唯一课程', 42)], auto_select=False)
    assert select('\r', [('唯一课程', 42)], auto_select=False)[0] == 42


def test_long_chinese_choices_scroll_to_last_value():
    options = [(f'第 {index} 节 ' + '很长的中文课程标题' * 10, index) for index in range(40)]
    assert select('\x1b[B' * 39 + '\r', options)[0] == 39
    assert select('\x1b[A' * 39 + '\r', options, default_index=39)[0] == 0


def test_injected_pair_bypasses_real_terminal_check(monkeypatch):
    monkeypatch.setattr(interaction, 'terminal_available', lambda: False)
    assert select('\x1b[B\r', [('甲', 1), ('乙', 2)])[0] == 2


def test_noninteractive_multiple_choices_fail_without_waiting(monkeypatch):
    monkeypatch.setattr(interaction, 'terminal_available', lambda: False)
    with pytest.raises(ConfigurationError):
        interaction.choose('课程', [('甲', 1), ('乙', 2)])


def test_empty_options_fail():
    with pytest.raises(ConfigurationError):
        interaction.choose('课程', [])


@pytest.mark.parametrize('index', [-1, 2])
def test_bad_default_index_fails(index):
    with pytest.raises(ConfigurationError):
        interaction.choose('课程', [('甲', 1), ('乙', 2)], default_index=index)


def test_injected_pair_is_required():
    with pytest.raises(ConfigurationError):
        interaction.choose('课程', [('甲', 1), ('乙', 2)], output=DummyOutput())


def test_single_option_shows_sanitized_label_without_terminal(monkeypatch, capsys):
    monkeypatch.setattr(interaction, 'terminal_available', lambda: False)
    assert interaction.choose('课程\x1b\n', [('中文\r\x07\x9b\u202e\u2028标题', 42)]) == 42
    rendered = capsys.readouterr().err
    assert '中文' in rendered and '标题' in rendered
    for control in ('\x1b', '\r', '\x07', '\x9b', '\u202e', '\u2028'):
        assert control not in rendered
    assert rendered.count('\n') == 1


def test_interactive_labels_cannot_inject_terminal_controls():
    result, rendered = select('\r', [('中文\x1b[31m\x07\u202e标题', 42), ('其他', 43)])
    assert result == 42
    assert '中文' in rendered
    for control in ('\x1b', '\x07', '\u202e'):
        assert control not in rendered


def test_closed_pipe_fails_clearly():
    output = DummyOutput()
    with create_pipe_input() as pipe:
        pipe.close()
        with pytest.raises(ConfigurationError):
            interaction.choose('课程', [('甲', 1), ('乙', 2)], input=pipe, output=output)


@pytest.mark.parametrize(('stdin_tty', 'stderr_tty', 'term', 'expected'), [
    (True, True, '', True),
    (False, True, '', False),
    (True, False, '', False),
    (True, True, 'dumb', False),
])
def test_terminal_availability(monkeypatch, stdin_tty, stderr_tty, term, expected):
    class Stream:
        def __init__(self, tty):
            self.tty = tty

        def isatty(self):
            return self.tty

    monkeypatch.setattr(interaction.sys, 'stdin', Stream(stdin_tty))
    monkeypatch.setattr(interaction.sys, 'stderr', Stream(stderr_tty))
    monkeypatch.setenv('TERM', term)
    assert interaction.terminal_available() is expected
