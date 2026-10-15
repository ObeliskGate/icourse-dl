# SPDX-License-Identifier: GPL-3.0-or-later
"""Keyboard-only selection; injected input/output pairs support offline UI tests."""
from __future__ import annotations

import os
import sys
import unicodedata
from collections.abc import Sequence
from typing import TypeVar

from prompt_toolkit.application import Application
from prompt_toolkit.data_structures import Point
from prompt_toolkit.input import Input
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.layout.margins import ScrollbarMargin
from prompt_toolkit.output import Output, create_output
from prompt_toolkit.styles import Style

from .errors import ConfigurationError

T = TypeVar('T')


def _safe_label(value: str) -> str:
    # Neutralize terminal controls, bidi overrides, surrogates and line breaks.
    return ''.join(' ' if unicodedata.category(char).startswith('C') or char in '\u2028\u2029' else char for char in value)


def terminal_available() -> bool:
    """Whether both keyboard input and the stderr UI have an interactive TTY."""
    try:
        return bool(sys.stdin.isatty() and sys.stderr.isatty() and os.environ.get('TERM') != 'dumb')
    except (AttributeError, OSError, ValueError):
        return False


def choose(title: str, options: Sequence[tuple[str, T]], *, auto_select: bool = True,
           default_index: int = 0, input: Input | None = None,
           output: Output | None = None) -> T:
    """Select using arrows/Enter, or cancel with Escape/Ctrl+C.

    Tests may supply a prompt_toolkit Input/Output pair (for example,
    create_pipe_input() and DummyOutput()). Both must be supplied together;
    this explicit pair bypasses the real-terminal check, without changing keys.
    """
    if not options:
        raise ConfigurationError('No candidates are available for selection.')
    if not 0 <= default_index < len(options):
        raise ConfigurationError('The default selection is invalid.')
    if (input is None) != (output is None):
        raise ConfigurationError('Interactive input and output must be supplied together.')
    labels = [_safe_label(label) for label, _ in options]
    heading = _safe_label(title)
    if len(options) == 1 and auto_select:
        message = f'{heading}: {labels[0]}\n'
        if output is None:
            print(message, end='', file=sys.stderr)
        else:
            output.write(message)
            output.flush()
        return options[0][1]
    if input is None and not terminal_available():
        raise ConfigurationError('A usable interactive terminal is required. For downloads, provide --course-id and --lecture-id.')

    selected = default_index
    bindings = KeyBindings()

    @bindings.add('up')
    def up(event):
        nonlocal selected
        selected = max(0, selected - 1)

    @bindings.add('down')
    def down(event):
        nonlocal selected
        selected = min(len(options) - 1, selected + 1)

    @bindings.add('enter')
    def accept(event):
        event.app.exit(result=options[selected][1])

    @bindings.add('escape')
    @bindings.add('c-c')
    def cancel(event):
        event.app.exit(exception=KeyboardInterrupt())

    def rows():
        fragments = []
        for index, label in enumerate(labels):
            style = 'class:selected' if index == selected else ''
            fragments.append((style, ('> ' if index == selected else '  ') + label))
            if index + 1 < len(labels):
                fragments.append(('', '\n'))
        return fragments

    control = FormattedTextControl(rows, focusable=True,
                                   get_cursor_position=lambda: Point(x=0, y=selected))
    listing = Window(control, wrap_lines=True,
                     height=Dimension(min=1, preferred=min(len(options), 12), max=12),
                     right_margins=[ScrollbarMargin(display_arrows=True)])
    body = HSplit([
        Window(FormattedTextControl(heading), wrap_lines=True, height=Dimension(min=1)),
        listing,
        Window(FormattedTextControl('Up/Down: move | Enter: select | Esc/Ctrl+C: cancel'),
               wrap_lines=True, height=Dimension(min=1)),
    ])
    application: Application[T] = Application(
        layout=Layout(body, focused_element=control), key_bindings=bindings,
        style=Style.from_dict({'selected': 'reverse'}),
        input=input, output=output if output is not None else create_output(stdout=sys.stderr),
        full_screen=False, mouse_support=False,
    )
    application.ttimeoutlen = 0.15
    try:
        return application.run()
    except (EOFError, OSError, ValueError):
        raise ConfigurationError('The terminal closed or is unavailable; selection cancelled.') from None
