# SPDX-License-Identifier: GPL-3.0-or-later
"""Run outside-source installation checks without school access."""
import os
from pathlib import Path
import subprocess
import tempfile


def run(*args, cwd=None):
    subprocess.run([str(arg) for arg in args], cwd=cwd, check=True)


def verify():
    root = Path(__file__).resolve().parents[1]
    wheel = root / 'dist/icourse_dl-0.1.0-py3-none-any.whl'
    with tempfile.TemporaryDirectory(prefix='icourse-artifact-') as temporary:
        outside = Path(temporary)
        env = outside / 'wheel'
        run('uv', 'venv', env, '--python', '3.12')
        binaries = env / ('Scripts' if os.name == 'nt' else 'bin')
        python = binaries / ('python.exe' if os.name == 'nt' else 'python')
        command = binaries / ('icourse-dl.exe' if os.name == 'nt' else 'icourse-dl')
        run('uv', 'pip', 'install', '--python', python, wheel)
        run(command, '--help', cwd=outside)
        run(python, '-m', 'icourse_dl', '--help', cwd=outside)
        run(python, root / 'tests/smoke_download.py', cwd=outside)
        clone = outside / 'clone'
        run('git', 'clone', root / 'dist/icourse-dl.bundle', clone)
        env = outside / 'bundle-env'
        run('uv', 'venv', env, '--python', '3.12')
        binaries = env / ('Scripts' if os.name == 'nt' else 'bin')
        python = binaries / ('python.exe' if os.name == 'nt' else 'python')
        command = binaries / ('icourse-dl.exe' if os.name == 'nt' else 'icourse-dl')
        run('uv', 'pip', 'install', '--python', python, clone)
        run(command, '--help', cwd=outside)
        run(python, '-m', 'icourse_dl', '--help', cwd=outside)
        run(python, clone / 'tests/smoke_download.py', cwd=outside)
    print('Clean wheel and bundle installation verification passed.')


if __name__ == '__main__':
    verify()
