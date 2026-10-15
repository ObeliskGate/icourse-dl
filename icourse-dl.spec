# SPDX-License-Identifier: GPL-3.0-or-later
"""Native onefile console build; invoke with the locked build dependency group."""
from pathlib import Path
import sys

from PyInstaller.utils.hooks import collect_data_files, copy_metadata
from yt_dlp.__pyinstaller import get_hook_dirs


root = Path(SPECPATH)
if sys.platform not in {"win32", "darwin"}:
    raise SystemExit("Executable packaging supports native Windows and macOS only.")

native_keyring = (
    "keyring.backends.Windows" if sys.platform == "win32"
    else "keyring.backends.macOS"
)
# Installed dependency data only: never copy the repository or an env file.
datas = collect_data_files("yt_dlp", excludes=["**/test*", "**/.env*"])
for distribution in ("icourse-dl", "keyring", "yt-dlp", "pycryptodome"):
    datas += copy_metadata(distribution, recursive=True)

analysis = Analysis(
    [str(root / "scripts" / "frozen_entry.py")],
    pathex=[str(root / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=[native_keyring, "keyring.backends.fail"],
    # Use yt-dlp's own hook plus the installed standard/contrib keyring and
    # Crypto hooks (including Crypto's dynamically loaded native libraries).
    hookspath=get_hook_dirs(),
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "test", "tests", "Crypto.SelfTest", "tkinter"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="icourse-dl",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
