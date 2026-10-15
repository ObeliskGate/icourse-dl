# SPDX-License-Identifier: GPL-3.0-or-later
"""Inspect and smoke the actual frozen CLI offline, outside the checkout."""
from __future__ import annotations

import argparse
from importlib.metadata import version
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from PyInstaller.archive.readers import CArchiveReader


def inspect_bundle(executable: Path) -> None:
    archive = CArchiveReader(str(executable))
    files = {name.replace("\\", "/") for name in archive.toc}
    pyz_names = [name for name in archive.toc if name.endswith(".pyz")]
    if len(pyz_names) != 1:
        raise RuntimeError("Expected exactly one frozen Python module archive.")
    modules = archive.open_embedded_archive(pyz_names[0]).toc
    native = "keyring.backends.Windows" if sys.platform == "win32" else "keyring.backends.macOS"
    for module in (
        "icourse_dl.cli", "icourse_dl.auth", "icourse_dl.download",
        "keyring", "keyring.backends.fail", native,
        "Crypto.Cipher.AES", "Crypto.Cipher.PKCS1_v1_5", "Crypto.PublicKey.RSA",
        "yt_dlp", "yt_dlp.downloader.hls", "prompt_toolkit",
    ):
        if module not in modules:
            raise RuntimeError(f"Missing frozen module: {module}")
    for distribution in ("icourse_dl", "keyring", "yt_dlp", "pycryptodome"):
        if not any(name.startswith(distribution + "-") and name.endswith(".dist-info/METADATA")
                   for name in files):
            raise RuntimeError(f"Missing frozen distribution metadata: {distribution}")
    if not any(name.startswith("keyring-") and name.endswith(".dist-info/entry_points.txt")
               for name in files):
        raise RuntimeError("Missing keyring backend entry-point metadata.")
    if not any(name.startswith("Crypto/Cipher/_raw_aes.") for name in files):
        raise RuntimeError("Missing Crypto native AES library.")
    if "certifi/cacert.pem" not in files:
        raise RuntimeError("Missing bundled TLS CA certificates.")
    if any(part in {"tests", "test", ".env"} or part.startswith(".env.")
           for name in files for part in name.split("/")):
        raise RuntimeError("An env file or tests were included in the bundle.")
    if any(name == "tests" or name.startswith(("tests.", "Crypto.SelfTest")) for name in modules):
        raise RuntimeError("Test modules were included in the bundle.")


def isolated_environment(directory: Path) -> dict[str, str]:
    # No inherited credentials, Python paths, proxy settings, or vault config.
    environment = {
        key: os.environ[key] for key in ("SystemRoot", "WINDIR", "COMSPEC")
        if key in os.environ
    }
    environment.update({
        "PATH": str(directory),
        "HOME": str(directory),
        "USERPROFILE": str(directory),
        "APPDATA": str(directory),
        "LOCALAPPDATA": str(directory),
        "XDG_CONFIG_HOME": str(directory),
        "XDG_DATA_HOME": str(directory),
        "TMPDIR": str(directory),
        "TMP": str(directory),
        "TEMP": str(directory),
        "PYTHON_KEYRING_BACKEND": "keyring.backends.fail.Keyring",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    })
    return environment


def smoke(executable: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="icourse-frozen-") as temp:
        directory = Path(temp)
        environment = isolated_environment(directory)
        cases = [
            (arguments + ["--help"], 0, "usage: icourse-dl")
            for arguments in ([], ["login"], ["search"], ["search", "courses"],
                              ["search", "lectures"], ["download"])
        ]
        cases.extend([
            (["--version"], 0, version("icourse-dl")),
            (["not-a-command"], 2, "invalid choice"),
            (["download", "offline-smoke"], 2,
             "Noninteractive download requires --course-id and --lecture-id."),
            (["search", "courses", "offline-smoke", "--env", str(directory / "missing.env")],
             2, "Cannot read the explicit UTF-8 credentials file."),
            (["login"], 6, "A trusted system credential store is unavailable."),
            (["search", "courses", "offline-smoke"], 6,
             "A trusted system credential store is unavailable."),
            (["search", "lectures", "--course-id", "1"], 6,
             "A trusted system credential store is unavailable."),
            (["download", "--course-id", "1", "--lecture-id", "1"], 6,
             "A trusted system credential store is unavailable."),
        ])
        for arguments, expected_code, expected_text in cases:
            result = subprocess.run(
                [str(executable), *arguments], cwd=directory, env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", timeout=90, check=False,
            )
            output = result.stdout + result.stderr
            if result.returncode != expected_code or expected_text not in output:
                # Do not dump subprocess output: diagnostics must not expose secrets.
                raise RuntimeError(
                    f"Frozen smoke case {arguments[0]} failed: exit {result.returncode}, "
                    f"expected {expected_code}; expected message present={expected_text in output}."
                )
            if "Traceback (most recent call last)" in output or "Internal failure" in output:
                raise RuntimeError("Frozen smoke reported an import or internal failure.")
    print("Frozen archive and offline public CLI smoke passed (no native vault access).")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    arguments = parser.parse_args()
    executable = arguments.executable.resolve(strict=True)
    if sys.platform not in {"win32", "darwin"}:
        parser.error("Frozen verification supports native Windows and macOS only.")
    inspect_bundle(executable)
    smoke(executable)


if __name__ == "__main__":
    main()
