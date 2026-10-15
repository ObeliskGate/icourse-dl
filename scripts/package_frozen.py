# SPDX-License-Identifier: GPL-3.0-or-later
"""Package only the native executable and root LICENSE, plus an archive SHA256."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import platform
import stat
import sys
import tarfile
import zipfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--platform", required=True, choices=("Windows", "macOS"))
    parser.add_argument("--arch", required=True, choices=("X64", "ARM64"))
    parser.add_argument("--output", type=Path, default=Path("dist/packages"))
    arguments = parser.parse_args()
    native_platform = {"win32": "Windows", "darwin": "macOS"}.get(sys.platform)
    native_arch = {"amd64": "X64", "x86_64": "X64", "arm64": "ARM64", "aarch64": "ARM64"}.get(
        platform.machine().lower()
    )
    if (arguments.platform, arguments.arch) != (native_platform, native_arch):
        parser.error("Archive labels must match the native build interpreter's platform and architecture.")
    executable = arguments.executable.resolve(strict=True)
    expected_name = "icourse-dl.exe" if sys.platform == "win32" else "icourse-dl"
    if not executable.is_file() or executable.name != expected_name:
        parser.error(f"Expected the onefile executable named {expected_name}.")
    if sys.platform == "darwin" and not executable.stat().st_mode & stat.S_IXUSR:
        parser.error("The macOS executable has lost its executable permission.")
    license_file = Path(__file__).resolve().parents[1] / "LICENSE"
    if not license_file.is_file():
        parser.error("The root LICENSE is required.")
    name = f"icourse-dl-{arguments.platform}-{arguments.arch}"
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    members = [(executable, f"{name}/{expected_name}"), (license_file, f"{name}/LICENSE")]
    if sys.platform == "win32":
        archive = output / f"{name}.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for source, destination in members:
                bundle.write(source, destination)
    else:
        archive = output / f"{name}.tar.gz"
        # tar preserves the executable mode; artifact upload never sees a bare binary.
        with tarfile.open(archive, "w:gz") as bundle:
            for source, destination in members:
                bundle.add(source, arcname=destination, recursive=False)
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    checksum = archive.with_name(archive.name + ".sha256")
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    print(f"Created {archive.name} and {checksum.name}.")


if __name__ == "__main__":
    main()
