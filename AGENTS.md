# Project instructions

## Scope

- This is a standalone Python 3.12+ CLI for authorized Fudan iCourse downloads, licensed GPL-3.0-or-later.
- Public commands are `login`, `search courses`, `search lectures`, and `download`.
- `cli.py` handles arguments, `auth.py` handles WebVPN/iCourse authentication, `credentials.py` handles system keyring storage, `client.py` handles course APIs, `interaction.py` handles keyboard selection, and `download.py` uses yt-dlp for transfers.

## Formatting

- Use ASCII punctuation in all project-authored documentation, comments, messages, and examples, including Chinese text. Use `. `, `, `, `: `, `; `, ASCII parentheses, and straight quotes. Do not use full-width punctuation or typographic quotes/dashes.
- Verbatim quotations are exempt: preserve the original text and punctuation. Never normalize punctuation inside quoted source material.
- Use spaces after sentence punctuation when another sentence or clause follows. Do not add trailing whitespace at line endings.
- Preserve Chinese words. Do not normalize punctuation in external school responses, user credentials, URLs, or downloaded content. To test non-ASCII punctuation as input, use Unicode escapes and preserve the original test semantics.
- Keep README usage concise. Use `sh` fences for portable command examples.

## Development and verification

- Use uv and the project environment, not a global environment.
- Install locked dependencies: `uv sync --locked`.
- Run the CLI: `uv run icourse-dl --help`.
- Run offline tests: `uv run --locked pytest -q`.
- Exercise actual transfers against a local synthetic HTTP server: `uv run --locked python tests/smoke_download.py`.
- Build a wheel: `uv build --wheel`.
- Build native single-file executables on Windows or macOS: `uv run --locked --no-dev --group build pyinstaller --noconfirm --clean --distpath dist/executable --workpath build/pyinstaller icourse-dl.spec`.
- Keep `icourse-dl.spec` in source control. Build outputs belong in ignored `build/` and `dist/` directories.
- `.github/workflows/tests.yml` runs offline tests and wheel installation checks. `build.yml` builds and verifies native executables.

## Security and behavior

- Never use real school credentials or native credential-store writes in automated tests. Use synthetic HTTP responses, fake stores, and temporary directories.
- Never print or commit passwords, cookies, tickets, signed media URLs, full authentication responses, or credential files.
- Only an explicit `--env` reads `./.env`; `--env PATH` reads the specified file. Read complete `StuId`/`UISPsw` pairs without interpolation or process-environment supplementation.
- `login` verifies and saves credentials to a supported system keyring. No plaintext storage fallback and no persistent cookie sessions. Search/download do not save credentials.
- Preserve school authorization, course membership, and playback-opening checks. Do not recover hidden addresses from refused responses.
- Keep default output concise. `--verbose` enables sanitized authentication diagnostics only, not HTTP-library debug logging.
- Do not overwrite existing completed downloads by default. Preserve resumable parts and delegate transfer/resume behavior to yt-dlp.
- Do not push, create public repositories, or publish releases without explicit user authorization.
