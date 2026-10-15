# SPDX-License-Identifier: GPL-3.0-or-later
import pytest


@pytest.fixture
def saved_credentials(monkeypatch):
    """Never access the operating-system keyring in CLI tests."""
    from icourse_dl import credentials

    class MemoryStore:
        value = None

        def __init__(self):
            self.writes = 0
            self.checked = False

        def check_writable(self):
            self.checked = True

        def load(self):
            return self.value

        def save(self, value):
            self.value = value
            self.writes += 1

        def clear(self):
            self.value = None

    store = MemoryStore()
    monkeypatch.setattr(credentials, 'CredentialStore', lambda: store)
    return store
