# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic vaults only: no real keyring, filesystem secrets, or school I/O."""
from collections import defaultdict, deque
import json
from types import SimpleNamespace

import pytest

from icourse_dl.auth import Credentials
from icourse_dl import credentials as storage


SECRET = "synthetic-secret-must-not-appear"
OLD = Credentials("synthetic-old", "old-" + SECRET, "prompt")
NEW = Credentials("synthetic-new", "new-" + SECRET, "prompt")
KEY = (storage.SERVICE, storage.ACCOUNT_KEY)


class FakeVault:
    def __init__(self):
        self.records = {}
        self.calls = []
        self.actions = defaultdict(deque)

    def perform(self, operation, service, account, value=None):
        key = service, account
        self.calls.append((operation, key, value))
        if self.actions[operation]:
            action = self.actions[operation].popleft()
            if isinstance(action, BaseException):
                raise action
            if action is not None:
                return action(key, value)
        if operation == "get":
            return self.records.get(key)
        if operation == "set":
            self.records[key] = value
        if operation == "delete":
            self.records.pop(key, None)

    def get_password(self, service, account):
        return self.perform("get", service, account)

    def _set_password(self, service, account, value):
        return self.perform("set", service, account, value)

    def set_password(self, service, account, value):
        raise AssertionError("Windows backup-producing public setter must not be used")

    def delete_password(self, service, account):
        return self.perform("delete", service, account)


class WinVaultKeyring(FakeVault):
    pass


WinVaultKeyring.__module__ = "keyring.backends.Windows"


def select(monkeypatch, backend, *, platform="win32", module=None):
    monkeypatch.setattr(storage, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(storage.keyring, "get_keyring", lambda: backend)
    if module is None:
        module = SimpleNamespace(WinVaultKeyring=WinVaultKeyring)
    monkeypatch.setattr(storage, "import_module", lambda name: module)
    return storage.CredentialStore()


@pytest.fixture
def vault(monkeypatch):
    backend = WinVaultKeyring()
    return select(monkeypatch, backend), backend


def assert_safe(exc):
    text = str(exc.value)
    assert SECRET not in text
    assert OLD.account not in text
    assert NEW.account not in text
    assert exc.value.exit_code == 6
    assert exc.value.__suppress_context__ or exc.value.__context__ is None


def test_load_absent_is_read_only_and_tool_scoped(vault):
    store, backend = vault
    assert store.load() is None
    assert backend.calls == [("get", KEY, None)]


def test_round_trip_preserves_password_and_only_stores_one_secret(vault):
    store, backend = vault
    credentials = Credentials("synthetic-account", "  密碼 \n" + SECRET, "prompt")
    store.save(credentials)
    assert store.load() == Credentials(credentials.account, credentials.password, "keyring")
    assert set(backend.records) == {KEY}
    assert json.loads(backend.records[KEY]) == {
        "version": 1, "school": "fudan", "account": credentials.account,
        "password": credentials.password,
    }
    assert credentials.account not in storage.SERVICE + storage.ACCOUNT_KEY


@pytest.mark.parametrize("module,name", [
    ("keyring.backends.fail", "Keyring"),
    ("keyring.backends.null", "Keyring"),
    ("keyrings.alt.file", "PlaintextKeyring"),
    ("keyring.backends.chainer", "ChainerBackend"),
    ("unverified_backend", "Keyring"),
])
def test_rejects_untrusted_backends_without_access(monkeypatch, module, name):
    cls = type(name, (FakeVault,), {"__module__": module})
    backend = cls()
    with pytest.raises(storage.StorageFailure) as exc:
        select(monkeypatch, backend)
    assert_safe(exc)
    assert not backend.calls
    assert "Plaintext" in str(exc.value)


def test_rejects_native_subclass_and_spoofed_class(monkeypatch):
    class Child(WinVaultKeyring):
        pass

    for backend in [Child(), type("WinVaultKeyring", (FakeVault,), {
        "__module__": "keyring.backends.Windows",
    })()]:
        with pytest.raises(storage.StorageFailure):
            select(monkeypatch, backend)
        assert not backend.calls


def test_selection_failure_is_safe_and_explains_linux_wsl(monkeypatch):
    def fail():
        raise RuntimeError(SECRET)

    monkeypatch.setattr(storage.keyring, "get_keyring", fail)
    with pytest.raises(storage.StorageFailure) as exc:
        storage.CredentialStore()
    assert_safe(exc)
    assert "Linux/WSL" in str(exc.value)
    assert "explicit credentials file" in str(exc.value)


@pytest.mark.parametrize("raw", [
    "", SECRET, "[]", "null", "{}", "[" * 2000,
    json.dumps({"version": True, "school": "fudan", "account": "a", "password": SECRET}),
    json.dumps({"version": 2, "school": "fudan", "account": "a", "password": SECRET}),
    json.dumps({"version": 1, "school": "other", "account": "a", "password": SECRET}),
    json.dumps({"version": 1, "school": "fudan", "account": 7, "password": SECRET}),
    json.dumps({"version": 1, "school": "fudan", "account": " a ", "password": SECRET}),
    json.dumps({"version": 1, "school": "fudan", "account": "", "password": SECRET}),
    json.dumps({"version": 1, "school": "fudan", "account": "a", "password": None}),
    json.dumps({"version": 1, "school": "fudan", "account": "a", "password": ""}),
    json.dumps({"version": 1, "school": "fudan", "account": "a", "password": SECRET, "extra": 1}),
    '{"version":1,"version":1,"school":"fudan","account":"a","password":"p"}',
    "x" * (storage.MAX_RECORD_BYTES + 1),
    '{"version":1,"school":"fudan","account":"a","password":"\\ud800"}',
    17,
])
def test_corruption_is_safe_read_only_and_not_overwritten(vault, raw):
    store, backend = vault
    backend.records[KEY] = raw
    with pytest.raises(storage.StorageFailure) as exc:
        store.load()
    assert_safe(exc)
    with pytest.raises(storage.StorageFailure):
        store.save(NEW)
    assert backend.records[KEY] == raw
    assert all(call[0] == "get" for call in backend.calls)


def test_encoded_record_size_is_bounded(vault):
    store, backend = vault
    backend.records[KEY] = json.dumps({
        "version": 1, "school": "fudan", "account": "a", "password": "密" * 6000,
    }, ensure_ascii=False)
    assert len(backend.records[KEY]) < storage.MAX_RECORD_BYTES
    with pytest.raises(storage.StorageFailure):
        store.load()


def test_windows_byte_capacity_is_checked_before_vault_access(vault):
    store, backend = vault
    with pytest.raises(storage.StorageFailure) as exc:
        store.save(Credentials("a", "😀" * 700, "prompt"))
    assert "byte capacity" in str(exc.value)
    assert not backend.calls


def test_preflight_round_trip_preserves_existing_record(vault):
    store, backend = vault
    backend.records[KEY] = storage._record(OLD)
    store.check_writable()
    assert backend.records == {KEY: storage._record(OLD)}
    assert [call[0] for call in backend.calls] == ["get", "set", "get", "delete", "get"]
    assert all(key != KEY for _, key, _ in backend.calls)
    assert all(SECRET not in str(value) for _, _, value in backend.calls)


def test_preflight_collision_is_not_deleted(vault):
    store, backend = vault
    backend.actions["get"].append(lambda key, value: "already-present")
    with pytest.raises(storage.StorageFailure):
        store.check_writable()
    assert [call[0] for call in backend.calls] == ["get"]


@pytest.mark.parametrize("operation", ["get", "set", "delete"])
def test_preflight_locked_denied_and_cleanup_failures_are_safe(vault, operation):
    store, backend = vault
    backend.actions[operation].append(RuntimeError(SECRET))
    with pytest.raises(storage.StorageFailure) as exc:
        store.check_writable()
    assert_safe(exc)
    assert KEY not in backend.records
    if operation == "delete":
        assert "deletion" in str(exc.value)
        assert "harmless" in str(exc.value)
        assert len(backend.records) == 1
    else:
        assert not backend.records


def test_preflight_wrong_readback_cleans_up(vault):
    store, backend = vault
    backend.actions["get"].extend([None, lambda key, value: "wrong"])
    with pytest.raises(storage.StorageFailure) as exc:
        store.check_writable()
    assert "removed" in str(exc.value)
    assert not backend.records


def test_preflight_interruption_still_cleans_up(vault):
    store, backend = vault
    backend.actions["get"].extend([None, KeyboardInterrupt()])
    with pytest.raises(KeyboardInterrupt):
        store.check_writable()
    assert not backend.records


def test_read_failure_does_not_write_or_disclose(vault):
    store, backend = vault
    backend.actions["get"].append(RuntimeError(SECRET))
    with pytest.raises(storage.StorageFailure) as exc:
        store.load()
    assert_safe(exc)
    assert len(backend.calls) == 1


@pytest.mark.parametrize("existing", [None, OLD])
def test_failed_write_restores_verified_previous_state(vault, existing):
    store, backend = vault
    if existing:
        backend.records[KEY] = storage._record(existing)
    previous = dict(backend.records)

    def partial_failure(key, value):
        backend.records[key] = value
        raise RuntimeError(SECRET)

    backend.actions["set"].append(partial_failure)
    with pytest.raises(storage.StorageFailure) as exc:
        store.save(NEW)
    assert_safe(exc)
    assert "restored and verified" in str(exc.value)
    assert backend.records == previous


def test_readback_failure_restores_existing_secret(vault):
    store, backend = vault
    backend.records[KEY] = storage._record(OLD)
    backend.actions["get"].extend([None, RuntimeError(SECRET)])
    with pytest.raises(storage.StorageFailure) as exc:
        store.save(NEW)
    assert_safe(exc)
    assert backend.records[KEY] == storage._record(OLD)


def test_failed_rollback_reports_uncertain_state_without_leaks(vault):
    store, backend = vault
    backend.records[KEY] = storage._record(OLD)
    backend.actions["get"].extend([None, RuntimeError(SECRET)])
    backend.actions["set"].extend([None, RuntimeError(SECRET)])
    with pytest.raises(storage.StorageFailure) as exc:
        store.save(NEW)
    assert_safe(exc)
    assert "may have changed" in str(exc.value)
    assert backend.records[KEY] == storage._record(NEW)


def test_rollback_failure_after_successful_restoration_uses_readback(vault):
    store, backend = vault
    backend.records[KEY] = storage._record(OLD)

    def failing_write(key, value):
        backend.records[key] = value
        raise RuntimeError(SECRET)

    backend.actions["set"].extend([failing_write, failing_write])
    with pytest.raises(storage.StorageFailure) as exc:
        store.save(NEW)
    assert "restored and verified" in str(exc.value)
    assert backend.records[KEY] == storage._record(OLD)


def test_save_interruption_restores_prior_record(vault):
    store, backend = vault
    backend.records[KEY] = storage._record(OLD)
    backend.actions["get"].extend([None, KeyboardInterrupt()])
    with pytest.raises(KeyboardInterrupt):
        store.save(NEW)
    assert backend.records[KEY] == storage._record(OLD)


def test_clear_is_idempotent_and_can_remove_corruption(vault):
    store, backend = vault
    backend.records[KEY] = "malformed-" + SECRET
    backend.records[("unrelated", "account")] = "keep"
    store.clear()
    store.clear()
    assert backend.records == {("unrelated", "account"): "keep"}
    assert all(key == KEY for _, key, _ in backend.calls)


def test_clear_denial_reports_that_credentials_may_remain(vault):
    store, backend = vault
    backend.records[KEY] = storage._record(OLD)
    backend.actions["delete"].append(RuntimeError(SECRET))
    with pytest.raises(storage.StorageFailure) as exc:
        store.clear()
    assert_safe(exc)
    assert "may remain" in str(exc.value)
    assert KEY in backend.records


def test_clear_checks_state_when_backend_raises_after_deletion(vault):
    store, backend = vault
    backend.records[KEY] = storage._record(OLD)

    def delete_then_raise(key, value):
        del backend.records[key]
        raise RuntimeError(SECRET)

    backend.actions["delete"].append(delete_then_raise)
    store.clear()
    assert not backend.records


def test_macos_uses_native_password_methods(monkeypatch):
    class Keyring(FakeVault):
        def set_password(self, service, account, value):
            return self.perform("set", service, account, value)

    Keyring.__module__ = "keyring.backends.macOS"
    backend = Keyring()
    store = select(monkeypatch, backend, platform="darwin", module=SimpleNamespace(Keyring=Keyring))
    store.save(NEW)
    assert store.load() == Credentials(NEW.account, NEW.password, "keyring")
    store.clear()
    assert not backend.records


def test_secretservice_never_creates_collections_or_enumerates(monkeypatch):
    records = {}
    searches = []
    connections = []

    class Connection:
        def __init__(self):
            self.closed = False
            connections.append(self)

        def close(self):
            self.closed = True

    class Item:
        def __init__(self, key):
            self.key = key

        def get_secret(self):
            return records[self.key]

        def delete(self):
            del records[self.key]

    class Collection:
        def __init__(self, connection, path):
            assert path == "/org/freedesktop/secrets/aliases/default"

        def search_items(self, query):
            searches.append(query)
            key = query["service"], query["username"]
            return [Item(key)] if key in records else []

        def create_item(self, label, attributes, value, replace):
            assert label == "icourse-dl credentials"
            assert replace is True
            records[(attributes["service"], attributes["username"])] = value

    class Keyring:
        def _query(self, service, username, **extra):
            return {"service": service, "username": username, **extra}

        def unlock(self, item):
            pass

    Keyring.__module__ = "keyring.backends.SecretService"
    module = SimpleNamespace(
        Keyring=Keyring,
        secretstorage=SimpleNamespace(dbus_init=Connection, Collection=Collection),
    )
    store = select(monkeypatch, Keyring(), platform="linux", module=module)
    assert store.load() is None
    assert not records
    store.save(NEW)
    assert store.load() == Credentials(NEW.account, NEW.password, "keyring")
    store.clear()
    assert not records
    assert all(query == {"service": KEY[0], "username": KEY[1]} for query in searches)
    assert all(connection.closed for connection in connections)


def test_kwallet_avoids_legacy_migration_and_checks_native_return_codes(monkeypatch):
    records = {}
    folders = set()

    class Wallet:
        write_result = 0
        is_open = True

        def networkWallet(self):
            return "synthetic-wallet"

        def folderDoesNotExist(self, wallet, folder):
            return folder not in folders

        def open(self, wallet, window, appid):
            return 7

        def hasFolder(self, handle, folder, appid):
            return folder in folders

        def createFolder(self, handle, folder, appid):
            folders.add(folder)
            return True

        def hasEntry(self, handle, folder, account, appid):
            return (folder, account) in records

        def readPassword(self, handle, folder, account, appid):
            return records[folder, account]

        def writePassword(self, handle, folder, account, value, appid):
            if not self.write_result:
                records[folder, account] = value
            return self.write_result

        def isOpen(self, wallet):
            return self.is_open

        def removeEntry(self, handle, folder, account, appid):
            records.pop((folder, account), None)
            return 0

    class DBusKeyring:
        bus_name = "synthetic-bus"
        object_path = "/synthetic"
        appid = "synthetic-tool"

        def connected(self, service):
            raise AssertionError("Legacy migration must not run")

    DBusKeyring.__module__ = "keyring.backends.kwallet"
    wallet = Wallet()
    module = SimpleNamespace(
        DBusKeyring=DBusKeyring,
        DBusGMainLoop=lambda: None,
        dbus=SimpleNamespace(
            SessionBus=lambda **kwargs: SimpleNamespace(get_object=lambda *args: object()),
            Interface=lambda *args: wallet,
        ),
    )
    store = select(monkeypatch, DBusKeyring(), platform="linux", module=module)
    assert store.load() is None
    assert not records and not folders
    store.save(OLD)
    assert store.load() == Credentials(OLD.account, OLD.password, "keyring")
    wallet.write_result = -1
    with pytest.raises(storage.StorageFailure) as exc:
        store.save(NEW)
    assert "restored and verified" in str(exc.value)
    assert records[KEY] == storage._record(OLD)
    store.clear()
    assert not records
    wallet.is_open = False
    with pytest.raises(storage.StorageFailure) as exc:
        store.load()
    assert "Unlock" in str(exc.value)


def test_no_plaintext_file_writes_or_fallback(vault, monkeypatch):
    store, backend = vault

    def forbid_file(*args, **kwargs):
        raise AssertionError("Credential operations must not write plaintext files")

    with monkeypatch.context() as context:
        context.setattr("builtins.open", forbid_file)
        context.setattr("io.open", forbid_file)
        store.check_writable()
        store.save(OLD)
        assert store.load() == Credentials(OLD.account, OLD.password, "keyring")
        backend.actions["set"].append(RuntimeError(SECRET))
        with pytest.raises(storage.StorageFailure):
            store.save(NEW)
        store.clear()
    assert not backend.records
