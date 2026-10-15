# SPDX-License-Identifier: GPL-3.0-or-later
"""Tool-scoped credentials in an explicitly trusted operating-system vault.

Only the fixed secret record is read; no account names are vault metadata.
Backend-specific access avoids keyring's legacy KWallet migration, automatic
SecretService collection creation, and WinVault's extra backup credentials.
No backend settings are changed and no plaintext fallback is provided.
"""
from contextlib import closing
from importlib import import_module
import json
import secrets
import sys

import keyring

from .auth import Credentials
from .errors import ICourseError


SERVICE = "icourse-dl.credentials"
ACCOUNT_KEY = "fudan.credentials.v1"
MAX_RECORD_BYTES = 16_384
WINDOWS_MAX_BYTES = 2_560
_TRUSTED = {
    "win32": {("keyring.backends.Windows", "WinVaultKeyring"): "windows"},
    "darwin": {("keyring.backends.macOS", "Keyring"): "macos"},
    "linux": {
        ("keyring.backends.SecretService", "Keyring"): "secretservice",
        ("keyring.backends.kwallet", "DBusKeyring"): "kwallet",
        ("keyring.backends.kwallet", "DBusKeyringKWallet4"): "kwallet",
    },
}
_UNAVAILABLE = (
    "A trusted system credential store is unavailable. Use Windows Credential "
    "Manager, macOS Keychain, or an existing Linux/WSL Secret Service or KWallet "
    "session; alternatively supply an explicit credentials file. Plaintext, "
    "chained, and third-party keyring backends are not accepted."
)
_ACCESS_FAILED = (
    "The system credential store could not be accessed. Unlock it and allow "
    "access, or supply an explicit credentials file."
)


class StorageFailure(ICourseError):
    exit_code = 6


def _record(credentials: Credentials) -> str:
    raw = json.dumps(
        {"version": 1, "school": "fudan", "account": credentials.account,
         "password": credentials.password},
        ensure_ascii=False, separators=(",", ":"),
    )
    _decode(raw)
    return raw


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def _decode(raw: str) -> Credentials:
    try:
        if type(raw) is not str or len(raw) > MAX_RECORD_BYTES:
            raise ValueError
        if len(raw.encode("utf-8")) > MAX_RECORD_BYTES:
            raise ValueError
        record = json.loads(raw, object_pairs_hook=_unique_object)
        if type(record) is not dict or set(record) != {
            "version", "school", "account", "password"
        }:
            raise ValueError
        if type(record["version"]) is not int or record["version"] != 1:
            raise ValueError
        if record["school"] != "fudan":
            raise ValueError
        account, password = record["account"], record["password"]
        if (type(account) is not str or not account or account != account.strip()
                or type(password) is not str or not password):
            raise ValueError
        account.encode("utf-8")
        password.encode("utf-8")
        return Credentials(account, password, "keyring")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise StorageFailure(
            "The stored credentials are malformed, oversized, or use an unsupported "
            "format. They were not changed; clear them explicitly before saving again."
        ) from None


class CredentialStore:
    """Use the selected exact native backend, never a subclass or a chainer.

    Updates are read back and failures trigger best-effort restoration. OS vaults
    provide no cross-process compare-and-swap: concurrent writers are unsupported.
    Neither construction nor load writes a credential or creates a collection.
    """

    def __init__(self) -> None:
        try:
            backend = keyring.get_keyring()
            cls = type(backend)
            name = (cls.__module__, cls.__name__)
            kind = _TRUSTED.get(sys.platform, {}).get(name)
            if kind is None:
                raise ValueError
            module = import_module(name[0])
            if cls is not getattr(module, name[1]):
                raise ValueError
            self._backend = backend
            self._module = module
            self._kind = kind
        except Exception:
            raise StorageFailure(_UNAVAILABLE) from None

    def _kwallet(self, operation: str, service: str, account: str, value=None):
        # Do not call connected(): it migrates unrelated legacy Python entries.
        backend, module = self._backend, self._module
        bus = module.dbus.SessionBus(mainloop=module.DBusGMainLoop())
        remote = bus.get_object(backend.bus_name, backend.object_path)
        iface = module.dbus.Interface(remote, "org.kde.KWallet")
        wallet = iface.networkWallet()
        # Opening a missing wallet can create it. Require an existing unlocked
        # wallet instead; users can unlock it in their desktop before retrying.
        if not iface.isOpen(wallet):
            raise StorageFailure(_ACCESS_FAILED)
        # This targeted query neither opens/creates a wallet nor enumerates items.
        # An absent folder implies an absent record for a read/delete operation.
        if operation != "set" and iface.folderDoesNotExist(wallet, service):
            return None
        handle = iface.open(wallet, 0, backend.appid)
        if handle < 0:
            raise StorageFailure(_ACCESS_FAILED)
        if operation == "get":
            if not iface.hasEntry(handle, service, account, backend.appid):
                return None
            return str(iface.readPassword(handle, service, account, backend.appid))
        if operation == "set":
            if not iface.hasFolder(handle, service, backend.appid):
                if not iface.createFolder(handle, service, backend.appid):
                    raise StorageFailure(_ACCESS_FAILED)
            if iface.writePassword(handle, service, account, value, backend.appid) != 0:
                raise StorageFailure(_ACCESS_FAILED)
        elif iface.hasEntry(handle, service, account, backend.appid):
            if iface.removeEntry(handle, service, account, backend.appid) != 0:
                raise StorageFailure(_ACCESS_FAILED)
        return None

    def _secretservice(self, operation: str, service: str, account: str, value=None):
        backend, storage = self._backend, self._module.secretstorage
        with closing(storage.dbus_init()) as connection:
            # get_default_collection() can create a collection even during load.
            collection = storage.Collection(
                connection, getattr(backend, "preferred_collection",
                                    "/org/freedesktop/secrets/aliases/default")
            )
            backend.unlock(collection)
            query = backend._query(service, account)
            if operation == "set":
                collection.create_item(
                    "icourse-dl credentials",
                    backend._query(service, account, application="icourse-dl"),
                    value.encode("utf-8"), replace=True,
                )
                return None
            for item in collection.search_items(query):
                backend.unlock(item)
                if operation == "get":
                    return item.get_secret().decode("utf-8")
                item.delete()
            return None

    def _access(self, operation: str, service: str, account: str, value=None):
        if self._kind == "kwallet":
            return self._kwallet(operation, service, account, value)
        if self._kind == "secretservice":
            return self._secretservice(operation, service, account, value)
        if operation == "set":
            if self._kind == "windows":
                # Public set_password silently copies the old secret to a second
                # compound target. Our single fixed target must not leave backups.
                return self._backend._set_password(service, account, value)
            return self._backend.set_password(service, account, value)
        if operation == "get":
            return self._backend.get_password(service, account)
        return self._backend.delete_password(service, account)

    def _delete_verified(self, service: str, account: str) -> None:
        try:
            self._access("delete", service, account)
        except Exception:
            # A backend may report an absent item, or fail after deleting it.
            # The observed final state, not the backend's message, is decisive.
            pass
        if self._access("get", service, account) is not None:
            raise StorageFailure("Credential deletion could not be verified.")

    def check_writable(self) -> None:
        """Round-trip harmless random data, then verify cleanup, before login.

        A distinct random service prevents WinVault service-name collisions.
        A failed cleanup can leave only this harmless probe, never credentials.
        """
        suffix = secrets.token_hex(16)
        service = SERVICE + ".probe." + suffix if self._kind == "windows" else SERVICE
        account = ACCOUNT_KEY if self._kind == "windows" else "probe." + suffix
        value = secrets.token_hex(32)
        try:
            if self._access("get", service, account) is not None:
                raise StorageFailure("The credential-store probe could not be created safely.")
        except Exception:
            raise StorageFailure(_ACCESS_FAILED) from None
        failure = None
        try:
            self._access("set", service, account, value)
            if self._access("get", service, account) != value:
                raise StorageFailure("Credential-store probe readback failed.")
        except (Exception, KeyboardInterrupt) as exc:
            failure = exc
        try:
            self._delete_verified(service, account)
        except (Exception, KeyboardInterrupt):
            raise StorageFailure(
                "Credential-store preflight failed: deletion of the harmless test "
                "record could not be verified. No login credentials were stored."
            ) from None
        if isinstance(failure, KeyboardInterrupt):
            raise KeyboardInterrupt from None
        if failure is not None:
            raise StorageFailure(
                "The credential store failed its write/read check. The harmless "
                "test record was removed; no login credentials were stored. "
                "Unlock the store and allow access, or use an explicit credentials file."
            ) from None

    def load(self) -> Credentials | None:
        try:
            raw = self._access("get", SERVICE, ACCOUNT_KEY)
        except Exception:
            raise StorageFailure(_ACCESS_FAILED) from None
        return None if raw is None else _decode(raw)

    def _restore(self, previous: str | None) -> bool:
        try:
            if self._access("get", SERVICE, ACCOUNT_KEY) == previous:
                return True
        except Exception:
            pass
        try:
            if previous is None:
                self._delete_verified(SERVICE, ACCOUNT_KEY)
            else:
                self._access("set", SERVICE, ACCOUNT_KEY, previous)
        except (Exception, KeyboardInterrupt):
            pass
        try:
            return self._access("get", SERVICE, ACCOUNT_KEY) == previous
        except (Exception, KeyboardInterrupt):
            return False

    def save(self, credentials: Credentials) -> None:
        """Persist only credentials whose identity the caller already verified."""
        try:
            raw = _record(credentials)
            if self._kind == "windows" and len(raw.encode("utf-16-le")) > WINDOWS_MAX_BYTES:
                raise StorageFailure(
                    "The credentials exceed Windows Credential Manager's byte capacity. "
                    "Existing credentials were not changed."
                )
        except StorageFailure:
            raise
        except Exception:
            raise StorageFailure("The credentials cannot be stored in the supported format.") from None
        try:
            previous = self._access("get", SERVICE, ACCOUNT_KEY)
        except Exception:
            raise StorageFailure(_ACCESS_FAILED) from None
        if previous is not None:
            _decode(previous)  # Never overwrite corrupt or unsupported data implicitly.
        try:
            self._access("set", SERVICE, ACCOUNT_KEY, raw)
            if self._access("get", SERVICE, ACCOUNT_KEY) != raw:
                raise StorageFailure("Credential readback failed.")
        except (Exception, KeyboardInterrupt) as exc:
            restored = self._restore(previous)
            if not restored:
                raise StorageFailure(
                    "Saving credentials failed and the previous state could not be "
                    "verified or restored. The credential store may have changed; "
                    "inspect or clear this tool's credentials before retrying."
                ) from None
            if isinstance(exc, KeyboardInterrupt):
                raise KeyboardInterrupt from None
            raise StorageFailure(
                "Saving credentials failed. The previous credential-store state "
                "was restored and verified."
            ) from None

    def clear(self) -> None:
        """Delete only this tool's record; absence is already success."""
        try:
            if self._access("get", SERVICE, ACCOUNT_KEY) is None:
                return
            self._delete_verified(SERVICE, ACCOUNT_KEY)
        except Exception:
            raise StorageFailure(
                "Credential deletion could not be verified. The tool's credentials "
                "may remain in the system store; unlock it and allow deletion."
            ) from None
