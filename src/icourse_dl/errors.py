# SPDX-License-Identifier: GPL-3.0-or-later
class ICourseError(Exception):
    exit_code = 1

class ConfigurationError(ICourseError):
    exit_code = 2

class AuthenticationError(ICourseError):
    exit_code = 3

class PermissionDenied(ICourseError):
    exit_code = 4

class DownloadFailure(ICourseError):
    exit_code = 5

class NetworkUnavailable(ICourseError):
    exit_code = 7

    def __init__(self, message: str, *, retryable: bool = False,
                 reason: str = "request-failed", method: str | None = None,
                 status: int | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.reason = reason
        self.method = method
        self.status = status

class ProtocolError(ICourseError):
    exit_code = 8
