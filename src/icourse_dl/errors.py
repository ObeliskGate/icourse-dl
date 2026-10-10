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

class StorageFailure(ICourseError):
    exit_code = 6

class NetworkUnavailable(ICourseError):
    exit_code = 7

class ProtocolError(ICourseError):
    exit_code = 8
