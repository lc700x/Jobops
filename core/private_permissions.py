"""Enforce owner-only storage permissions across supported host platforms."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from functools import lru_cache
from pathlib import Path
from typing import Any


_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x1
_DACL_SECURITY_INFORMATION = 0x4
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_SDDL_REVISION_1 = 1
_WINDOWS_SYSTEM_SID = "SY"
_SE_DACL_PROTECTED = 0x1000
_ACL_SIZE_INFORMATION = 2
_ACCESS_ALLOWED_ACE_TYPE = 0
_GENERIC_ALL = 0x10000000
_FILE_ALL_ACCESS = 0x001F01FF
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_INHERITED_ACE = 0x10


class PrivatePermissionError(PermissionError):
    """Raised when private storage cannot be secured to the current user."""


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("AceType", wintypes.BYTE),
        ("AceFlags", wintypes.BYTE),
        ("AceSize", wintypes.WORD),
    ]


class _AccessAllowedAce(ctypes.Structure):
    _fields_ = [
        ("Header", _AceHeader),
        ("Mask", wintypes.DWORD),
        ("SidStart", wintypes.DWORD),
    ]


@lru_cache(maxsize=1)
def _windows_api() -> tuple[Any, Any]:
    if os.name != "nt":
        raise PrivatePermissionError("Windows ACL APIs are unavailable")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    kernel32.OpenProcessToken.restype = wintypes.BOOL
    kernel32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetTokenInformation.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    return kernel32, advapi32


def _sid_to_string(sid: ctypes.c_void_p) -> str:
    kernel32, advapi32 = _windows_api()
    value = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(value)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not value.value:
            raise PrivatePermissionError("Windows returned an empty user SID")
        return value.value
    finally:
        kernel32.LocalFree(ctypes.cast(value, ctypes.c_void_p))


@lru_cache(maxsize=1)
def _current_user_sid() -> str:
    kernel32, _ = _windows_api()
    token = wintypes.HANDLE()
    if not kernel32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        required = wintypes.DWORD()
        kernel32.GetTokenInformation(
            token, _TOKEN_USER, None, 0, ctypes.byref(required)
        )
        if required.value == 0:
            raise PrivatePermissionError("Could not read the current Windows user")
        buffer = ctypes.create_string_buffer(required.value)
        if not kernel32.GetTokenInformation(
            token,
            _TOKEN_USER,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
        if not user.User.Sid:
            raise PrivatePermissionError("Windows returned an empty user SID")
        return _sid_to_string(user.User.Sid)
    finally:
        kernel32.CloseHandle(token)


def _owner_sid(path: Path) -> str:
    kernel32, advapi32 = _windows_api()
    owner = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    status = advapi32.GetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        None,
        None,
        ctypes.byref(descriptor),
    )
    if status != 0:
        raise ctypes.WinError(status)
    try:
        if not owner.value:
            raise PrivatePermissionError("Private path has no Windows owner")
        return _sid_to_string(owner)
    finally:
        if descriptor.value:
            kernel32.LocalFree(descriptor)


def is_reparse_point(path: Path) -> bool:
    """Return true for symlinks and Windows reparse points such as junctions."""

    if os.name != "nt":
        return path.is_symlink()
    try:
        attributes = path.lstat().st_file_attributes
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def owned_by_current_user(path: Path) -> bool:
    """Check the filesystem owner without trusting Windows st_uid placeholders."""

    if os.name == "nt":
        try:
            return _owner_sid(path) == _current_user_sid()
        except (OSError, PrivatePermissionError):
            return False
    getuid = getattr(os, "geteuid", None)
    return getuid is None or path.stat(follow_symlinks=False).st_uid == getuid()


def has_private_permissions(path: Path, *, is_directory: bool) -> bool:
    """Return whether a path has the owner-only permissions Jobops writes.

    Windows paths must have exactly two full-control ACEs: the current user and
    Local System. POSIX paths must have no group/other permission bits.
    """

    if is_reparse_point(path) or not owned_by_current_user(path):
        return False
    if os.name != "nt":
        try:
            mode = path.stat(follow_symlinks=False).st_mode
        except OSError:
            return False
        return mode & 0o077 == 0

    kernel32, advapi32 = _windows_api()
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    status = advapi32.GetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if status != 0:
        return False
    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            return False
        dacl_is_protected = bool(control.value & _SE_DACL_PROTECTED)
        dacl_present = wintypes.BOOL()
        descriptor_dacl = ctypes.c_void_p()
        dacl_defaulted = wintypes.BOOL()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(dacl_present),
            ctypes.byref(descriptor_dacl),
            ctypes.byref(dacl_defaulted),
        ) or not dacl_present.value or not descriptor_dacl.value:
            return False
        size = _AclSizeInformation()
        if not advapi32.GetAclInformation(
            descriptor_dacl,
            ctypes.byref(size),
            ctypes.sizeof(size),
            _ACL_SIZE_INFORMATION,
        ) or size.AceCount != 2:
            return False

        expected_flags = (
            _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE if is_directory else 0
        )
        inherited_flags = expected_flags | _INHERITED_ACE
        expected_sids = {_current_user_sid(), _WINDOWS_SYSTEM_SID}
        actual_sids: set[str] = set()
        for index in range(size.AceCount):
            ace = ctypes.c_void_p()
            if not advapi32.GetAce(descriptor_dacl, index, ctypes.byref(ace)):
                return False
            allowed = ctypes.cast(ace, ctypes.POINTER(_AccessAllowedAce)).contents
            flags_are_private = (
                allowed.Header.AceFlags == expected_flags
                if dacl_is_protected
                else bool(allowed.Header.AceFlags & _INHERITED_ACE)
                and not (allowed.Header.AceFlags & ~inherited_flags)
            )
            if (
                allowed.Header.AceType != _ACCESS_ALLOWED_ACE_TYPE
                or not flags_are_private
                or allowed.Mask not in {_GENERIC_ALL, _FILE_ALL_ACCESS}
                or allowed.Header.AceSize < ctypes.sizeof(_AccessAllowedAce)
            ):
                return False
            sid_pointer = ctypes.c_void_p(ace.value + 8)
            actual_sids.add(_sid_to_string(sid_pointer))
        return actual_sids == expected_sids
    except (OSError, PrivatePermissionError):
        return False
    finally:
        if descriptor.value:
            kernel32.LocalFree(descriptor)


def set_private_permissions(path: Path, *, is_directory: bool) -> None:
    """Restrict a private file or directory to its current-user owner.

    POSIX hosts receive mode 0700/0600. Windows receives a protected DACL with
    full access for the current user and Local System only. Directory ACEs are
    inheritable so files created beneath a secured directory stay private.
    """

    if is_reparse_point(path):
        raise PrivatePermissionError("Private paths cannot be symlinks or junctions")
    if not path.exists():
        raise FileNotFoundError(path)
    if os.name != "nt":
        path.chmod(0o700 if is_directory else 0o600)
        return

    current_sid = _current_user_sid()
    if _owner_sid(path) != current_sid:
        raise PrivatePermissionError("Private path is not owned by the current user")

    kernel32, advapi32 = _windows_api()
    inheritance = "OICI" if is_directory else ""
    sddl = (
        f"D:P(A;{inheritance};GA;;;{current_sid})"
        f"(A;{inheritance};GA;;;{_WINDOWS_SYSTEM_SID})"
    )
    descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.DWORD()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        _SDDL_REVISION_1,
        ctypes.byref(descriptor),
        ctypes.byref(descriptor_size),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        dacl_present = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        dacl_defaulted = wintypes.BOOL()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(dacl_present),
            ctypes.byref(dacl),
            ctypes.byref(dacl_defaulted),
        ) or not dacl_present.value or not dacl.value:
            raise PrivatePermissionError("Could not create a private Windows DACL")
        status = advapi32.SetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
        if status != 0:
            raise ctypes.WinError(status)
    finally:
        if descriptor.value:
            kernel32.LocalFree(descriptor)


__all__ = [
    "PrivatePermissionError",
    "is_reparse_point",
    "has_private_permissions",
    "owned_by_current_user",
    "set_private_permissions",
]
