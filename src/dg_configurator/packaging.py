# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Build and read Data Gateway config packages (plain zip, signed zip, config.tar)."""

import json
import tarfile
import zipfile
from dataclasses import dataclass
from io import BytesIO
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from . import signing
from .errors import InvalidPackageError
from .model import SCHEMA_URLS, UserConfig
from .safe_archive import DEFAULT_LIMITS, ArchiveLimits, read_tar, read_zip

# 1980-01-01T00:00:00Z, the minimum zip/tar timestamp
_FIXED_MTIME = 315532800
_ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)
_CONFIG_TAR_NAME = "config.tar"
_SIGNATURE_NAME = "signature.sig"
_CONFIG_JSON_NAME = "config.json"
_PROJECT_JSON_NAME = "project.json"
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")
_UNIX_CREATE_SYSTEM = 3

SignatureStatus = Literal["valid", "invalid", "unchecked"]


def dump_config(config: UserConfig) -> bytes:
    """Serialize a UserConfig to pretty-printed config.json bytes with ``$schema`` restored.

    Only fields that were set explicitly are written, so defaults introduced by a newer config version (for example
    ``passwordPolicy`` or ``timestampFormat``) never turn a version 1.0 document into an invalid one.
    """
    payload = config.model_dump(mode="json", by_alias=True, exclude_none=True, exclude_unset=True)
    document = {"$schema": SCHEMA_URLS[config.version], **payload}
    return (json.dumps(document, indent=2) + "\n").encode("utf-8")


def deterministic_zip(entries: dict[str, bytes]) -> bytes:
    """Build a zip whose bytes depend only on the entry names and contents."""
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w") as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(filename=name, date_time=_ZIP_DATE_TIME)
            info.create_system = _UNIX_CREATE_SYSTEM
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, entries[name])
    return buffer.getvalue()


def _deterministic_tar(entries: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(entries):
            info = tarfile.TarInfo(name=name)
            info.size = len(entries[name])
            info.mtime = _FIXED_MTIME
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, BytesIO(entries[name]))
    return buffer.getvalue()


def build_plain_zip(config_json: bytes, files: dict[str, bytes]) -> bytes:
    """Build a plain deploy package: config.json + supporting files at the zip root."""
    return deterministic_zip({**files, _CONFIG_JSON_NAME: config_json})


def build_config_tar(config_json: bytes, files: dict[str, bytes]) -> bytes:
    """Build the config.tar payload (config.json + supporting files) used inside a signed package."""
    return _deterministic_tar({**files, _CONFIG_JSON_NAME: config_json})


def build_signed_zip(config_json: bytes, files: dict[str, bytes], private_key: RSAPrivateKey) -> bytes:
    """Build a signed deploy package: a zip containing config.tar and its detached signature.sig."""
    tar_bytes = build_config_tar(config_json, files)
    signature = signing.sign(tar_bytes, private_key)
    return deterministic_zip({_CONFIG_TAR_NAME: tar_bytes, _SIGNATURE_NAME: signature})


@dataclass
class LoadedPackage:
    """Result of reading an imported package, independent of its on-disk format."""

    kind: Literal["json", "plain-zip", "signed-zip", "project"]
    config_json: bytes
    files: dict[str, bytes]
    layout: dict[str, Any] | None = None
    signature_status: SignatureStatus | None = None


def read_package(
    data: bytes, public_key: RSAPublicKey | None = None, limits: ArchiveLimits = DEFAULT_LIMITS
) -> LoadedPackage:
    """Detect and read any supported package format.

    A zip is a project, a signed package or a plain package depending on its entry names; anything else must be a
    bare config.json document.
    """
    if data[:4] in _ZIP_MAGICS:
        entries = read_zip(data, limits)
        if _PROJECT_JSON_NAME in entries:
            from .project import read_project_entries  # noqa: PLC0415 - project.py imports this module

            return read_project_entries(entries)
        if _CONFIG_TAR_NAME in entries and _SIGNATURE_NAME in entries:
            return _read_signed(entries, public_key, limits)
        if _CONFIG_JSON_NAME in entries:
            files = {name: value for name, value in entries.items() if name != _CONFIG_JSON_NAME}
            return LoadedPackage(kind="plain-zip", config_json=entries[_CONFIG_JSON_NAME], files=files)
        raise InvalidPackageError("zip archive does not contain a recognised config package layout")

    try:
        json.loads(data)
    except ValueError as exc:
        raise InvalidPackageError(f"input is neither a zip archive nor valid JSON: {exc}") from exc
    return LoadedPackage(kind="json", config_json=data, files={})


def _read_signed(entries: dict[str, bytes], public_key: RSAPublicKey | None, limits: ArchiveLimits) -> LoadedPackage:
    tar_entries = read_tar(entries[_CONFIG_TAR_NAME], limits)
    if _CONFIG_JSON_NAME not in tar_entries:
        raise InvalidPackageError("config.tar does not contain config.json")
    status: SignatureStatus = "unchecked"
    if public_key is not None:
        is_valid = signing.verify(entries[_CONFIG_TAR_NAME], entries[_SIGNATURE_NAME], public_key)
        status = "valid" if is_valid else "invalid"
    files = {name: value for name, value in tar_entries.items() if name != _CONFIG_JSON_NAME}
    return LoadedPackage(
        kind="signed-zip", config_json=tar_entries[_CONFIG_JSON_NAME], files=files, signature_status=status
    )
