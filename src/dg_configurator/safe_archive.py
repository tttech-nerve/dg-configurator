# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Safe zip/tar reading with zip-slip, symlink, and archive-bomb protections."""

import tarfile
import zipfile
from dataclasses import dataclass
from io import BytesIO

from .errors import InvalidPackageError, UnsafeArchiveError

# the compression ratio is only meaningful for entries large enough to be a bomb
_RATIO_CHECK_MIN_BYTES = 1024 * 1024
_SYMLINK_MODE = 0o120000
_FILE_TYPE_MASK = 0o170000


@dataclass(frozen=True)
class ArchiveLimits:
    """Safety limits enforced while reading an archive."""

    max_entries: int = 1000
    max_total_bytes: int = 50 * 1024 * 1024
    max_ratio: int = 100


DEFAULT_LIMITS = ArchiveLimits()


def _normalize_name(name: str) -> str:
    name = name.removeprefix("./")
    if name.startswith(("/", "\\")):
        raise UnsafeArchiveError(f"archive entry has an absolute path: {name!r}")
    if any(part == ".." for part in name.replace("\\", "/").split("/")):
        raise UnsafeArchiveError(f"archive entry escapes its base directory: {name!r}")
    return name


def _add_entry(result: dict[str, bytes], name: str, data: bytes) -> None:
    if name in result:
        raise UnsafeArchiveError(f"archive contains the entry {name!r} more than once")
    result[name] = data


def _check_total(total: int, limits: ArchiveLimits) -> None:
    if total > limits.max_total_bytes:
        raise UnsafeArchiveError(f"archive exceeds the total uncompressed size limit ({limits.max_total_bytes} bytes)")


def read_zip(data: bytes, limits: ArchiveLimits = DEFAULT_LIMITS) -> dict[str, bytes]:
    """Read every regular-file entry of a zip archive into memory, enforcing limits."""
    result: dict[str, bytes] = {}
    total = 0
    try:
        archive = zipfile.ZipFile(BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise InvalidPackageError(f"not a valid zip archive: {exc}") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > limits.max_entries:
            raise UnsafeArchiveError(f"archive has too many entries ({len(infos)} > {limits.max_entries})")
        for info in infos:
            if info.is_dir():
                continue
            # zip stores the unix mode in the high 16 bits of external_attr
            if ((info.external_attr >> 16) & _FILE_TYPE_MASK) == _SYMLINK_MODE:
                raise UnsafeArchiveError(f"archive entry is a symlink: {info.filename!r}")
            name = _normalize_name(info.filename)
            if (
                info.file_size >= _RATIO_CHECK_MIN_BYTES
                and info.compress_size > 0
                and info.file_size / info.compress_size > limits.max_ratio
            ):
                raise UnsafeArchiveError(f"archive entry has a suspicious compression ratio: {info.filename!r}")
            total += info.file_size
            _check_total(total, limits)
            try:
                _add_entry(result, name, archive.read(info))
            except zipfile.BadZipFile as exc:
                raise InvalidPackageError(f"corrupt zip entry {info.filename!r}: {exc}") from exc
    return result


def read_tar(data: bytes, limits: ArchiveLimits = DEFAULT_LIMITS) -> dict[str, bytes]:
    """Read every regular-file entry of a tar archive into memory, enforcing limits."""
    result: dict[str, bytes] = {}
    total = 0
    try:
        archive = tarfile.open(fileobj=BytesIO(data), mode="r:*")  # noqa: SIM115 - closed by the with block below
    except tarfile.TarError as exc:
        raise InvalidPackageError(f"not a valid tar archive: {exc}") from exc
    with archive:
        members = archive.getmembers()
        if len(members) > limits.max_entries:
            raise UnsafeArchiveError(f"archive has too many entries ({len(members)} > {limits.max_entries})")
        for member in members:
            if member.isdir():
                continue
            if not member.isfile():
                raise UnsafeArchiveError(f"archive entry is not a regular file: {member.name!r}")
            name = _normalize_name(member.name)
            total += member.size
            _check_total(total, limits)
            extracted = archive.extractfile(member)
            if extracted is None:  # pragma: no cover - extractfile only returns None for non-file members
                raise UnsafeArchiveError(f"could not read archive entry: {member.name!r}")
            _add_entry(result, name, extracted.read())
    return result
