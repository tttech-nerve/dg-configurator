# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for safe archive reading."""

import tarfile
import zipfile
from io import BytesIO

import pytest

from dg_configurator.errors import InvalidPackageError, UnsafeArchiveError
from dg_configurator.safe_archive import ArchiveLimits, read_tar, read_zip


def _zip(entries: dict[str, bytes], *, compression: int = zipfile.ZIP_STORED) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _tar(entries: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, BytesIO(data))
    return buffer.getvalue()


def test_zip_with_parent_directory_entry_is_rejected():
    with pytest.raises(UnsafeArchiveError, match="escapes"):
        read_zip(_zip({"../escape.txt": b"x"}))


@pytest.mark.parametrize("name", ["/abs.txt", "\\abs.txt"])
def test_zip_with_absolute_entry_is_rejected(name: str):
    with pytest.raises(UnsafeArchiveError, match="absolute"):
        read_zip(_zip({name: b"x"}))


def test_zip_symlink_entry_is_rejected():
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        archive.writestr(info, "target")

    with pytest.raises(UnsafeArchiveError, match="symlink"):
        read_zip(buffer.getvalue())


def test_zip_with_too_many_entries_is_rejected():
    limits = ArchiveLimits(max_entries=2)

    with pytest.raises(UnsafeArchiveError, match="too many entries"):
        read_zip(_zip({"a": b"1", "b": b"2", "c": b"3"}), limits)


def test_zip_exceeding_total_size_is_rejected():
    limits = ArchiveLimits(max_total_bytes=10)

    with pytest.raises(UnsafeArchiveError, match="size limit"):
        read_zip(_zip({"a": b"x" * 11}), limits)


def test_zip_with_suspicious_compression_ratio_is_rejected():
    bomb = _zip({"zeros": bytes(5 * 1024 * 1024)}, compression=zipfile.ZIP_DEFLATED)

    with pytest.raises(UnsafeArchiveError, match="compression ratio"):
        read_zip(bomb)


def test_small_highly_compressible_entries_are_allowed():
    data = _zip({"config.json": b" " * 10_000}, compression=zipfile.ZIP_DEFLATED)

    assert read_zip(data) == {"config.json": b" " * 10_000}


def test_zip_with_duplicate_entries_is_rejected():
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("config.json", "first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("config.json", "second")

    with pytest.raises(UnsafeArchiveError, match="more than once"):
        read_zip(buffer.getvalue())


def test_zip_directories_are_skipped_and_dot_prefix_is_stripped():
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("certs/", "")
        archive.writestr("./certs/ca.pem", b"pem")

    assert read_zip(buffer.getvalue()) == {"certs/ca.pem": b"pem"}


def test_zip_within_limits_returns_exact_bytes():
    entries = {"config.json": b"{}", "certs/ca.pem": b"\x00\x01binary"}

    assert read_zip(_zip(entries, compression=zipfile.ZIP_DEFLATED)) == entries


def test_non_zip_data_is_an_invalid_package():
    with pytest.raises(InvalidPackageError):
        read_zip(b"not a zip")


def test_corrupt_zip_entry_is_an_invalid_package():
    data = bytearray(_zip({"config.json": b"payload-payload"}))
    data[data.index(b"payload")] ^= 0xFF

    with pytest.raises(InvalidPackageError, match="corrupt"):
        read_zip(bytes(data))


def test_tar_dot_prefixed_names_are_stripped():
    entries = _tar({"./config.json": b"{}", "./certs/ca.pem": b"pem"})

    assert read_tar(entries) == {"config.json": b"{}", "certs/ca.pem": b"pem"}


def test_tar_with_parent_directory_entry_is_rejected():
    with pytest.raises(UnsafeArchiveError, match="escapes"):
        read_tar(_tar({"../escape": b"x"}))


def test_tar_with_non_regular_member_is_rejected():
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        archive.addfile(info)

    with pytest.raises(UnsafeArchiveError, match="not a regular file"):
        read_tar(buffer.getvalue())


def test_tar_directories_are_skipped():
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("./")
        info.type = tarfile.DIRTYPE
        archive.addfile(info)
        file_info = tarfile.TarInfo("./a")
        file_info.size = 1
        archive.addfile(file_info, BytesIO(b"x"))

    assert read_tar(buffer.getvalue()) == {"a": b"x"}


def test_tar_limits_are_enforced():
    entries = _tar({"a": b"12345", "b": b"12345"})

    with pytest.raises(UnsafeArchiveError, match="too many entries"):
        read_tar(entries, ArchiveLimits(max_entries=1))
    with pytest.raises(UnsafeArchiveError, match="size limit"):
        read_tar(entries, ArchiveLimits(max_total_bytes=9))


def test_tar_with_duplicate_entries_is_rejected():
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for content in (b"1", b"2"):
            info = tarfile.TarInfo("a")
            info.size = len(content)
            archive.addfile(info, BytesIO(content))

    with pytest.raises(UnsafeArchiveError, match="more than once"):
        read_tar(buffer.getvalue())


def test_non_tar_data_is_an_invalid_package():
    with pytest.raises(InvalidPackageError):
        read_tar(b"definitely not a tar archive" * 50)
