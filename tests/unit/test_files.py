# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for supporting-file handling."""

import json
from pathlib import Path

import pytest

from dg_configurator.files import collect_supporting_files, load_files_from_dir
from dg_configurator.model import UserConfig
from tests.conftest import FIXTURES_DIR


def _config_with_files() -> UserConfig:
    document = json.loads((FIXTURES_DIR / "configs" / "valid" / "v1.0" / "minimal.json").read_text())
    document["endpoints"][0].update(
        url="mqtts://h", security={"tlsEnabled": True, "ca": "ca.pem", "certificate": "certs/client.pem"}
    )
    return UserConfig.model_validate(document)


def test_collect_splits_used_files_and_missing_names():
    used, missing = collect_supporting_files(_config_with_files(), {"ca.pem": b"ca", "stray.pem": b"x"})

    assert used == {"ca.pem": b"ca"}
    assert missing == ["certs/client.pem"]


def test_collect_reports_nothing_missing_when_all_files_exist():
    available = {"ca.pem": b"ca", "certs/client.pem": b"cert"}

    assert collect_supporting_files(_config_with_files(), available) == (available, [])


def test_load_files_reads_relative_files(tmp_path: Path):
    (tmp_path / "certs").mkdir()
    (tmp_path / "certs" / "ca.pem").write_bytes(b"pem")

    assert load_files_from_dir(tmp_path, ["certs/ca.pem"]) == {"certs/ca.pem": b"pem"}


def test_load_files_reports_missing_files(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_files_from_dir(tmp_path, ["absent.pem"])


def test_load_files_refuses_to_leave_the_base_directory(tmp_path: Path):
    base = tmp_path / "base"
    base.mkdir()
    (tmp_path / "outside.txt").write_bytes(b"secret")

    with pytest.raises(FileNotFoundError, match="outside"):
        load_files_from_dir(base, ["../outside.txt"])


def test_load_files_refuses_symlinks_pointing_outside(tmp_path: Path):
    base = tmp_path / "base"
    base.mkdir()
    (tmp_path / "outside.txt").write_bytes(b"secret")
    (base / "link.pem").symlink_to(tmp_path / "outside.txt")

    with pytest.raises(FileNotFoundError, match="outside"):
        load_files_from_dir(base, ["link.pem"])
