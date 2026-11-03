# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for .dgproj reading and writing."""

import json
import zipfile
from io import BytesIO

import pytest

from dg_configurator import packaging, project
from dg_configurator.errors import InvalidPackageError

CONFIG = b'{"version": "1.1"}'
FILES = {"ca.pem": b"ca", "certs/key.pem": b"key"}
LAYOUT = {"nodes": {"1": {"x": 40, "y": 40}}}


def _zip(entries: dict[str, bytes]) -> bytes:
    return packaging.deterministic_zip(entries)


def test_project_round_trips():
    loaded = project.read_project(project.write_project(CONFIG, FILES, LAYOUT))

    assert loaded.kind == "project"
    assert loaded.config_json == CONFIG
    assert loaded.files == FILES
    assert loaded.layout == LAYOUT


def test_project_output_is_deterministic():
    assert project.write_project(CONFIG, FILES, LAYOUT) == project.write_project(
        CONFIG, dict(reversed(FILES.items())), LAYOUT
    )


def test_read_package_dispatches_projects():
    loaded = packaging.read_package(project.write_project(CONFIG, FILES, LAYOUT))

    assert (loaded.kind, loaded.layout) == ("project", LAYOUT)


def _meta(**overrides: object) -> bytes:
    return json.dumps({"formatVersion": 1, "layout": {}} | overrides).encode()


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ({"config.json": CONFIG}, "project.json"),
        ({"project.json": b"{", "config.json": CONFIG}, "not valid JSON"),
        ({"project.json": _meta(formatVersion=2), "config.json": CONFIG}, "formatVersion"),
        ({"project.json": b"[]", "config.json": CONFIG}, "formatVersion"),
        ({"project.json": _meta()}, "config.json"),
        ({"project.json": _meta(layout=[]), "config.json": CONFIG}, "layout"),
    ],
)
def test_invalid_projects_are_rejected(entries: dict[str, bytes], message: str):
    with pytest.raises(InvalidPackageError, match=message):
        project.read_project(_zip(entries))


def test_non_zip_data_is_rejected():
    with pytest.raises(InvalidPackageError):
        project.read_project(b"nope")


def test_missing_layout_defaults_to_empty():
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("project.json", json.dumps({"formatVersion": 1}))
        archive.writestr("config.json", CONFIG)

    assert project.read_project(buffer.getvalue()).layout == {}
