# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Read and write .dgproj project files (config + supporting files + graph layout)."""

import json
from typing import Any

from .errors import InvalidPackageError
from .packaging import LoadedPackage, deterministic_zip
from .safe_archive import DEFAULT_LIMITS, ArchiveLimits, read_zip

_PROJECT_FORMAT_VERSION = 1
_PROJECT_JSON_NAME = "project.json"
_CONFIG_JSON_NAME = "config.json"
_FILES_PREFIX = "files/"


def write_project(config_json: bytes, files: dict[str, bytes], layout: dict[str, Any]) -> bytes:
    """Build a .dgproj archive: project.json (format + layout) + config.json + files/<name>."""
    project_meta = {"formatVersion": _PROJECT_FORMAT_VERSION, "tool": "dg-configurator", "layout": layout}
    entries = {
        _PROJECT_JSON_NAME: json.dumps(project_meta, indent=2).encode("utf-8"),
        _CONFIG_JSON_NAME: config_json,
    }
    entries.update({f"{_FILES_PREFIX}{name}": data for name, data in files.items()})
    return deterministic_zip(entries)


def read_project(data: bytes, limits: ArchiveLimits = DEFAULT_LIMITS) -> LoadedPackage:
    """Read a .dgproj archive back into a LoadedPackage with kind='project'."""
    return read_project_entries(read_zip(data, limits))


def read_project_entries(entries: dict[str, bytes]) -> LoadedPackage:
    """Build a LoadedPackage from the already extracted entries of a .dgproj archive."""
    if _PROJECT_JSON_NAME not in entries:
        raise InvalidPackageError("archive does not contain project.json")
    try:
        meta = json.loads(entries[_PROJECT_JSON_NAME])
    except ValueError as exc:
        raise InvalidPackageError(f"project.json is not valid JSON: {exc}") from exc
    if not isinstance(meta, dict) or meta.get("formatVersion") != _PROJECT_FORMAT_VERSION:
        version = meta.get("formatVersion") if isinstance(meta, dict) else None
        raise InvalidPackageError(f"unsupported .dgproj formatVersion: {version!r}")
    if _CONFIG_JSON_NAME not in entries:
        raise InvalidPackageError("archive does not contain config.json")
    layout = meta.get("layout", {})
    if not isinstance(layout, dict):
        raise InvalidPackageError("project.json layout must be an object")
    files = {
        name.removeprefix(_FILES_PREFIX): value for name, value in entries.items() if name.startswith(_FILES_PREFIX)
    }
    return LoadedPackage(kind="project", config_json=entries[_CONFIG_JSON_NAME], files=files, layout=layout)
