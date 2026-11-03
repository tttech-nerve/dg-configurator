# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Supporting-file collection and loading for a UserConfig."""

from pathlib import Path

from .model import UserConfig


def collect_supporting_files(config: UserConfig, available: dict[str, bytes]) -> tuple[dict[str, bytes], list[str]]:
    """Split ``available`` into the files ``config`` references and the referenced names that are missing.

    Returns:
        A tuple of (files that are referenced and present, sorted names that are referenced but absent). Files that
        are present but not referenced are dropped.
    """
    referenced = {linked.name for linked in config.linked_files()}
    used = {name: data for name, data in available.items() if name in referenced}
    missing = sorted(referenced - available.keys())
    return used, missing


def load_files_from_dir(base: Path, names: list[str]) -> dict[str, bytes]:
    """Load each named file relative to ``base``, rejecting any path that escapes ``base``.

    This is a second line of defence independent of the model's ``SupportingFileName`` validation.

    Raises:
        FileNotFoundError: if a file does not exist under ``base`` or its resolved path leaves ``base``.
    """
    base_resolved = base.resolve()
    result: dict[str, bytes] = {}
    for name in names:
        candidate = (base / name).resolve()
        if not candidate.is_relative_to(base_resolved):
            raise FileNotFoundError(f"refusing to read file outside {base}: {name}")
        result[name] = candidate.read_bytes()
    return result
