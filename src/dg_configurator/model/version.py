# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Config file schema version enum with ordered comparison."""

from enum import StrEnum


class ConfigVersion(StrEnum):
    """Supported config.json schema versions."""

    V1_0 = "1.0"
    V1_1 = "1.1"

    def _as_tuple(self) -> tuple[int, ...]:
        return tuple(int(part) for part in self.value.split("."))

    def __lt__(self, other: object) -> bool:
        """Return whether this version is older than ``other``."""
        if not isinstance(other, ConfigVersion):
            return NotImplemented
        return self._as_tuple() < other._as_tuple()

    def __le__(self, other: object) -> bool:
        """Return whether this version is older than or equal to ``other``."""
        if not isinstance(other, ConfigVersion):
            return NotImplemented
        return self._as_tuple() <= other._as_tuple()

    def __gt__(self, other: object) -> bool:
        """Return whether this version is newer than ``other``."""
        if not isinstance(other, ConfigVersion):
            return NotImplemented
        return self._as_tuple() > other._as_tuple()

    def __ge__(self, other: object) -> bool:
        """Return whether this version is newer than or equal to ``other``."""
        if not isinstance(other, ConfigVersion):
            return NotImplemented
        return self._as_tuple() >= other._as_tuple()


LATEST = ConfigVersion.V1_1

SCHEMA_URLS: dict[ConfigVersion, str] = {
    ConfigVersion.V1_0: "https://docs.nerve.cloud/datagate/v100/configuration/static/config-schema-v1.0.json",
    ConfigVersion.V1_1: "https://docs.nerve.cloud/datagate/v110/configuration/static/config-schema-v1.1.json",
}
