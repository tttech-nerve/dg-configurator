# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for ConfigVersion ordering."""

from dg_configurator.model.version import LATEST, SCHEMA_URLS, ConfigVersion


def test_versions_are_ordered():
    assert ConfigVersion.V1_0 < ConfigVersion.V1_1
    assert ConfigVersion.V1_1 > ConfigVersion.V1_0
    assert ConfigVersion.V1_0 <= ConfigVersion.V1_0
    assert ConfigVersion.V1_1 >= ConfigVersion.V1_1
    assert not ConfigVersion.V1_1 < ConfigVersion.V1_0


def test_versions_sort_by_number():
    assert sorted([ConfigVersion.V1_1, ConfigVersion.V1_0]) == [ConfigVersion.V1_0, ConfigVersion.V1_1]


def test_comparison_with_foreign_type_is_not_implemented():
    assert ConfigVersion.V1_0.__lt__(3) is NotImplemented
    assert ConfigVersion.V1_0.__le__(3) is NotImplemented
    assert ConfigVersion.V1_0.__gt__(3) is NotImplemented
    assert ConfigVersion.V1_0.__ge__(3) is NotImplemented


def test_latest_has_a_schema_url():
    assert LATEST is ConfigVersion.V1_1
    assert set(SCHEMA_URLS) == set(ConfigVersion)
