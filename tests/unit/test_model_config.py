# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for UserConfig and its cross-object rules."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from dg_configurator.model import ConfigVersion, UserConfig
from tests.conftest import VALID_CONFIGS


def _load(name: str) -> dict[str, Any]:
    path = next(p for p in VALID_CONFIGS if p.parent.name + "/" + p.name == name)
    return json.loads(path.read_text())


def _codes(data: dict[str, Any]) -> set[tuple[str, tuple[Any, ...]]]:
    with pytest.raises(ValidationError) as exc_info:
        UserConfig.model_validate(data)
    return {
        (error["msg"].split("]")[0].removeprefix("Value error, ["), tuple(error["loc"]))
        for error in exc_info.value.errors()
    }


@pytest.mark.parametrize("path", VALID_CONFIGS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_valid_fixtures_parse(path: Path):
    config = UserConfig.model_validate_json(path.read_bytes())

    assert config.version in set(ConfigVersion)


def test_schema_url_is_accepted_but_not_dumped():
    config = UserConfig.model_validate(_load("v1.1/sql-bootstrap.json"))

    assert config.json_schema_url is not None
    assert "$schema" not in config.model_dump(by_alias=True)


def test_connections_are_required():
    data = _load("v1.0/minimal.json")
    del data["connections"]

    with pytest.raises(ValidationError):
        UserConfig.model_validate(data)


def test_unknown_version_is_rejected():
    data = _load("v1.0/minimal.json") | {"version": "2.0"}

    with pytest.raises(ValidationError):
        UserConfig.model_validate(data)


def test_endpoint_limit_is_enforced():
    data = _load("v1.0/minimal.json")
    data["endpoints"] = [
        {"id": index, "name": "e", "endpointType": "mqtt-client", "url": "mqtt://h"} for index in range(101)
    ]
    data["connections"] = []

    with pytest.raises(ValidationError, match="at most 100"):
        UserConfig.model_validate(data)


def test_password_policy_requires_version_1_1():
    data = _load("v1.0/minimal.json") | {"passwordPolicy": {"minLength": 20, "maxLength": 20}}

    assert ("version_too_low", ("passwordPolicy",)) in _codes(data)


def test_password_policy_default_is_not_a_version_problem():
    UserConfig.model_validate(_load("v1.0/minimal.json"))


def test_binary_input_and_variable_schema_require_version_1_1():
    data = _load("v1.1/sql-binary.json")
    data["version"] = "1.0"

    codes = _codes(data)

    assert ("version_too_low", ("endpoints", 0, "inputs", 0)) in codes
    assert ("version_too_low", ("endpoints", 1)) in codes


def test_timestamp_format_requires_version_1_1():
    data = _load("v1.0/minimal.json")
    data["endpoints"][1]["outputs"][0]["timestampFormat"] = "rfc3339nano"

    assert ("version_too_low", ("endpoints", 1, "outputs", 0)) in _codes(data)


def test_variable_schema_alone_requires_version_1_1():
    data = _load("v1.0/minimal.json")
    data["endpoints"][0]["inputs"][0]["variableSchema"] = {"a": "bool"}

    assert ("version_too_low", ("endpoints", 0, "inputs", 0)) in _codes(data)


def test_duplicate_output_and_connection_ids_are_reported():
    data = _load("v1.1/minimal.json")
    data["endpoints"][2]["outputs"].append(copy.deepcopy(data["endpoints"][2]["outputs"][0]))
    data["connections"][1]["id"] = 1

    codes = _codes(data)

    assert ("duplicate_id", ("endpoints", 2, "outputs", 1, "id")) in codes
    assert ("duplicate_id", ("connections", 1, "id")) in codes


def test_dangling_source_input_is_reported():
    data = _load("v1.0/minimal.json")
    data["connections"][0]["source"]["input"] = 42

    assert ("dangling_reference", ("connections", 0, "source", "input")) in _codes(data)


def test_dangling_source_endpoint_and_destination_output_are_reported():
    data = _load("v1.0/minimal.json")
    data["connections"][0]["source"]["endpoint"] = 42
    data["connections"][0]["destination"]["output"] = 42

    codes = _codes(data)

    assert ("dangling_reference", ("connections", 0, "source", "endpoint")) in codes
    assert ("dangling_reference", ("connections", 0, "destination", "output")) in codes


def test_binary_input_can_only_feed_a_binary_writer():
    data = _load("v1.1/sql-binary.json")
    data["endpoints"][1]["outputs"][0] = {"id": 1, "name": "c", "outputType": "sql-columnar-writer", "table": "t"}

    assert ("encoding_mismatch", ("connections", 0)) in _codes(data)


def test_unused_output_is_an_orphan():
    data = _load("v1.0/minimal.json")
    data["connections"] = []

    codes = _codes(data)

    assert ("orphan_port", ("endpoints", 0, "inputs", 0)) in codes
    assert ("orphan_port", ("endpoints", 1, "outputs", 0)) in codes


def test_linked_files_collects_every_endpoint():
    data = _load("v1.0/minimal.json")
    data["endpoints"][0].update(url="mqtts://h", security={"tlsEnabled": True, "ca": "ca.pem"})
    data["endpoints"][1].update(url="mqtts://h", security={"tlsEnabled": True, "ca": "other.pem"})

    names = [linked.name for linked in UserConfig.model_validate(data).linked_files()]

    assert names == ["ca.pem", "other.pem"]
