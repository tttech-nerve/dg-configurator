# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Conformance of the Pydantic model with the public JSON Schemas."""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from dg_configurator.model import UserConfig
from dg_configurator.model.base import StrictModel
from dg_configurator.model.connection import Connection, ConnectionDestination, ConnectionSource
from dg_configurator.model.mqtt import (
    MqttAdvanced,
    MqttEndpoint,
    MqttPublisherOutput,
    MqttSecurity,
    MqttSubscriberInput,
    MqttTopicSubscription,
    UserPasswordLogin,
)
from dg_configurator.model.opcua import OpcuaEndpoint, OpcuaInput, OpcuaNode, OpcuaSecurity
from dg_configurator.model.password_policy import PasswordPolicy
from dg_configurator.model.sql import (
    SqlAdvanced,
    SqlBinaryWriterOutput,
    SqlBootstrap,
    SqlBootstrapAdmin,
    SqlBootstrapExportUser,
    SqlColumnarWriterOutput,
    SqlEndpoint,
    SqlSecurity,
)
from tests.conftest import FIXTURES_DIR, INVALID_CONFIGS, VALID_CONFIGS

SCHEMAS_DIR = FIXTURES_DIR / "schemas"

# The JSON Schema cannot express cross-field/cross-object rules, so these invalid fixtures are valid for the schema.
# `extra_field` is accepted because the schema does not forbid unknown keys inside endpoints; the model does.
SCHEMA_GAP_FIXTURES = {
    "questdb_bootstrap",
    "questdb_binary_writer",
    "questdb_delimiter_dot",
    "orphan_port",
    "encoding_mismatch",
    "duplicate_endpoint_id",
    "duplicate_input_id",
    "dangling_connection",
    "url_tls_mismatch",
    "password_policy_bad_length",
    "extra_field",
}


def _schema(version: str) -> dict[str, Any]:
    return json.loads((SCHEMAS_DIR / f"config-schema-v{version}.json").read_text())


def _validator(version: str) -> Draft202012Validator:
    return Draft202012Validator(_schema(version))


@pytest.mark.parametrize("path", VALID_CONFIGS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_valid_fixtures_satisfy_schema_and_model(path: Path):
    document = json.loads(path.read_text())

    _validator(document["version"]).validate(document)
    UserConfig.model_validate(document)


@pytest.mark.parametrize("path", INVALID_CONFIGS, ids=lambda p: p.stem)
def test_schema_agrees_with_model_on_schema_expressible_rules(path: Path):
    if path.stem == "malformed_json":
        pytest.skip("not a JSON document")
    document = json.loads(path.read_text())
    schema_accepts = _validator(document["version"]).is_valid(document)

    assert schema_accepts is (path.stem in SCHEMA_GAP_FIXTURES)


def _aliases(model: type[StrictModel]) -> set[str]:
    return {field.alias or name for name, field in model.model_fields.items()}


def _properties(schema: dict[str, Any], *definitions: str) -> set[str]:
    return {name for definition in definitions for name in schema["$defs"][definition]["properties"]}


_V10_MODELS: dict[type[StrictModel], tuple[str, ...]] = {
    MqttEndpoint: ("Endpoint", "MqttEndpoint"),
    OpcuaEndpoint: ("Endpoint", "OpcuaEndpoint"),
    UserPasswordLogin: ("UserPasswordLogin",),
    MqttSecurity: ("MqttSecurity",),
    OpcuaSecurity: ("OpcuaSecurity",),
    MqttAdvanced: ("MqttAdvanced",),
    MqttSubscriberInput: ("MqttSubscriberInput",),
    MqttTopicSubscription: ("MqttTopicSubscription",),
    MqttPublisherOutput: ("MqttPublisherOutput",),
    OpcuaInput: ("OpcuaInput",),
    OpcuaNode: ("OpcuaNode",),
    Connection: ("Connection",),
    ConnectionSource: ("ConnectionSource",),
    ConnectionDestination: ("ConnectionDestination",),
}

_V11_ONLY_MODELS: dict[type[StrictModel], tuple[str, ...]] = {
    SqlEndpoint: ("Endpoint", "SqlEndpoint"),
    SqlSecurity: ("SqlSecurity",),
    SqlAdvanced: ("SqlAdvanced",),
    SqlColumnarWriterOutput: ("SqlOutput", "SqlColumnarWriterOutput"),
    SqlBinaryWriterOutput: ("SqlOutput", "SqlBinaryWriterOutput"),
    PasswordPolicy: ("PasswordPolicy",),
}


_V11_ONLY_FIELDS: dict[type[StrictModel], set[str]] = {
    MqttSubscriberInput: {"variableSchema"},
    MqttPublisherOutput: {"timestampFormat"},
}


@pytest.mark.parametrize("model", _V10_MODELS, ids=lambda m: m.__name__)
@pytest.mark.parametrize("version", ["1.0", "1.1"])
def test_property_names_match_the_schema_for_shared_models(model: type[StrictModel], version: str):
    added_in_v11 = _V11_ONLY_FIELDS.get(model, set()) if version == "1.0" else set()

    assert _aliases(model) - added_in_v11 == _properties(_schema(version), *_V10_MODELS[model])


@pytest.mark.parametrize("model", _V11_ONLY_MODELS, ids=lambda m: m.__name__)
def test_property_names_match_the_v11_schema(model: type[StrictModel]):
    assert _aliases(model) == _properties(_schema("1.1"), *_V11_ONLY_MODELS[model])


def test_subscriber_input_properties_match_the_v11_schema():
    assert _aliases(MqttSubscriberInput) == _properties(_schema("1.1"), "MqttSubscriberInput")


def test_bootstrap_properties_match_the_v11_schema():
    bootstrap = _schema("1.1")["$defs"]["SqlEndpoint"]["properties"]["bootstrap"]

    assert _aliases(SqlBootstrap) == set(bootstrap["properties"])
    assert _aliases(SqlBootstrapAdmin) == set(bootstrap["properties"]["admin"]["properties"])
    assert _aliases(SqlBootstrapExportUser) == set(bootstrap["properties"]["exportUser"]["properties"])


@pytest.mark.parametrize("version", ["1.0", "1.1"])
def test_root_properties_match_the_schema(version: str):
    root_aliases = {name for name in _aliases(UserConfig)}

    assert set(_schema(version)["properties"]) <= root_aliases
