# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for the SQL endpoint models."""

import pytest
from pydantic import ValidationError

from dg_configurator.model.common import LinkedFile, MessageEncoding
from dg_configurator.model.sql import SqlBinaryWriterOutput, SqlBootstrap, SqlColumnarWriterOutput, SqlEndpoint

_ADMIN = {"username": "admin", "password": "secret"}
_COLUMNAR = {"id": 1, "name": "c", "outputType": "sql-columnar-writer", "table": "t"}
_BINARY = {"id": 2, "name": "b", "outputType": "sql-binary-writer", "table": "t"}


def _endpoint(**overrides: object) -> dict[str, object]:
    return {"id": 1, "name": "e", "endpointType": "sql-client", "dbType": "postgresql", "host": "h"} | overrides


def test_endpoint_defaults():
    endpoint = SqlEndpoint.model_validate(_endpoint())

    assert endpoint.port is None
    assert endpoint.ilp_port == 9000
    assert endpoint.advanced.batch_size == 1
    assert endpoint.advanced.flush_interval_ms == 1000
    assert endpoint.security.tls_version == "1.2"
    assert SqlEndpoint.MIN_CONFIG_VERSION.value == "1.1"


def test_columnar_and_binary_outputs_parse_by_discriminator():
    endpoint = SqlEndpoint.model_validate(_endpoint(outputs=[_COLUMNAR, _BINARY]))

    assert isinstance(endpoint.outputs[0], SqlColumnarWriterOutput)
    assert isinstance(endpoint.outputs[1], SqlBinaryWriterOutput)
    assert endpoint.outputs[0].timestamp_column == "timestamp"
    assert endpoint.outputs[1].data_column == "data"


def test_inputs_must_be_empty():
    with pytest.raises(ValidationError):
        SqlEndpoint.model_validate(_endpoint(inputs=[{"id": 1}]))


def test_output_accepted_encodings():
    columnar = SqlColumnarWriterOutput.model_validate(_COLUMNAR)
    binary = SqlBinaryWriterOutput.model_validate(_BINARY)

    assert [columnar.accepts(e) for e in MessageEncoding] == [True, True, False]
    assert [binary.accepts(e) for e in MessageEncoding] == [False, False, True]


def test_bootstrap_requires_export_key_unless_plaintext_export_is_allowed():
    with pytest.raises(ValidationError):
        SqlBootstrap.model_validate({"enabled": True, "admin": _ADMIN})

    SqlBootstrap.model_validate({"enabled": True, "admin": _ADMIN, "allowPlaintextExport": True})
    SqlBootstrap.model_validate({"enabled": True, "admin": _ADMIN, "exportPublicKey": "age1abc"})


def test_bootstrap_dumps_schema_key_by_alias():
    bootstrap = SqlBootstrap.model_validate({"enabled": True, "admin": _ADMIN, "allowPlaintextExport": True})

    dumped = bootstrap.model_dump(by_alias=True)
    assert dumped["schema"] == "public"
    assert "schema_" not in dumped


@pytest.mark.parametrize("admin", [{"username": "", "password": "x"}, {"username": "x", "password": ""}])
def test_bootstrap_admin_credentials_must_not_be_empty(admin: dict[str, str]):
    with pytest.raises(ValidationError):
        SqlBootstrap.model_validate({"enabled": True, "admin": admin, "allowPlaintextExport": True})


_BOOTSTRAP = {"enabled": True, "admin": _ADMIN, "allowPlaintextExport": True}
_DOT_DELIMITER = _COLUMNAR | {"nestedVariableDelimiter": "."}


@pytest.mark.parametrize(
    "overrides",
    [{"bootstrap": _BOOTSTRAP}, {"outputs": [_BINARY]}, {"outputs": [_DOT_DELIMITER]}],
)
def test_questdb_rejects_unsupported_features(overrides: dict[str, object]):
    with pytest.raises(ValidationError, match="questdb_incompatible"):
        SqlEndpoint.model_validate(_endpoint(dbType="questdb", **overrides))


@pytest.mark.parametrize("db_type", ["postgresql", "timescaledb"])
def test_postgres_flavours_accept_all_features(db_type: str):
    SqlEndpoint.model_validate(
        _endpoint(dbType=db_type, bootstrap=_BOOTSTRAP, outputs=[_BINARY, _DOT_DELIMITER | {"id": 3}])
    )


def test_questdb_accepts_plain_columnar_output():
    SqlEndpoint.model_validate(_endpoint(dbType="questdb", outputs=[_COLUMNAR]))


def test_questdb_issues_carry_precise_locations():
    with pytest.raises(ValidationError) as exc_info:
        SqlEndpoint.model_validate(_endpoint(dbType="questdb", bootstrap=_BOOTSTRAP, outputs=[_BINARY, _DOT_DELIMITER]))

    assert {error["loc"] for error in exc_info.value.errors()} == {
        ("bootstrap",),
        ("outputs", 0),
        ("outputs", 1, "nestedVariableDelimiter"),
    }


def test_linked_files():
    endpoint = SqlEndpoint.model_validate(
        _endpoint(security={"tlsEnabled": True, "ca": "ca.pem", "certificate": "c.pem", "key": "k.pem"})
    )

    assert endpoint.linked_files() == [
        LinkedFile(endpoint_id=1, role="ca", name="ca.pem"),
        LinkedFile(endpoint_id=1, role="certificate", name="c.pem"),
        LinkedFile(endpoint_id=1, role="key", name="k.pem"),
    ]
    assert SqlEndpoint.model_validate(_endpoint()).linked_files() == []
