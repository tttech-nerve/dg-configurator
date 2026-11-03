# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for the OPC UA endpoint models."""

import pytest
from pydantic import ValidationError

from dg_configurator.model.common import LinkedFile, MessageEncoding
from dg_configurator.model.opcua import OpcuaEndpoint, OpcuaInput

_NODES = [{"node": "ns=2;s=T"}]


def _input(**overrides: object) -> dict[str, object]:
    return {"id": 1, "name": "i", "nodes": _NODES} | overrides


def test_polling_input_requires_polling_interval():
    with pytest.raises(ValidationError):
        OpcuaInput.model_validate(_input(inputType="opcua-polling"))

    parsed = OpcuaInput.model_validate(_input(inputType="opcua-polling", pollingIntervalMS=1000))
    assert parsed.encoding is MessageEncoding.PROTOBUF


@pytest.mark.parametrize("missing", ["samplingIntervalMS", "publishingIntervalMS"])
def test_subscriber_input_requires_both_intervals(missing: str):
    data = _input(inputType="opcua-subscriber", samplingIntervalMS=10, publishingIntervalMS=20)
    del data[missing]

    with pytest.raises(ValidationError):
        OpcuaInput.model_validate(data)


def test_subscriber_input_with_both_intervals_is_valid():
    OpcuaInput.model_validate(_input(inputType="opcua-subscriber", samplingIntervalMS=10, publishingIntervalMS=20))


@pytest.mark.parametrize("interval", [0, 86400001])
def test_intervals_are_range_checked(interval: int):
    with pytest.raises(ValidationError):
        OpcuaInput.model_validate(_input(inputType="opcua-polling", pollingIntervalMS=interval))


def test_input_requires_at_least_one_node():
    with pytest.raises(ValidationError):
        OpcuaInput.model_validate(
            {"id": 1, "name": "i", "inputType": "opcua-polling", "pollingIntervalMS": 1, "nodes": []}
        )


def _endpoint(**overrides: object) -> dict[str, object]:
    return {"id": 1, "name": "e", "endpointType": "opcua-client", "url": "opc.tcp://h:4840"} | overrides


def test_endpoint_defaults_and_outputs_must_be_empty():
    endpoint = OpcuaEndpoint.model_validate(_endpoint())

    assert endpoint.reconnect_interval == 5
    assert endpoint.security.mode == "None"
    with pytest.raises(ValidationError):
        OpcuaEndpoint.model_validate(_endpoint(outputs=[{"id": 1}]))


@pytest.mark.parametrize("security", [{"mode": "Other"}, {"policy": "Basic64"}])
def test_invalid_security_values_are_rejected(security: dict[str, str]):
    with pytest.raises(ValidationError):
        OpcuaEndpoint.model_validate(_endpoint(security=security))


def test_url_must_use_the_opc_tcp_scheme():
    with pytest.raises(ValidationError):
        OpcuaEndpoint.model_validate(_endpoint(url="http://h"))


def test_node_flags_use_schema_names():
    endpoint = OpcuaEndpoint.model_validate(
        _endpoint(
            inputs=[
                _input(
                    inputType="opcua-polling",
                    pollingIntervalMS=5,
                    nodes=[{"node": "n", "nameFromNodeID": True, "register": True}],
                )
            ]
        )
    )

    node = endpoint.inputs[0].nodes[0]
    assert node.name_from_node_id is True
    assert node.model_dump(by_alias=True) == {"node": "n", "nameFromNodeID": True, "register": True}


def test_linked_files():
    endpoint = OpcuaEndpoint.model_validate(
        _endpoint(security={"ca": "ca.pem", "certificate": "c.pem", "key": "k.pem"})
    )

    assert endpoint.linked_files() == [
        LinkedFile(endpoint_id=1, role="ca", name="ca.pem"),
        LinkedFile(endpoint_id=1, role="certificate", name="c.pem"),
        LinkedFile(endpoint_id=1, role="key", name="k.pem"),
    ]
    assert OpcuaEndpoint.model_validate(_endpoint()).linked_files() == []
