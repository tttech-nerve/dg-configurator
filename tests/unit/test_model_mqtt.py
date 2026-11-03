# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for the MQTT endpoint models."""

import pytest
from pydantic import ValidationError

from dg_configurator.model.common import LinkedFile, MessageEncoding
from dg_configurator.model.mqtt import MqttEndpoint, MqttPublisherOutput, MqttSubscriberInput, VariableSchemaNode


def _endpoint(**overrides: object) -> dict[str, object]:
    return {"id": 1, "name": "e", "endpointType": "mqtt-client", "url": "mqtt://h:1883"} | overrides


def test_defaults_match_the_schema():
    endpoint = MqttEndpoint.model_validate(_endpoint())

    assert endpoint.reconnect_interval == 5
    assert endpoint.client_id == "data-gateway-client"
    assert endpoint.security.tls_version == "1.3"
    assert endpoint.advanced.keep_alive == 60
    assert endpoint.advanced.will_qos == 1
    assert endpoint.login is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"url": "http://h"},
        {"reconnectInterval": 86401},
        {"version": "3.1"},
        {"advanced": {"keepAlive": 65536}},
        {"security": {"tlsVersion": "1.0"}},
        {"endpointType": "other"},
    ],
)
def test_invalid_values_are_rejected(overrides: dict[str, object]):
    with pytest.raises(ValidationError):
        MqttEndpoint.model_validate(_endpoint(**overrides))


@pytest.mark.parametrize(
    ("url", "tls_enabled", "valid"),
    [("mqtts://h", False, False), ("mqtts://h", True, True), ("mqtt://h", True, False), ("mqtt://h", False, True)],
)
def test_url_scheme_must_match_tls_flag(url: str, tls_enabled: bool, valid: bool):
    data = _endpoint(url=url, security={"tlsEnabled": tls_enabled})

    if valid:
        MqttEndpoint.model_validate(data)
    else:
        with pytest.raises(ValidationError, match="url scheme does not match security.tlsEnabled"):
            MqttEndpoint.model_validate(data)


def test_linked_files_lists_ca_certificate_and_key_in_order():
    endpoint = MqttEndpoint.model_validate(
        _endpoint(
            url="mqtts://h",
            security={"tlsEnabled": True, "key": "k.pem", "ca": "ca.pem", "certificate": "certs/c.pem"},
        )
    )

    assert endpoint.linked_files() == [
        LinkedFile(endpoint_id=1, role="ca", name="ca.pem"),
        LinkedFile(endpoint_id=1, role="certificate", name="certs/c.pem"),
        LinkedFile(endpoint_id=1, role="key", name="k.pem"),
    ]


def test_linked_files_is_empty_without_security_files():
    assert MqttEndpoint.model_validate(_endpoint()).linked_files() == []


def test_subscriber_requires_at_least_one_topic():
    with pytest.raises(ValidationError):
        MqttSubscriberInput.model_validate(
            {"id": 1, "name": "i", "inputType": "mqtt-subscriber", "messageFormat": "json", "topics": []}
        )


@pytest.mark.parametrize("message_format", ["json", "binary", "protobuf"])
def test_subscriber_encoding_is_its_message_format(message_format: str):
    subscriber = MqttSubscriberInput.model_validate(
        {
            "id": 1,
            "name": "i",
            "inputType": "mqtt-subscriber",
            "messageFormat": message_format,
            "topics": [{"topic": "a/#"}],
        }
    )

    assert subscriber.encoding == MessageEncoding(message_format)
    assert subscriber.topics[0].qos == 0
    assert subscriber.topics[0].rate_limit == 0


def _publisher(message_format: str) -> dict[str, object]:
    return {"id": 1, "name": "o", "outputType": "mqtt-publisher", "messageFormat": message_format, "topic": "t"}


@pytest.mark.parametrize("message_format", ["json", "protobuf"])
def test_publisher_accepts_any_non_binary_format(message_format: str):
    publisher = MqttPublisherOutput.model_validate(_publisher(message_format))

    assert publisher.accepts(MessageEncoding.JSON)
    assert publisher.accepts(MessageEncoding.PROTOBUF)
    assert not publisher.accepts(MessageEncoding.BINARY)
    assert publisher.timestamp_format == "unix-ns"


def test_publisher_rejects_binary_format():
    with pytest.raises(ValidationError):
        MqttPublisherOutput.model_validate(_publisher("binary"))


def test_variable_schema_accepts_nested_types_and_rejects_unknown_ones():
    assert VariableSchemaNode.model_validate({"a": "int32[]", "b": {"c": "string"}})
    with pytest.raises(ValidationError):
        VariableSchemaNode.model_validate({"a": "int8"})
    with pytest.raises(ValidationError):
        VariableSchemaNode.model_validate({"not valid!": "bool"})
