# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""MQTT client endpoint, subscriber input and publisher output models."""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, RootModel, StringConstraints, model_validator

from .base import StrictModel
from .common import EndpointBase, InputBase, LinkedFile, MessageEncoding, OutputBase, SupportingFileName
from .limits import MAX_INPUTS_PER_ENDPOINT, MAX_OUTPUTS_PER_ENDPOINT


class UserPasswordLogin(StrictModel):
    """Username/password credentials. Omit the whole object for anonymous access."""

    username: str | None = None
    password: str | None = None


class MqttSecurity(StrictModel):
    """TLS settings of an MQTT endpoint."""

    tls_enabled: bool = False
    ca: SupportingFileName | None = None
    certificate: SupportingFileName | None = None
    key: SupportingFileName | None = None
    key_password: str | None = None
    tls_version: Literal["1.2", "1.3"] = "1.3"
    tls_insecure: bool = False


class MqttAdvanced(StrictModel):
    """Advanced MQTT connection settings."""

    keep_alive: int = Field(60, ge=0, le=65535)
    clean_session: bool = False
    will_topic: str | None = None
    will_message: str | None = None
    will_qos: int = Field(1, ge=0, le=2, alias="willQoS")
    will_retain: bool = False


_SCALARS = ("bool", "int16", "uint16", "int32", "uint32", "int64", "uint64", "float", "double", "string", "datetime")

VariableLeafType = StrEnum(
    "VariableLeafType",
    {s: s for s in _SCALARS} | {f"{s}_array": f"{s}[]" for s in _SCALARS},
)

_VariableName = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_]+$")]


class VariableSchemaNode(RootModel[VariableLeafType | dict[_VariableName, "VariableSchemaNode"]]):  # type: ignore[valid-type]
    """Either a leaf type or a nested object mapping child variable names to nodes."""


VariableSchemaNode.model_rebuild()


class MqttTopicSubscription(StrictModel):
    """One subscribed topic (``+`` and ``#`` wildcards are allowed)."""

    topic: str
    qos: int = Field(0, ge=0, le=2)
    rate_limit: int = Field(0, ge=0)


class MqttSubscriberInput(InputBase):
    """Input that subscribes to MQTT topics."""

    input_type: Literal["mqtt-subscriber"]
    message_format: Literal[MessageEncoding.JSON, MessageEncoding.BINARY, MessageEncoding.PROTOBUF]
    variable_schema: VariableSchemaNode | None = None
    topics: list[MqttTopicSubscription] = Field(min_length=1)

    @property
    def encoding(self) -> MessageEncoding:
        """The message format this input produces."""
        return MessageEncoding(self.message_format)


class MqttPublisherOutput(OutputBase):
    """Output that publishes to an MQTT topic."""

    output_type: Literal["mqtt-publisher"]
    message_format: Literal[MessageEncoding.JSON, MessageEncoding.PROTOBUF]
    topic: str
    qos: int = Field(0, ge=0, le=2)
    timestamp_format: Literal["unix-ns", "rfc3339nano"] = "unix-ns"

    def accepts(self, encoding: MessageEncoding) -> bool:
        """Accept any structured (non-binary) payload; the gateway converts it to the configured message format."""
        return encoding != MessageEncoding.BINARY


class MqttEndpoint(EndpointBase):
    """MQTT client endpoint."""

    endpoint_type: Literal["mqtt-client"]
    url: str = Field(pattern=r"^mqtts?://")
    reconnect_interval: int = Field(5, ge=0, le=86400)
    version: Literal["5.0"] = "5.0"
    client_id: str = Field("data-gateway-client", alias="clientID")
    websockets: bool = False
    login: UserPasswordLogin | None = None
    security: MqttSecurity = Field(default_factory=MqttSecurity)
    advanced: MqttAdvanced = Field(default_factory=MqttAdvanced)
    inputs: list[MqttSubscriberInput] = Field(default_factory=list, max_length=MAX_INPUTS_PER_ENDPOINT)
    outputs: list[MqttPublisherOutput] = Field(default_factory=list, max_length=MAX_OUTPUTS_PER_ENDPOINT)

    @model_validator(mode="after")
    def _check_url_scheme(self) -> Self:
        if self.url.startswith("mqtt://") and self.security.tls_enabled:
            raise ValueError("url scheme does not match security.tlsEnabled: mqtt:// requires tlsEnabled=false")
        if self.url.startswith("mqtts://") and not self.security.tls_enabled:
            raise ValueError("url scheme does not match security.tlsEnabled: mqtts:// requires tlsEnabled=true")
        return self

    def linked_files(self) -> list[LinkedFile]:
        """Return the CA, certificate and key files referenced by ``security``."""
        pairs = (("ca", self.security.ca), ("certificate", self.security.certificate), ("key", self.security.key))
        return [LinkedFile(endpoint_id=self.id, role=role, name=name) for role, name in pairs if name is not None]
