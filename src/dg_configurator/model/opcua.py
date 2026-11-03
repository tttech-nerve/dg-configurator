# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""OPC UA client endpoint and input models."""

from typing import Literal, Self

from pydantic import Field, model_validator

from .base import StrictModel
from .common import EndpointBase, InputBase, LinkedFile, MessageEncoding, SupportingFileName
from .limits import MAX_INPUTS_PER_ENDPOINT
from .mqtt import UserPasswordLogin

_INTERVAL_MAX_MS = 86400000


class OpcuaSecurity(StrictModel):
    """OPC UA security settings."""

    mode: Literal["None", "Sign", "SignAndEncrypt"] = "None"
    policy: Literal[
        "None", "Basic128Rsa15", "Basic256", "Basic256Sha256", "Aes128Sha256RsaOaep", "Aes256Sha256RsaPss"
    ] = "None"
    ca: SupportingFileName | None = None
    certificate: SupportingFileName | None = None
    key: SupportingFileName | None = None
    key_password: str | None = None


class OpcuaNode(StrictModel):
    """One OPC UA node to read."""

    node: str
    name_from_node_id: bool = Field(False, alias="nameFromNodeID")
    register_: bool = Field(False, alias="register")


class OpcuaInput(InputBase):
    """Polling or subscription based OPC UA input."""

    input_type: Literal["opcua-polling", "opcua-subscriber"]
    polling_interval_ms: int | None = Field(None, ge=1, le=_INTERVAL_MAX_MS, alias="pollingIntervalMS")
    sampling_interval_ms: int | None = Field(None, ge=1, le=_INTERVAL_MAX_MS, alias="samplingIntervalMS")
    publishing_interval_ms: int | None = Field(None, ge=1, le=_INTERVAL_MAX_MS, alias="publishingIntervalMS")
    nodes: list[OpcuaNode] = Field(min_length=1)

    @property
    def encoding(self) -> MessageEncoding:
        """OPC UA inputs always produce structured protobuf data."""
        return MessageEncoding.PROTOBUF

    @model_validator(mode="after")
    def _check_required_intervals(self) -> Self:
        if self.input_type == "opcua-polling" and self.polling_interval_ms is None:
            raise ValueError("pollingIntervalMS is required for inputType 'opcua-polling'")
        if self.input_type == "opcua-subscriber" and (
            self.sampling_interval_ms is None or self.publishing_interval_ms is None
        ):
            raise ValueError(
                "samplingIntervalMS and publishingIntervalMS are required for inputType 'opcua-subscriber'"
            )
        return self


class OpcuaEndpoint(EndpointBase):
    """OPC UA client endpoint (inputs only)."""

    endpoint_type: Literal["opcua-client"]
    url: str = Field(pattern=r"^opc\.tcp://")
    reconnect_interval: int = Field(5, ge=0, le=86400)
    login: UserPasswordLogin | None = None
    security: OpcuaSecurity = Field(default_factory=OpcuaSecurity)
    inputs: list[OpcuaInput] = Field(default_factory=list, max_length=MAX_INPUTS_PER_ENDPOINT)
    outputs: list[object] = Field(default_factory=list, max_length=0)

    def linked_files(self) -> list[LinkedFile]:
        """Return the CA, certificate and key files referenced by ``security``."""
        pairs = (("ca", self.security.ca), ("certificate", self.security.certificate), ("key", self.security.key))
        return [LinkedFile(endpoint_id=self.id, role=role, name=name) for role, name in pairs if name is not None]
