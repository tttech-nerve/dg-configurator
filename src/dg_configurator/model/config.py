# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""UserConfig — the root config.json model, with cross-object validation."""

from typing import Annotated, Self, Union

from pydantic import Field, model_validator

from .base import StrictModel
from .common import LinkedFile, raise_coded_issues
from .connection import Connection
from .limits import MAX_ENDPOINTS
from .mqtt import MqttEndpoint, MqttPublisherOutput, MqttSubscriberInput
from .opcua import OpcuaEndpoint
from .password_policy import PasswordPolicy
from .sql import SqlEndpoint
from .version import ConfigVersion

EndpointUnion = Annotated[
    Union[MqttEndpoint, OpcuaEndpoint, SqlEndpoint],  # noqa: UP007 - needed for the discriminated union
    Field(discriminator="endpoint_type"),
]

Issue = tuple[str, tuple[str | int, ...], str]


def _required_version(obj: object) -> ConfigVersion:
    """Return the lowest config version in which ``obj`` is legal.

    Besides whole types (``MIN_CONFIG_VERSION``), v1.1 added a few fields and the ``binary`` message format to
    types that already exist in v1.0.
    """
    if isinstance(obj, MqttSubscriberInput) and (obj.message_format == "binary" or obj.variable_schema is not None):
        return ConfigVersion.V1_1
    if isinstance(obj, MqttPublisherOutput) and "timestamp_format" in obj.model_fields_set:
        return ConfigVersion.V1_1
    return getattr(type(obj), "MIN_CONFIG_VERSION", ConfigVersion.V1_0)


class UserConfig(StrictModel):
    """Root model of a Nerve Data Gateway config.json document."""

    json_schema_url: str | None = Field(default=None, alias="$schema", exclude=True)
    version: ConfigVersion
    endpoints: list[EndpointUnion] = Field(max_length=MAX_ENDPOINTS)
    connections: list[Connection]
    password_policy: PasswordPolicy = Field(default_factory=PasswordPolicy)

    @model_validator(mode="after")
    def _check_cross_object_rules(self) -> Self:
        issues: list[Issue] = []
        issues.extend(self._version_issues())
        issues.extend(self._duplicate_id_issues())
        issues.extend(self._connection_issues())
        raise_coded_issues("UserConfig", issues)
        return self

    def _version_issues(self) -> list[Issue]:
        issues: list[Issue] = []
        if "password_policy" in self.model_fields_set and self.version < _required_version(self.password_policy):
            issues.append(("version_too_low", ("passwordPolicy",), "passwordPolicy requires config version 1.1"))
        for e_idx, ep in enumerate(self.endpoints):
            if self.version < _required_version(ep):
                message = f"endpointType '{ep.endpoint_type}' requires config version {_required_version(ep)}"
                issues.append(("version_too_low", ("endpoints", e_idx), message))
            for i_idx, inp in enumerate(ep.inputs):
                if self.version < _required_version(inp):
                    message = f"this input requires config version {_required_version(inp)}"
                    issues.append(("version_too_low", ("endpoints", e_idx, "inputs", i_idx), message))
            for o_idx, out in enumerate(ep.outputs):
                if self.version < _required_version(out):
                    message = f"this output requires config version {_required_version(out)}"
                    issues.append(("version_too_low", ("endpoints", e_idx, "outputs", o_idx), message))
        return issues

    def _duplicate_id_issues(self) -> list[Issue]:
        issues: list[Issue] = []
        seen_endpoints: set[int] = set()
        for e_idx, ep in enumerate(self.endpoints):
            if ep.id in seen_endpoints:
                issues.append(("duplicate_id", ("endpoints", e_idx, "id"), f"duplicate endpoint id {ep.id}"))
            seen_endpoints.add(ep.id)
            seen_inputs: set[int] = set()
            for i_idx, inp in enumerate(ep.inputs):
                if inp.id in seen_inputs:
                    message = f"duplicate input id {inp.id} on endpoint {ep.id}"
                    issues.append(("duplicate_id", ("endpoints", e_idx, "inputs", i_idx, "id"), message))
                seen_inputs.add(inp.id)
            seen_outputs: set[int] = set()
            for o_idx, out in enumerate(ep.outputs):
                if out.id in seen_outputs:
                    message = f"duplicate output id {out.id} on endpoint {ep.id}"
                    issues.append(("duplicate_id", ("endpoints", e_idx, "outputs", o_idx, "id"), message))
                seen_outputs.add(out.id)
        seen_connections: set[int] = set()
        for c_idx, conn in enumerate(self.connections):
            if conn.id in seen_connections:
                issues.append(("duplicate_id", ("connections", c_idx, "id"), f"duplicate connection id {conn.id}"))
            seen_connections.add(conn.id)
        return issues

    def _connection_issues(self) -> list[Issue]:
        issues: list[Issue] = []
        # first occurrence wins, so duplicate ids resolve deterministically
        endpoints = {}
        for ep in reversed(self.endpoints):
            endpoints[ep.id] = ep
        connected_inputs: set[tuple[int, int]] = set()
        connected_outputs: set[tuple[int, int]] = set()

        for c_idx, conn in enumerate(self.connections):
            src_ep = endpoints.get(conn.source.endpoint)
            src_input = next((i for i in src_ep.inputs if i.id == conn.source.input), None) if src_ep else None
            dst_ep = endpoints.get(conn.destination.endpoint)
            dst_output = next((o for o in dst_ep.outputs if o.id == conn.destination.output), None) if dst_ep else None

            if src_input is None:
                field = "endpoint" if src_ep is None else "input"
                issues.append(
                    (
                        "dangling_reference",
                        ("connections", c_idx, "source", field),
                        "source does not resolve to an input",
                    )
                )
            if dst_output is None:
                field = "endpoint" if dst_ep is None else "output"
                issues.append(
                    (
                        "dangling_reference",
                        ("connections", c_idx, "destination", field),
                        "destination does not resolve to an output",
                    )
                )
            if src_input is not None:
                connected_inputs.add((conn.source.endpoint, conn.source.input))
            if dst_output is not None:
                connected_outputs.add((conn.destination.endpoint, conn.destination.output))
            if src_input is not None and dst_output is not None and not dst_output.accepts(src_input.encoding):
                issues.append(
                    (
                        "encoding_mismatch",
                        ("connections", c_idx),
                        f"destination output does not accept the '{src_input.encoding}' encoding of the source input",
                    )
                )

        for e_idx, ep in enumerate(self.endpoints):
            for i_idx, inp in enumerate(ep.inputs):
                if (ep.id, inp.id) not in connected_inputs:
                    message = f"input {inp.id} on endpoint {ep.id} has no connection"
                    issues.append(("orphan_port", ("endpoints", e_idx, "inputs", i_idx), message))
            for o_idx, out in enumerate(ep.outputs):
                if (ep.id, out.id) not in connected_outputs:
                    message = f"output {out.id} on endpoint {ep.id} has no connection"
                    issues.append(("orphan_port", ("endpoints", e_idx, "outputs", o_idx), message))
        return issues

    def linked_files(self) -> list[LinkedFile]:
        """Return every supporting file referenced by any endpoint."""
        return [file for endpoint in self.endpoints for file in endpoint.linked_files()]
