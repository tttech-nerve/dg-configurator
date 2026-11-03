# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""SQL client endpoint and output models (config version 1.1+)."""

from typing import Annotated, ClassVar, Literal, Self, Union

from pydantic import Field, model_validator

from .base import StrictModel
from .common import EndpointBase, LinkedFile, MessageEncoding, OutputBase, SupportingFileName, raise_coded_issues
from .limits import MAX_OUTPUTS_PER_ENDPOINT
from .mqtt import UserPasswordLogin
from .version import ConfigVersion

_RETENTION_MAX_MINUTES = 5256000


class SqlSecurity(StrictModel):
    """TLS settings of a SQL endpoint."""

    tls_enabled: bool = False
    ca: SupportingFileName | None = None
    certificate: SupportingFileName | None = None
    key: SupportingFileName | None = None
    tls_version: Literal["1.2", "1.3"] = "1.2"
    tls_insecure: bool = False


class SqlAdvanced(StrictModel):
    """Batching settings of a SQL endpoint."""

    batch_size: int = Field(1, ge=1)
    flush_interval_ms: int = Field(1000, ge=1, alias="flushIntervalMS")


class SqlBootstrapAdmin(StrictModel):
    """One-time administrative credential used to provision the gateway role."""

    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class SqlBootstrapExportUser(StrictModel):
    """Optional database user created for exporting the data."""

    username: str = Field(min_length=1)
    privilege: Literal["read-only", "read-write"]
    regenerate: str | None = None


class SqlBootstrap(StrictModel):
    """Self-provisioning of a least-privilege gateway role."""

    enabled: bool
    admin: SqlBootstrapAdmin
    gateway_role_name: str | None = Field(None, min_length=1)
    schema_: str = Field("public", min_length=1, alias="schema", serialization_alias="schema")
    rotate_admin_password: bool = True
    export_public_key: str | None = Field(None, min_length=1)
    allow_plaintext_export: bool = False
    export_user: SqlBootstrapExportUser | None = None

    @model_validator(mode="after")
    def _check_export_key(self) -> Self:
        if not self.allow_plaintext_export and self.export_public_key is None:
            raise ValueError("exportPublicKey is required unless allowPlaintextExport is true")
        return self


class SqlColumnarWriterOutput(OutputBase):
    """Writes structured data into one column per variable."""

    output_type: Literal["sql-columnar-writer"]
    table: str
    timestamp_column: str = "timestamp"
    exclude_variables: list[str] = Field(default_factory=list)
    auto_create_table: bool = False
    retention_period: int = Field(0, ge=0, le=_RETENTION_MAX_MINUTES)
    nested_variable_delimiter: Literal["_", "-", "."] = "_"

    @classmethod
    def accepts(cls, encoding: MessageEncoding) -> bool:
        """Accept any structured payload format."""
        return encoding in (MessageEncoding.JSON, MessageEncoding.PROTOBUF)


class SqlBinaryWriterOutput(OutputBase):
    """Writes binary payloads into a single data column."""

    output_type: Literal["sql-binary-writer"]
    table: str
    timestamp_column: str = "timestamp"
    data_column: str = "data"
    auto_create_table: bool = False
    retention_period: int = Field(0, ge=0, le=_RETENTION_MAX_MINUTES)

    @classmethod
    def accepts(cls, encoding: MessageEncoding) -> bool:
        """Accept binary payloads only."""
        return encoding == MessageEncoding.BINARY


SqlOutput = Annotated[
    Union[SqlColumnarWriterOutput, SqlBinaryWriterOutput],  # noqa: UP007 - needed for the discriminated union
    Field(discriminator="output_type"),
]


class SqlEndpoint(EndpointBase):
    """SQL database endpoint (outputs only)."""

    MIN_CONFIG_VERSION: ClassVar[ConfigVersion] = ConfigVersion.V1_1

    endpoint_type: Literal["sql-client"]
    db_type: Literal["postgresql", "timescaledb", "questdb"]
    host: str
    port: int | None = Field(None, ge=1, le=65535)
    ilp_port: int = Field(9000, ge=1, le=65535)
    database: str | None = None
    reconnect_interval: int = Field(5, ge=0, le=86400)
    login: UserPasswordLogin | None = None
    security: SqlSecurity = Field(default_factory=SqlSecurity)
    advanced: SqlAdvanced = Field(default_factory=SqlAdvanced)
    bootstrap: SqlBootstrap | None = None
    inputs: list[object] = Field(default_factory=list, max_length=0)
    outputs: list[SqlOutput] = Field(default_factory=list, max_length=MAX_OUTPUTS_PER_ENDPOINT)

    @model_validator(mode="after")
    def _check_questdb_compatibility(self) -> Self:
        if self.db_type != "questdb":
            return self
        issues: list[tuple[str, tuple[str | int, ...], str]] = []
        if self.bootstrap is not None:
            issues.append(("questdb_incompatible", ("bootstrap",), "bootstrap is not supported for dbType 'questdb'"))
        for index, output in enumerate(self.outputs):
            if isinstance(output, SqlBinaryWriterOutput):
                issues.append(
                    (
                        "questdb_incompatible",
                        ("outputs", index),
                        "sql-binary-writer is not supported for dbType 'questdb'",
                    )
                )
            elif output.nested_variable_delimiter == ".":
                issues.append(
                    (
                        "questdb_incompatible",
                        ("outputs", index, "nestedVariableDelimiter"),
                        "nestedVariableDelimiter '.' is not supported for dbType 'questdb'",
                    )
                )
        raise_coded_issues("SqlEndpoint", issues)
        return self

    def linked_files(self) -> list[LinkedFile]:
        """Return the CA, certificate and key files referenced by ``security``."""
        pairs = (("ca", self.security.ca), ("certificate", self.security.certificate), ("key", self.security.key))
        return [LinkedFile(endpoint_id=self.id, role=role, name=name) for role, name in pairs if name is not None]
