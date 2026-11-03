# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Request/response DTOs for the dg-configurator HTTP API."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from ..pki import Usage


class ValidateRequest(BaseModel):
    """Body of POST /api/validate."""

    config: dict[str, Any]
    files: list[str] = Field(default_factory=list)


class DiagnosticDto(BaseModel):
    """One diagnostic, matching validation.Diagnostic field-for-field."""

    severity: str
    code: str
    path: list[str | int]
    message: str
    line: int | None = None
    column: int | None = None


class ValidationReportDto(BaseModel):
    """Matches validation.ValidationReport."""

    valid: bool
    version: str | None
    diagnostics: list[DiagnosticDto]


class FileDto(BaseModel):
    """One supporting file, base64-encoded for JSON transport."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    name: str
    content_base64: str = Field(alias="contentBase64")


class ImportResponse(BaseModel):
    """Body of the POST /api/import response."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    config: Any
    layout: dict[str, Any] | None
    files: list[FileDto]
    package_kind: str = Field(alias="packageKind")
    signature: str | None
    report: ValidationReportDto


class EndpointMeta(BaseModel):
    """One row of the endpoint-type catalog returned by GET /api/meta."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    endpoint_type: str = Field(alias="endpointType")
    min_version: str = Field(alias="minVersion")
    input_types: list[str] = Field(alias="inputTypes")
    output_types: list[str] = Field(alias="outputTypes")


class UsageMeta(BaseModel):
    """One certificate usage profile, as shown by the PKI dialog."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    usage: str
    label: str
    role: Literal["ca", "server", "client", "application"]
    requires_san: bool = Field(alias="requiresSan")
    requires_application_uri: bool = Field(alias="requiresApplicationUri")
    allowed_keys: list[str] = Field(alias="allowedKeys")
    default_validity_days: int = Field(alias="defaultValidityDays")
    max_validity_days: int = Field(alias="maxValidityDays")
    common_name_hint: str = Field(alias="commonNameHint")
    notes: list[str]


class PkiMeta(BaseModel):
    """The PKI catalog returned by GET /api/meta."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    usages: list[UsageMeta]
    keys: list[str]
    domains: dict[str, dict[str, str]]


class MetaResponse(BaseModel):
    """Body of GET /api/meta."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    tool_version: str = Field(alias="toolVersion")
    config_versions: list[str] = Field(alias="configVersions")
    endpoint_types: list[EndpointMeta] = Field(alias="endpointTypes")
    limits: dict[str, int]
    pki: PkiMeta


class GeneratedFileDto(BaseModel):
    """One generated file (key material, certificate), base64-encoded for JSON transport."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    name: str
    content_base64: str = Field(alias="contentBase64")
    secret: bool = False


class KeypairRequest(BaseModel):
    """Body of POST /api/keypair."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    bits: Literal[2048, 3072, 4096] = 4096
    passphrase: SecretStr | None = None


class KeypairResponse(BaseModel):
    """Body of the POST /api/keypair response."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    files: list[GeneratedFileDto]
    public_key_base64_der: str = Field(alias="publicKeyBase64Der")
    warnings: list[str] = Field(default_factory=list)


class SubjectDto(BaseModel):
    """Distinguished-name fields of a certificate subject."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    common_name: str = Field(alias="commonName")
    organization: str | None = None
    organizational_unit: str | None = Field(None, alias="organizationalUnit")
    country: str | None = None
    state: str | None = None
    locality: str | None = None


class SanDto(BaseModel):
    """Subject alternative names."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    dns: list[str] = Field(default_factory=list)
    ip: list[str] = Field(default_factory=list)
    uri: list[str] = Field(default_factory=list)
    email: list[str] = Field(default_factory=list)


class LeafDto(BaseModel):
    """One end-entity certificate of a PKI request."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    usage: Usage
    subject: SubjectDto
    san: SanDto = Field(default_factory=SanDto)
    key: str = "rsa-4096"
    validity_days: int | None = Field(None, alias="validityDays")
    passphrase: SecretStr | None = None
    basename: str | None = None


class CaDto(BaseModel):
    """A new CA of a PKI request."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    subject: SubjectDto
    key: str = "rsa-4096"
    validity_days: int | None = Field(None, alias="validityDays")
    passphrase: SecretStr | None = None
    basename: str = "ca"


class ExistingCaDto(BaseModel):
    """An existing CA (base64 PEM certificate and key) of a PKI request."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    certificate_base64: str = Field(alias="certificateBase64")
    private_key_base64: str = Field(alias="privateKeyBase64")
    passphrase: SecretStr | None = None


class PkiGenerateRequest(BaseModel):
    """Body of POST /api/pki/generate."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    issuer: Literal["new-ca", "existing-ca", "self-signed", "ca-only"]
    ca: CaDto | None = None
    existing_ca: ExistingCaDto | None = Field(None, alias="existingCa")
    leaves: list[LeafDto] = Field(default_factory=list, max_length=20)


class CertificateSummaryDto(BaseModel):
    """Facts about one generated certificate."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    file: str
    subject: str
    issuer: str
    serial_hex: str = Field(alias="serialHex")
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime = Field(alias="notAfter")
    sha256_fingerprint: str = Field(alias="sha256Fingerprint")
    usage: str
    key: str
    san: list[str]


class PkiGenerateResponse(BaseModel):
    """Body of the POST /api/pki/generate response."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    files: list[GeneratedFileDto]
    certificates: list[CertificateSummaryDto]
    warnings: list[str]


class ConvertResponse(BaseModel):
    """Body of the POST /api/pki/convert response."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, serialize_by_alias=True)

    files: list[GeneratedFileDto]
    warnings: list[str]
    detected: list[str]
