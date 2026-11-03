# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""HTTP API routes: meta, schema, validate, import, package, project, keypair and the pki/* routes."""

import base64
import binascii
import io
import json
import re
import zipfile
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, File, Form, HTTPException, Response, UploadFile
from pydantic import SecretStr, ValidationError

from .. import __version__
from ..errors import ConversionError, InvalidPackageError, KeyLoadError, PkiError, UnsafeArchiveError
from ..files import collect_supporting_files
from ..layout import auto_layout
from ..model import UserConfig
from ..model.limits import MAX_ENDPOINTS, MAX_INPUTS_PER_ENDPOINT, MAX_OUTPUTS_PER_ENDPOINT
from ..model.version import ConfigVersion
from ..packaging import build_plain_zip, build_signed_zip, dump_config, read_package
from ..pki import (
    ALLOWED_KEYS,
    PROFILES,
    CaRequest,
    ExistingCa,
    KeySpec,
    LeafRequest,
    PkiRequest,
    SanSpec,
    SubjectSpec,
    Usage,
    generate_pki,
)
from ..pki.convert import MAX_INPUT_BYTES, convert_to_pem
from ..pki.profiles import client_usage_for, server_usage_for
from ..project import write_project
from ..signing import RECOMMENDED_KEY_BITS, generate_keypair, load_private_key, load_public_key
from ..validation import ValidationReport, validate
from .dto import (
    CaDto,
    CertificateSummaryDto,
    ConvertResponse,
    DiagnosticDto,
    EndpointMeta,
    FileDto,
    GeneratedFileDto,
    ImportResponse,
    KeypairRequest,
    KeypairResponse,
    LeafDto,
    MetaResponse,
    PkiGenerateRequest,
    PkiGenerateResponse,
    PkiMeta,
    SubjectDto,
    UsageMeta,
    ValidateRequest,
    ValidationReportDto,
)

router = APIRouter()

_ZIP_MEDIA_TYPE = "application/zip"
_ARCHIVE_NAME = re.compile(r"[A-Za-z0-9._-]+\.pem")
_PRIVATE_FILE_MODE = 0o600
_PUBLIC_FILE_MODE = 0o644
_PKI_DOMAINS = ("opcua", "mqtt", "sql", "tls")

_ENDPOINT_CATALOG = [
    EndpointMeta(
        endpointType="mqtt-client", minVersion="1.0", inputTypes=["mqtt-subscriber"], outputTypes=["mqtt-publisher"]
    ),
    EndpointMeta(
        endpointType="opcua-client",
        minVersion="1.0",
        inputTypes=["opcua-polling", "opcua-subscriber"],
        outputTypes=[],
    ),
    EndpointMeta(
        endpointType="sql-client",
        minVersion="1.1",
        inputTypes=[],
        outputTypes=["sql-columnar-writer", "sql-binary-writer"],
    ),
]


def _usage_role(usage: Usage) -> str:
    if usage is Usage.CA:
        return "ca"
    if usage is Usage.OPCUA_APPLICATION:
        return "application"
    return "server" if usage.value.endswith("-server") else "client"


def _pki_meta() -> PkiMeta:
    return PkiMeta(
        usages=[
            UsageMeta(
                usage=usage.value,
                label=profile.label,
                role=_usage_role(usage),
                requiresSan=profile.requires_san,
                requiresApplicationUri=profile.requires_application_uri,
                allowedKeys=[spec.label for spec in profile.allowed_keys],
                defaultValidityDays=profile.default_validity_days,
                maxValidityDays=profile.max_validity_days,
                commonNameHint=profile.common_name_hint,
                notes=list(profile.notes),
            )
            for usage, profile in PROFILES.items()
        ],
        keys=[spec.label for spec in ALLOWED_KEYS],
        domains={
            domain: {"server": server_usage_for(domain).value, "client": client_usage_for(domain).value}
            for domain in _PKI_DOMAINS
        },
    )


def _report_to_dto(report: ValidationReport) -> ValidationReportDto:
    return ValidationReportDto(
        valid=report.valid,
        version=report.version,
        diagnostics=[
            DiagnosticDto(
                severity=d.severity,
                code=d.code,
                path=list(d.path),
                message=d.message,
                line=d.line,
                column=d.column,
            )
            for d in report.diagnostics
        ],
    )


async def _read_json_upload(upload: UploadFile, what: str) -> Any:  # noqa: ANN401 - any JSON value
    try:
        return json.loads(await upload.read())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{what} is not valid JSON: {exc}") from exc


def _parse_json_field(text: str, what: str) -> Any:  # noqa: ANN401 - any JSON value
    try:
        return json.loads(text)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{what} is not valid JSON: {exc}") from exc


async def _read_upload_files(files: list[UploadFile]) -> dict[str, bytes]:
    return {upload.filename: await upload.read() for upload in files if upload.filename}


def _parse_config(document: Any) -> UserConfig:  # noqa: ANN401 - any JSON value
    try:
        return UserConfig.model_validate(document)
    except ValidationError as exc:
        report = validate(json.dumps(document))
        raise HTTPException(status_code=422, detail=_report_to_dto(report).model_dump()) from exc


@router.get("/meta", response_model=MetaResponse)
def get_meta() -> MetaResponse:
    """Return the tool version, supported config versions and the endpoint-type catalog."""
    return MetaResponse(
        toolVersion=__version__,
        configVersions=[v.value for v in ConfigVersion],
        endpointTypes=_ENDPOINT_CATALOG,
        limits={
            "maxEndpoints": MAX_ENDPOINTS,
            "maxInputsPerEndpoint": MAX_INPUTS_PER_ENDPOINT,
            "maxOutputsPerEndpoint": MAX_OUTPUTS_PER_ENDPOINT,
        },
        pki=_pki_meta(),
    )


@router.get("/schema/{config_version}")
def get_schema(config_version: str) -> dict[str, Any]:
    """Return the JSON Schema generated from the model."""
    try:
        ConfigVersion(config_version)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=f"unknown config version {config_version!r}") from exc
    return UserConfig.model_json_schema(by_alias=True)


@router.post("/validate", response_model=ValidationReportDto)
def post_validate(body: ValidateRequest) -> ValidationReportDto:
    """Validate a config document against the model and the available supporting files."""
    report = validate(json.dumps(body.config).encode("utf-8"), available_files=set(body.files))
    return _report_to_dto(report)


@router.post("/import", response_model=ImportResponse)
async def post_import(
    file: Annotated[UploadFile, File()], public_key: Annotated[str | None, Form(alias="publicKey")] = None
) -> ImportResponse:
    """Read a config.json, plain/signed zip or .dgproj and return it for editing."""
    data = await file.read()
    public_key_object = None
    if public_key:
        try:
            public_key_object = load_public_key(public_key)
        except KeyLoadError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        loaded = read_package(data, public_key=public_key_object)
    except (InvalidPackageError, UnsafeArchiveError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    report = validate(loaded.config_json, available_files=set(loaded.files))
    config_document = json.loads(loaded.config_json)
    layout = loaded.layout
    if layout is None and report.valid:
        layout = auto_layout(UserConfig.model_validate(config_document))

    return ImportResponse(
        config=config_document,
        layout=layout,
        files=[
            FileDto(name=name, contentBase64=base64.b64encode(content).decode("ascii"))
            for name, content in loaded.files.items()
        ],
        packageKind=loaded.kind,
        signature=loaded.signature_status,
        report=_report_to_dto(report),
    )


@router.post("/package")
async def post_package(
    config: Annotated[UploadFile, File()],
    files: Annotated[list[UploadFile] | None, File()] = None,
    signing_key: Annotated[UploadFile | None, File(alias="signingKey")] = None,
    key_password: Annotated[str | None, Form(alias="keyPassword")] = None,
) -> Response:
    """Build a plain or signed deploy package from the posted config and supporting files."""
    user_config = _parse_config(await _read_json_upload(config, "config"))
    config_json = dump_config(user_config)
    available = await _read_upload_files(files or [])
    used_files, missing = collect_supporting_files(user_config, available)
    if missing:
        raise HTTPException(status_code=422, detail=f"missing supporting files: {missing}")

    if signing_key is not None:
        password = key_password.encode("utf-8") if key_password else None
        try:
            private_key = load_private_key(await signing_key.read(), password)
        except KeyLoadError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        data = build_signed_zip(config_json, used_files, private_key)
    else:
        data = build_plain_zip(config_json, used_files)

    return _zip_response(data, "config.zip")


@router.post("/project")
async def post_project(
    config: Annotated[UploadFile, File()],
    layout: Annotated[str, Form()],
    files: Annotated[list[UploadFile] | None, File()] = None,
) -> Response:
    """Build a .dgproj archive from the posted config, layout and supporting files."""
    user_config = _parse_config(await _read_json_upload(config, "config"))
    layout_document = _parse_json_field(layout, "layout")
    if not isinstance(layout_document, dict):
        raise HTTPException(status_code=422, detail="layout must be a JSON object")
    data = write_project(dump_config(user_config), await _read_upload_files(files or []), layout_document)
    return _zip_response(data, "project.dgproj")


@router.post("/keypair", response_model=KeypairResponse)
def post_keypair(body: KeypairRequest) -> KeypairResponse:
    """Generate an RSA signing key pair; nothing is stored on the server."""
    passphrase = body.passphrase.get_secret_value().encode("utf-8") if body.passphrase else None
    keypair = generate_keypair(bits=body.bits, passphrase=passphrase)
    warnings: list[str] = []
    if body.bits < RECOMMENDED_KEY_BITS:
        warnings.append("RSA keys below 4096 bits go against the Data Gateway hardening guideline")
    if passphrase is None:
        warnings.append("The private key is not protected by a passphrase")
    return KeypairResponse(
        files=[
            _generated_file("private.pem", keypair.private_pem, secret=True),
            _generated_file("public.pem", keypair.public_pem),
            _generated_file("public.txt", f"{keypair.public_b64der}\n".encode("ascii")),
        ],
        publicKeyBase64Der=keypair.public_b64der,
        warnings=warnings,
    )


def _generated_file(name: str, content: bytes, *, secret: bool = False) -> GeneratedFileDto:
    return GeneratedFileDto(name=name, contentBase64=base64.b64encode(content).decode("ascii"), secret=secret)


def _secret_bytes(value: SecretStr | None) -> bytes | None:
    return value.get_secret_value().encode("utf-8") if value else None


def _subject_spec(dto: SubjectDto) -> SubjectSpec:
    return SubjectSpec(
        common_name=dto.common_name.strip(),
        organization=dto.organization,
        organizational_unit=dto.organizational_unit,
        country=dto.country,
        state=dto.state,
        locality=dto.locality,
    )


def _names(values: list[str]) -> tuple[str, ...]:
    return tuple(stripped for value in values if (stripped := value.strip()))


def _leaf_request(dto: LeafDto) -> LeafRequest:
    return LeafRequest(
        usage=dto.usage,
        subject=_subject_spec(dto.subject),
        san=SanSpec(
            dns_names=_names(dto.san.dns),
            ip_addresses=_names(dto.san.ip),
            uris=_names(dto.san.uri),
            emails=_names(dto.san.email),
        ),
        key=KeySpec.parse(dto.key),
        validity_days=dto.validity_days,
        passphrase=_secret_bytes(dto.passphrase),
        basename=dto.basename or None,
    )


def _ca_request(dto: CaDto) -> CaRequest:
    return CaRequest(
        subject=_subject_spec(dto.subject),
        key=KeySpec.parse(dto.key),
        validity_days=dto.validity_days,
        passphrase=_secret_bytes(dto.passphrase),
        basename=dto.basename,
    )


def _decode_base64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise HTTPException(status_code=422, detail="existingCa: invalid base64") from exc


def _to_pki_request(body: PkiGenerateRequest) -> PkiRequest:
    existing = body.existing_ca
    return PkiRequest(
        issuer=body.issuer,
        ca=_ca_request(body.ca) if body.ca else None,
        existing_ca=ExistingCa(
            certificate_pem=_decode_base64(existing.certificate_base64),
            private_key_pem=_decode_base64(existing.private_key_base64),
            passphrase=_secret_bytes(existing.passphrase),
        )
        if existing
        else None,
        leaves=[_leaf_request(leaf) for leaf in body.leaves],
    )


@router.post("/pki/generate", response_model=PkiGenerateResponse)
def post_pki_generate(body: PkiGenerateRequest) -> PkiGenerateResponse:
    """Generate a CA and/or certificates in memory; nothing is stored on the server."""
    try:
        result = generate_pki(_to_pki_request(body))
    except PkiError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return PkiGenerateResponse(
        files=[_generated_file(item.name, item.content, secret=item.secret) for item in result.files],
        certificates=[
            CertificateSummaryDto(
                file=summary.file,
                subject=summary.subject,
                issuer=summary.issuer,
                serialHex=summary.serial_hex,
                notBefore=summary.not_before,
                notAfter=summary.not_after,
                sha256Fingerprint=summary.sha256_fingerprint,
                usage=summary.usage,
                key=summary.key,
                san=summary.san,
            )
            for summary in result.certificates
        ],
        warnings=result.warnings,
    )


@router.post("/pki/convert", response_model=ConvertResponse)
async def post_pki_convert(
    file: Annotated[UploadFile, File()],
    password: Annotated[str | None, Form()] = None,
    output_passphrase: Annotated[str | None, Form(alias="outputPassphrase")] = None,
    basename: Annotated[str | None, Form()] = None,
) -> ConvertResponse:
    """Convert a certificate, key or keystore to PEM; nothing is stored on the server."""
    data = await file.read(MAX_INPUT_BYTES + 1)
    try:
        result = convert_to_pem(
            data,
            filename=file.filename,
            password=password.encode("utf-8") if password else None,
            output_passphrase=output_passphrase.encode("utf-8") if output_passphrase else None,
            basename=basename or None,
        )
    except ConversionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return ConvertResponse(
        files=[_generated_file(item.name, item.content, secret=item.secret) for item in result.files],
        warnings=result.warnings,
        detected=result.detected,
    )


@router.post("/pki/archive")
async def post_pki_archive(files: Annotated[list[UploadFile], File()]) -> Response:
    """Zip the posted .pem files; private keys (``*-key.pem``) get mode 0600 inside the archive."""
    contents: dict[str, bytes] = {}
    for upload in files:
        name = upload.filename or ""
        if not _ARCHIVE_NAME.fullmatch(name):
            raise HTTPException(status_code=422, detail=f"invalid file name {name!r}: expected a plain *.pem name")
        if name in contents:
            raise HTTPException(status_code=422, detail=f"duplicate file name {name!r}")
        contents[name] = await upload.read()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in contents.items():
            info = zipfile.ZipInfo(name, date_time=datetime.now(UTC).timetuple()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (_PRIVATE_FILE_MODE if name.endswith("-key.pem") else _PUBLIC_FILE_MODE) << 16
            archive.writestr(info, content)
    return _zip_response(buffer.getvalue(), "pki.zip")


def _zip_response(data: bytes, filename: str) -> Response:
    return Response(
        content=data,
        media_type=_ZIP_MEDIA_TYPE,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
