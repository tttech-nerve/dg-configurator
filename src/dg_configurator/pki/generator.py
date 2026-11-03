# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""PKI orchestration: new or existing CA, server/client/application certificates, PEM output files."""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from dg_configurator.errors import PkiError
from dg_configurator.signing import RECOMMENDED_KEY_BITS

from .builder import SanSpec, SubjectSpec, build_certificate, check_leaf_parameters
from .keys import (
    DEFAULT_KEY,
    KeySpec,
    PrivateKey,
    generate_private_key,
    load_certificate,
    load_private_key_any,
    serialize_private_key,
)
from .profiles import PROFILES, Usage

MAX_LEAVES = 20
_BASENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_CA_EXPIRY_MARGIN = timedelta(days=30)
_SUBJECT_PUBLIC_KEY_INFO = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

type Issuer = Literal["new-ca", "existing-ca", "self-signed", "ca-only"]


@dataclass(frozen=True)
class LeafRequest:
    """One end-entity certificate (server, client or OPC UA application)."""

    usage: Usage
    subject: SubjectSpec
    san: SanSpec
    key: KeySpec = DEFAULT_KEY
    validity_days: int | None = None
    passphrase: bytes | None = None
    basename: str | None = None

    @property
    def effective_basename(self) -> str:
        """The file name stem: the explicit basename or ``server`` / ``client`` / ``opcua`` by usage."""
        if self.basename:
            return self.basename
        if self.usage is Usage.OPCUA_APPLICATION:
            return "opcua"
        return "server" if self.usage.value.endswith("-server") else "client"


@dataclass(frozen=True)
class CaRequest:
    """A new certificate authority."""

    subject: SubjectSpec
    key: KeySpec = DEFAULT_KEY
    validity_days: int | None = None
    passphrase: bytes | None = None
    basename: str = "ca"


@dataclass(frozen=True)
class ExistingCa:
    """An existing CA given as PEM certificate and PEM private key."""

    certificate_pem: bytes
    private_key_pem: bytes
    passphrase: bytes | None = None


@dataclass(frozen=True)
class PkiRequest:
    """What to generate: a CA, leaves, or both."""

    issuer: Issuer
    ca: CaRequest | None = None
    existing_ca: ExistingCa | None = None
    leaves: list[LeafRequest] = field(default_factory=list)


@dataclass(frozen=True)
class GeneratedFile:
    """One output file; ``secret`` marks private keys."""

    name: str
    content: bytes
    secret: bool


@dataclass(frozen=True)
class CertificateSummary:
    """Human-readable facts about one generated certificate."""

    file: str
    subject: str
    issuer: str
    serial_hex: str
    not_before: datetime
    not_after: datetime
    sha256_fingerprint: str
    usage: str
    key: str
    san: list[str]


@dataclass(frozen=True)
class PkiResult:
    """Generated files with certificate summaries and warnings."""

    files: list[GeneratedFile]
    certificates: list[CertificateSummary]
    warnings: list[str]


def _load_existing_ca(existing: ExistingCa, now: datetime) -> tuple[x509.Certificate, PrivateKey]:
    certificate = load_certificate(existing.certificate_pem)
    key = load_private_key_any(existing.private_key_pem, existing.passphrase)
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        constraints = None
    if constraints is None or not constraints.ca:
        raise PkiError("the CA certificate is not a CA (BasicConstraints CA:TRUE is missing)")
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and not usage.key_cert_sign:
        raise PkiError("the CA certificate does not allow signing certificates (keyCertSign is missing)")
    if certificate.not_valid_after_utc <= now:
        raise PkiError("the CA certificate has expired")
    if certificate.public_key().public_bytes(*_SUBJECT_PUBLIC_KEY_INFO) != key.public_key().public_bytes(
        *_SUBJECT_PUBLIC_KEY_INFO
    ):
        raise PkiError("the CA private key does not belong to the CA certificate")
    return certificate, key


def _check_names(request: PkiRequest) -> None:
    names = [leaf.effective_basename for leaf in request.leaves]
    if request.ca is not None and request.issuer in ("new-ca", "ca-only"):
        names.append(request.ca.basename)
    for name in names:
        if not _BASENAME.fullmatch(name):
            raise PkiError(f"invalid file name {name!r}: use letters, digits, '.', '_' and '-' (at most 64)")
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise PkiError(
            f"file names must be unique, but {', '.join(duplicates)} is used more than once; "
            "give each certificate its own basename"
        )


def _check_leaf(leaf: LeafRequest, *, ca_validity_days: int | None, ca_not_after: datetime | None, now: datetime):
    if leaf.usage is Usage.CA:
        raise PkiError("a leaf certificate cannot have the usage 'ca'")
    profile = PROFILES[leaf.usage]
    days = leaf.validity_days or profile.default_validity_days
    check_leaf_parameters(profile, leaf.key, leaf.san, days)
    leaf.subject.to_name()
    leaf.san.to_general_names()
    if ca_validity_days is not None and days > ca_validity_days:
        raise PkiError(f"the {leaf.effective_basename} certificate would outlive its CA; reduce the validity")
    if ca_not_after is not None and now + timedelta(days=days) > ca_not_after:
        raise PkiError(f"the {leaf.effective_basename} certificate would outlive its CA; reduce the validity")


def validate_request(request: PkiRequest, now: datetime | None = None) -> None:
    """Check a request for consistency before any key is generated.

    Args:
        request: The request to check.
        now: The reference time for the CA expiry check; defaults to the current UTC time.

    Raises:
        PkiError: The request is inconsistent, a profile rule is violated or the existing CA is unusable.
    """
    now = now or datetime.now(UTC)
    if request.issuer == "ca-only" and request.leaves:
        raise PkiError("a CA-only request must not contain certificates")
    if request.issuer != "ca-only" and not request.leaves:
        raise PkiError("at least one certificate is required")
    if len(request.leaves) > MAX_LEAVES:
        raise PkiError(f"at most {MAX_LEAVES} certificates can be generated at once")
    if request.issuer in ("new-ca", "ca-only") and request.ca is None:
        raise PkiError("a new CA needs its CA settings")
    if request.issuer == "existing-ca" and request.existing_ca is None:
        raise PkiError("an existing CA needs the CA certificate and key")
    if request.issuer == "self-signed" and (request.ca is not None or request.existing_ca is not None):
        raise PkiError("self-signed certificates do not use a CA")

    ca_validity_days: int | None = None
    ca_not_after: datetime | None = None
    if request.ca is not None and request.issuer in ("new-ca", "ca-only"):
        ca_profile = PROFILES[Usage.CA]
        ca_validity_days = request.ca.validity_days or ca_profile.default_validity_days
        check_leaf_parameters(ca_profile, request.ca.key, SanSpec(), ca_validity_days)
        request.ca.subject.to_name()
    if request.issuer == "existing-ca" and request.existing_ca is not None:
        certificate, _key = _load_existing_ca(request.existing_ca, now)
        ca_not_after = certificate.not_valid_after_utc
    _check_names(request)
    for leaf in request.leaves:
        _check_leaf(leaf, ca_validity_days=ca_validity_days, ca_not_after=ca_not_after, now=now)


def _san_texts(certificate: x509.Certificate) -> list[str]:
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    prefixes = (
        (x509.UniformResourceIdentifier, "URI"),
        (x509.DNSName, "DNS"),
        (x509.IPAddress, "IP"),
        (x509.RFC822Name, "email"),
    )
    return [f"{prefix}:{value}" for kind, prefix in prefixes for value in san.get_values_for_type(kind)]


def _summary(file: str, certificate: x509.Certificate, usage: Usage, key: KeySpec) -> CertificateSummary:
    return CertificateSummary(
        file=file,
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_hex=format(certificate.serial_number, "x"),
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        sha256_fingerprint=certificate.fingerprint(hashes.SHA256()).hex(":").upper(),
        usage=usage.value,
        key=key.label,
        san=_san_texts(certificate),
    )


def _key_warnings(file: str, key: KeySpec, passphrase: bytes | None) -> list[str]:
    warnings = []
    if key.algorithm == "rsa" and int(key.parameter) < RECOMMENDED_KEY_BITS:
        warnings.append(
            f"{file}: RSA key below the {RECOMMENDED_KEY_BITS}-bit key length of the Data Gateway hardening guideline"
        )
    if key.algorithm == "ec":
        warnings.append(
            f"{file}: EC keys are not covered by the {RECOMMENDED_KEY_BITS}-bit RSA requirement of the Data Gateway "
            "hardening guideline"
        )
    if not passphrase:
        warnings.append(f"{file}: Private keys without a passphrase are stored in clear text")
    return warnings


def generate_pki(request: PkiRequest, now: datetime | None = None) -> PkiResult:
    """Generate the requested CA and certificates.

    Args:
        request: What to generate.
        now: The issue time (timezone-aware); defaults to the current UTC time.

    Returns:
        PEM files (certificates, and PKCS#8 private keys marked ``secret``), certificate summaries and warnings.

    Raises:
        PkiError: The request is invalid.
    """
    now = now or datetime.now(UTC)
    validate_request(request, now)
    files: list[GeneratedFile] = []
    certificates: list[CertificateSummary] = []
    warnings: list[str] = []

    def emit(
        basename: str, certificate: x509.Certificate, key: PrivateKey, spec: KeySpec, usage: Usage, pw: bytes | None
    ):
        cert_name, key_name = f"{basename}.pem", f"{basename}-key.pem"
        files.append(GeneratedFile(cert_name, certificate.public_bytes(serialization.Encoding.PEM), secret=False))
        files.append(GeneratedFile(key_name, serialize_private_key(key, pw), secret=True))
        certificates.append(_summary(cert_name, certificate, usage, spec))
        warnings.extend(_key_warnings(key_name, spec, pw))

    ca_certificate: x509.Certificate | None = None
    ca_key: PrivateKey | None = None
    if request.ca is not None and request.issuer in ("new-ca", "ca-only"):
        ca = request.ca
        ca_key = generate_private_key(ca.key)
        ca_certificate = build_certificate(
            profile=PROFILES[Usage.CA],
            subject=ca.subject,
            public_key=ca_key.public_key(),
            san=SanSpec(),
            validity_days=ca.validity_days or PROFILES[Usage.CA].default_validity_days,
            issuer_key=ca_key,
            issuer_cert=None,
            now=now,
        )
        emit(ca.basename, ca_certificate, ca_key, ca.key, Usage.CA, ca.passphrase)
    elif request.existing_ca is not None:
        ca_certificate, ca_key = _load_existing_ca(request.existing_ca, now)

    for leaf in request.leaves:
        profile = PROFILES[leaf.usage]
        key = generate_private_key(leaf.key)
        certificate = build_certificate(
            profile=profile,
            subject=leaf.subject,
            public_key=key.public_key(),
            san=leaf.san,
            validity_days=leaf.validity_days or profile.default_validity_days,
            issuer_key=ca_key or key,
            issuer_cert=ca_certificate,
            now=now,
        )
        basename = leaf.effective_basename
        emit(basename, certificate, key, leaf.key, leaf.usage, leaf.passphrase)
        if leaf.usage is Usage.OPCUA_APPLICATION and not leaf.subject.organization:
            warnings.append(f"{basename}.pem: OPC UA application certificates should carry an organization (O)")
        if (
            ca_certificate is not None
            and ca_certificate.not_valid_after_utc - certificate.not_valid_after_utc < _CA_EXPIRY_MARGIN
        ):
            warnings.append(f"{basename}.pem: the certificate expires less than 30 days before its CA does")

    if request.issuer == "self-signed":
        warnings.append(
            "Self-signed: each certificate is its own trust anchor, so give the peer this certificate file "
            "(there is no separate CA certificate)"
        )
    return PkiResult(files=files, certificates=certificates, warnings=warnings)
