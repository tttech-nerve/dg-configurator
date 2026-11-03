# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""X.509 certificate construction from a usage profile."""

import dataclasses
import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from dg_configurator.errors import PkiError

from .keys import KeySpec, PrivateKey, PublicKey, key_spec_of
from .profiles import Profile

_MAX_NAME_FIELD = 64
_BACKDATE = timedelta(minutes=5)


def _check_text(label: str, value: str) -> None:
    if len(value) > _MAX_NAME_FIELD:
        raise PkiError(f"{label} is longer than {_MAX_NAME_FIELD} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise PkiError(f"{label} contains control characters")


@dataclass(frozen=True)
class SubjectSpec:
    """Distinguished-name fields of a certificate subject."""

    common_name: str
    organization: str | None = None
    organizational_unit: str | None = None
    country: str | None = None
    state: str | None = None
    locality: str | None = None

    def to_name(self) -> x509.Name:
        """Build the X.509 name (C, ST, L, O, OU, CN; empty fields are skipped).

        Raises:
            PkiError: A field is too long, contains control characters, or the country is not two letters.
        """
        if not self.common_name:
            raise PkiError("the common name must not be empty")
        country = self.country.upper() if self.country else None
        if country is not None and not (len(country) == 2 and country.isascii() and country.isalpha()):
            raise PkiError("the country must be a two-letter code")
        fields = (
            ("country", NameOID.COUNTRY_NAME, country),
            ("state", NameOID.STATE_OR_PROVINCE_NAME, self.state),
            ("locality", NameOID.LOCALITY_NAME, self.locality),
            ("organization", NameOID.ORGANIZATION_NAME, self.organization),
            ("organizational unit", NameOID.ORGANIZATIONAL_UNIT_NAME, self.organizational_unit),
            ("common name", NameOID.COMMON_NAME, self.common_name),
        )
        attributes = []
        for label, oid, value in fields:
            if value:
                _check_text(label, value)
                attributes.append(x509.NameAttribute(oid, value))
        return x509.Name(attributes)


@dataclass(frozen=True)
class SanSpec:
    """Subject alternative names."""

    dns_names: tuple[str, ...] = ()
    ip_addresses: tuple[str, ...] = ()
    uris: tuple[str, ...] = ()
    emails: tuple[str, ...] = ()

    def to_general_names(self) -> list[x509.GeneralName]:
        """Return the names in the order URIs, DNS names, IP addresses, e-mails.

        Raises:
            PkiError: A value is empty, not ASCII or not a valid IP address.
        """
        names: list[x509.GeneralName] = []
        try:
            names.extend(x509.UniformResourceIdentifier(value) for value in self.uris)
            names.extend(x509.DNSName(value.lower()) for value in self.dns_names)
            names.extend(x509.IPAddress(ipaddress.ip_address(value)) for value in self.ip_addresses)
            names.extend(x509.RFC822Name(value) for value in self.emails)
        except ValueError as exc:
            raise PkiError(f"invalid subject alternative name: {exc}") from exc
        if any(not value.value for value in names if isinstance(value, x509.DNSName | x509.UniformResourceIdentifier)):
            raise PkiError("invalid subject alternative name: empty value")
        return names


def _hash_for(key: PrivateKey) -> hashes.HashAlgorithm:
    if isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name == "secp384r1":
        return hashes.SHA384()
    return hashes.SHA256()


def _key_usage(profile: Profile, key: PublicKey, *, self_signed: bool) -> x509.KeyUsage:
    flags = dataclasses.asdict(profile.key_usage)
    if key_spec_of(key).algorithm == "rsa":
        flags.update(dict.fromkeys(profile.rsa_key_usage_extra, True))
    if self_signed and profile.requires_application_uri:
        flags["key_cert_sign"] = True
    return x509.KeyUsage(**flags)


def check_leaf_parameters(profile: Profile, key: KeySpec, san: SanSpec, validity_days: int) -> None:
    """Check a certificate request against its profile without generating anything.

    Raises:
        PkiError: The validity, key type or subject alternative names violate the profile.
    """
    if not 1 <= validity_days <= profile.max_validity_days:
        raise PkiError(f"the validity must be between 1 and {profile.max_validity_days} days")
    if key not in profile.allowed_keys:
        allowed = ", ".join(spec.label for spec in profile.allowed_keys)
        raise PkiError(f"a {profile.usage.value} certificate needs one of these key types: {allowed}")
    if profile.requires_san and not (san.dns_names or san.ip_addresses):
        raise PkiError(f"a {profile.usage.value} certificate needs at least one DNS name or IP address")
    if profile.requires_application_uri:
        if not san.uris:
            raise PkiError("an OPC UA application certificate needs the application URI (a URI subject alt name)")
        if not urlparse(san.uris[0]).scheme:
            raise PkiError(f"the application URI must be an absolute URI (for example urn:host:app): {san.uris[0]}")


def build_certificate(
    *,
    profile: Profile,
    subject: SubjectSpec,
    public_key: PublicKey,
    san: SanSpec,
    validity_days: int,
    issuer_key: PrivateKey,
    issuer_cert: x509.Certificate | None,
    now: datetime | None = None,
) -> x509.Certificate:
    """Build and sign a certificate for ``public_key`` according to ``profile``.

    Args:
        profile: The usage profile that decides the extensions.
        subject: Subject name fields.
        public_key: The key the certificate is issued for.
        san: Subject alternative names.
        validity_days: Validity in days, from 1 to the profile maximum.
        issuer_key: The key that signs the certificate (the subject's own key for a self-signed certificate).
        issuer_cert: The issuing CA certificate, or ``None`` for a self-signed certificate.
        now: The issue time. Must be timezone-aware; defaults to the current UTC time.

    Returns:
        The signed certificate. The signature uses SHA-256 (SHA-384 for P-384 issuer keys), never SHA-1.

    Raises:
        PkiError: The request violates the profile (key type, SAN, validity) or the issuer's validity.
    """
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise PkiError("the issue time must be timezone-aware")
    check_leaf_parameters(profile, key_spec_of(public_key), san, validity_days)

    not_after = now + timedelta(days=validity_days)
    if issuer_cert is not None and not_after > issuer_cert.not_valid_after_utc:
        raise PkiError("the certificate would outlive its CA; reduce the validity")

    self_signed = issuer_cert is None
    subject_name = subject.to_name()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name if issuer_cert is None else issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=profile.is_ca, path_length=0 if profile.is_ca else None), critical=True)
        .add_extension(_key_usage(profile, public_key, self_signed=self_signed), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    )
    if not (profile.is_ca and self_signed):
        authority_key = public_key if issuer_cert is None else issuer_cert.public_key()
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key), False)
    if profile.extended_key_usage:
        builder = builder.add_extension(x509.ExtendedKeyUsage(profile.extended_key_usage), critical=False)
    names = san.to_general_names()
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(issuer_key, _hash_for(issuer_key))
