# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for the X.509 certificate builder."""

import ipaddress
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from dg_configurator.errors import PkiError
from dg_configurator.pki.builder import SanSpec, SubjectSpec, build_certificate
from dg_configurator.pki.profiles import PROFILES, Usage
from tests.conftest import CaMaterial

NOW = datetime(2030, 1, 1, 12, 0, tzinfo=UTC)
SAN = SanSpec(dns_names=("Host.Example",), ip_addresses=("192.0.2.1",))
OPCUA_SAN = SanSpec(uris=("urn:host:app",), dns_names=("host.example",))


def _build(usage: Usage, key, ca: CaMaterial | None, *, san: SanSpec = SAN, days: int = 365, **kwargs):
    return build_certificate(
        profile=PROFILES[usage],
        subject=SubjectSpec("leaf", organization="Org"),
        public_key=key.public_key(),
        san=san,
        validity_days=days,
        issuer_key=ca.key if ca else key,
        issuer_cert=ca.certificate if ca else None,
        now=kwargs.pop("now", NOW),
        **kwargs,
    )


def _ext(certificate: x509.Certificate, extension_type):
    return certificate.extensions.get_extension_for_class(extension_type)


def _key_usage_names(certificate: x509.Certificate) -> set[str]:
    usage = _ext(certificate, x509.KeyUsage).value
    names = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment", "key_cert_sign")
    return {name for name in (*names, "crl_sign", "key_agreement") if getattr(usage, name)}


def test_tls_server_certificate_with_rsa_key(rsa2048_key: rsa.RSAPrivateKey, ca_material: CaMaterial):
    certificate = _build(Usage.TLS_SERVER, rsa2048_key, ca_material, now=datetime.now(UTC))

    basic = _ext(certificate, x509.BasicConstraints)
    assert (basic.critical, basic.value.ca, basic.value.path_length) == (True, False, None)
    assert _ext(certificate, x509.KeyUsage).critical is True
    assert _key_usage_names(certificate) == {"digital_signature", "key_encipherment"}
    eku = _ext(certificate, x509.ExtendedKeyUsage)
    assert (eku.critical, list(eku.value)) == (False, [ExtendedKeyUsageOID.SERVER_AUTH])
    san = _ext(certificate, x509.SubjectAlternativeName)
    assert san.critical is False
    assert san.value.get_values_for_type(x509.DNSName) == ["host.example"]
    assert san.value.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("192.0.2.1")]
    ski = _ext(certificate, x509.SubjectKeyIdentifier).value
    assert ski == x509.SubjectKeyIdentifier.from_public_key(rsa2048_key.public_key())
    assert (
        _ext(certificate, x509.AuthorityKeyIdentifier).value.key_identifier
        == _ext(ca_material.certificate, x509.SubjectKeyIdentifier).value.digest
    )
    certificate.verify_directly_issued_by(ca_material.certificate)


def test_ec_leaf_has_no_key_encipherment(ca_material: CaMaterial):
    other = ec.generate_private_key(ec.SECP256R1())

    certificate = _build(Usage.TLS_CLIENT, other, ca_material)

    assert _key_usage_names(certificate) == {"digital_signature"}
    assert [*_ext(certificate, x509.ExtendedKeyUsage).value] == [ExtendedKeyUsageOID.CLIENT_AUTH]


def test_client_certificate_without_san_has_no_san_extension(ca_material: CaMaterial):
    certificate = _build(Usage.MQTT_CLIENT, ec.generate_private_key(ec.SECP256R1()), ca_material, san=SanSpec())

    with pytest.raises(x509.ExtensionNotFound):
        _ext(certificate, x509.SubjectAlternativeName)


def test_ca_certificate(ec_p256_key: ec.EllipticCurvePrivateKey):
    certificate = build_certificate(
        profile=PROFILES[Usage.CA],
        subject=SubjectSpec("Root CA"),
        public_key=ec_p256_key.public_key(),
        san=SanSpec(),
        validity_days=3650,
        issuer_key=ec_p256_key,
        issuer_cert=None,
        now=NOW,
    )

    basic = _ext(certificate, x509.BasicConstraints)
    assert (basic.critical, basic.value.ca, basic.value.path_length) == (True, True, 0)
    assert _key_usage_names(certificate) == {"key_cert_sign", "crl_sign", "digital_signature"}
    assert certificate.issuer == certificate.subject
    with pytest.raises(x509.ExtensionNotFound):
        _ext(certificate, x509.AuthorityKeyIdentifier)
    certificate.verify_directly_issued_by(certificate)


def test_self_signed_opcua_certificate_has_key_cert_sign_and_the_uri_first(rsa2048_key: rsa.RSAPrivateKey):
    certificate = _build(Usage.OPCUA_APPLICATION, rsa2048_key, None, san=OPCUA_SAN)

    assert _key_usage_names(certificate) == {
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_cert_sign",
    }
    assert {*_ext(certificate, x509.ExtendedKeyUsage).value} == {
        ExtendedKeyUsageOID.SERVER_AUTH,
        ExtendedKeyUsageOID.CLIENT_AUTH,
    }
    names = list(_ext(certificate, x509.SubjectAlternativeName).value)
    assert names[0] == x509.UniformResourceIdentifier("urn:host:app")
    assert names[1] == x509.DNSName("host.example")
    assert certificate.issuer == certificate.subject


def test_ca_signed_opcua_certificate_has_no_key_cert_sign(rsa2048_key: rsa.RSAPrivateKey, ca_material: CaMaterial):
    certificate = _build(Usage.OPCUA_APPLICATION, rsa2048_key, ca_material, san=OPCUA_SAN)

    assert "key_cert_sign" not in _key_usage_names(certificate)
    certificate.verify_directly_issued_by(ca_material.certificate)


@pytest.mark.parametrize(
    ("usage", "san", "message"),
    [
        (Usage.TLS_SERVER, SanSpec(), "DNS name or IP"),
        (Usage.OPCUA_APPLICATION, SanSpec(dns_names=("h",)), "application URI"),
        (Usage.OPCUA_APPLICATION, SanSpec(uris=("urn:x:y",)), "DNS name or IP"),
        (Usage.OPCUA_APPLICATION, SanSpec(uris=("not-a-uri",), dns_names=("h",)), "absolute URI"),
    ],
)
def test_san_requirements(rsa2048_key: rsa.RSAPrivateKey, usage: Usage, san: SanSpec, message: str):
    with pytest.raises(PkiError, match=message):
        _build(usage, rsa2048_key, None, san=san)


def test_ec_key_is_rejected_for_opcua(ec_p256_key: ec.EllipticCurvePrivateKey):
    with pytest.raises(PkiError, match="key types"):
        _build(Usage.OPCUA_APPLICATION, ec_p256_key, None, san=OPCUA_SAN)


def test_validity_window_is_backdated_by_five_minutes(ec_p256_key: ec.EllipticCurvePrivateKey):
    certificate = _build(Usage.TLS_CLIENT, ec_p256_key, None, days=10)

    assert certificate.not_valid_before_utc == NOW - timedelta(minutes=5)
    assert certificate.not_valid_after_utc == NOW + timedelta(days=10)


@pytest.mark.parametrize("days", [0, -1, 3651])
def test_validity_outside_the_profile_bounds_is_rejected(ec_p256_key: ec.EllipticCurvePrivateKey, days: int):
    with pytest.raises(PkiError, match="validity"):
        _build(Usage.TLS_CLIENT, ec_p256_key, None, days=days)


def test_leaf_must_not_outlive_its_ca(ca_material: CaMaterial):
    key = ec.generate_private_key(ec.SECP256R1())

    with pytest.raises(PkiError, match="outlive"):
        _build(Usage.TLS_CLIENT, key, ca_material, days=3650, now=datetime.now(UTC) + timedelta(days=30))


def test_naive_issue_time_is_rejected(ec_p256_key: ec.EllipticCurvePrivateKey):
    with pytest.raises(PkiError, match="timezone"):
        _build(Usage.TLS_CLIENT, ec_p256_key, None, now=datetime(2030, 1, 1))  # noqa: DTZ001


def test_serial_numbers_differ(ec_p256_key: ec.EllipticCurvePrivateKey):
    first = _build(Usage.TLS_CLIENT, ec_p256_key, None)
    second = _build(Usage.TLS_CLIENT, ec_p256_key, None)

    assert first.serial_number != second.serial_number


@pytest.mark.parametrize(
    ("issuer_key", "expected"),
    [
        (ec.generate_private_key(ec.SECP256R1()), hashes.SHA256),
        (ec.generate_private_key(ec.SECP384R1()), hashes.SHA384),
        (rsa.generate_private_key(65537, 2048), hashes.SHA256),
    ],
)
def test_signature_hash_follows_the_issuer_key_and_is_never_sha1(issuer_key, expected):
    certificate = _build(Usage.TLS_CLIENT, issuer_key, None)

    assert isinstance(certificate.signature_hash_algorithm, expected)


def test_subject_name_fields_and_order():
    name = SubjectSpec("cn", "org", "unit", "at", "Vienna", "Graz").to_name()

    assert [attribute.oid for attribute in name] == [
        NameOID.COUNTRY_NAME,
        NameOID.STATE_OR_PROVINCE_NAME,
        NameOID.LOCALITY_NAME,
        NameOID.ORGANIZATION_NAME,
        NameOID.ORGANIZATIONAL_UNIT_NAME,
        NameOID.COMMON_NAME,
    ]
    assert name.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "AT"


@pytest.mark.parametrize(
    "subject",
    [
        SubjectSpec(""),
        SubjectSpec("x" * 65),
        SubjectSpec("cn", country="AUT"),
        SubjectSpec("cn", country="1A"),
        SubjectSpec("cn", organization="bad\norg"),
    ],
)
def test_invalid_subjects_are_rejected(subject: SubjectSpec):
    with pytest.raises(PkiError):
        subject.to_name()


def test_san_order_and_normalisation():
    names = SanSpec(
        dns_names=("A.example",), ip_addresses=("::1",), uris=("urn:a:b",), emails=("a@example.com",)
    ).to_general_names()

    assert names == [
        x509.UniformResourceIdentifier("urn:a:b"),
        x509.DNSName("a.example"),
        x509.IPAddress(ipaddress.ip_address("::1")),
        x509.RFC822Name("a@example.com"),
    ]


@pytest.mark.parametrize("san", [SanSpec(ip_addresses=("999.1.1.1",)), SanSpec(dns_names=("",)), SanSpec(uris=("",))])
def test_invalid_san_values_are_rejected(san: SanSpec):
    with pytest.raises(PkiError):
        san.to_general_names()
