# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for the PKI generator."""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from dg_configurator.errors import PkiError
from dg_configurator.pki.builder import SanSpec, SubjectSpec
from dg_configurator.pki.generator import (
    CaRequest,
    ExistingCa,
    GeneratedFile,
    LeafRequest,
    PkiRequest,
    generate_pki,
    validate_request,
)
from dg_configurator.pki.keys import KeySpec, load_private_key_any
from dg_configurator.pki.profiles import Usage, client_usage_for, server_usage_for
from tests.conftest import CaMaterial

RSA_2048 = KeySpec("rsa", 2048)
EC_P256 = KeySpec("ec", "P-256")
CA = CaRequest(SubjectSpec("Test CA", organization="Org"), key=EC_P256)


def _leaf(usage: Usage, name: str, **kwargs) -> LeafRequest:
    san = SanSpec(dns_names=(f"{name}.example",), uris=("urn:test:app",) if usage is Usage.OPCUA_APPLICATION else ())
    return LeafRequest(
        usage,
        SubjectSpec(name, organization="Org"),
        san,
        key=kwargs.pop("key", RSA_2048),
        basename=kwargs.pop("basename", None),
        **kwargs,
    )


def _files(result) -> dict[str, GeneratedFile]:
    return {item.name: item for item in result.files}


def _cert(result, name: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(_files(result)[name].content)


@pytest.mark.parametrize("domain", ["opcua", "mqtt", "sql", "tls"])
def test_full_pki_for_every_domain(domain: str):
    request = PkiRequest(
        "new-ca",
        ca=CA,
        leaves=[
            _leaf(server_usage_for(domain), "srv", basename="server"),
            _leaf(client_usage_for(domain), "cli", basename="client"),
        ],
    )

    result = generate_pki(request)

    files = _files(result)
    assert list(files) == ["ca.pem", "ca-key.pem", "server.pem", "server-key.pem", "client.pem", "client-key.pem"]
    assert {name for name, item in files.items() if item.secret} == {"ca-key.pem", "server-key.pem", "client-key.pem"}
    ca_cert = _cert(result, "ca.pem")
    for name in ("server", "client"):
        leaf = _cert(result, f"{name}.pem")
        leaf.verify_directly_issued_by(ca_cert)
        key = load_private_key_any(files[f"{name}-key.pem"].content, None)
        assert key.public_key().public_numbers() == leaf.public_key().public_numbers()
    assert [summary.file for summary in result.certificates] == ["ca.pem", "server.pem", "client.pem"]
    assert all(item.name.endswith(".pem") for item in result.files)


def test_summaries_describe_the_certificates():
    result = generate_pki(PkiRequest("new-ca", ca=CA, leaves=[_leaf(Usage.TLS_SERVER, "srv")]))

    summary = result.certificates[1]
    certificate = _cert(result, "server.pem")
    assert summary.usage == "tls-server"
    assert summary.key == "rsa-2048"
    assert summary.san == ["DNS:srv.example"]
    assert summary.subject == certificate.subject.rfc4514_string()
    assert summary.issuer == result.certificates[0].subject
    assert summary.serial_hex == format(certificate.serial_number, "x")
    assert len(summary.sha256_fingerprint.split(":")) == 32
    assert summary.not_after == certificate.not_valid_after_utc


def test_ca_only():
    result = generate_pki(PkiRequest("ca-only", ca=CaRequest(SubjectSpec("Only CA"), key=EC_P256, basename="root")))

    assert list(_files(result)) == ["root.pem", "root-key.pem"]


def test_client_certificate_with_an_existing_encrypted_ca(ca_material: CaMaterial):
    existing = ExistingCa(ca_material.certificate_pem, ca_material.encrypted_key_pem, ca_material.passphrase)

    result = generate_pki(PkiRequest("existing-ca", existing_ca=existing, leaves=[_leaf(Usage.MQTT_CLIENT, "cli")]))

    assert list(_files(result)) == ["client.pem", "client-key.pem"]
    _cert(result, "client.pem").verify_directly_issued_by(ca_material.certificate)


def test_server_certificate_with_an_existing_unencrypted_ca(ca_material: CaMaterial):
    existing = ExistingCa(ca_material.certificate_pem, ca_material.key_pem, None)

    result = generate_pki(PkiRequest("existing-ca", existing_ca=existing, leaves=[_leaf(Usage.SQL_SERVER, "db")]))

    assert list(_files(result)) == ["server.pem", "server-key.pem"]


def test_self_signed_opcua_certificate():
    result = generate_pki(PkiRequest("self-signed", leaves=[_leaf(Usage.OPCUA_APPLICATION, "app")]))

    certificate = _cert(result, "opcua.pem")
    assert list(_files(result)) == ["opcua.pem", "opcua-key.pem"]
    assert certificate.issuer == certificate.subject
    assert any("trust anchor" in warning for warning in result.warnings)


def test_passphrases_apply_to_each_key_independently():
    leaves = [
        _leaf(Usage.TLS_SERVER, "srv", passphrase=b"server-pw"),
        _leaf(Usage.TLS_CLIENT, "cli"),
    ]

    result = generate_pki(
        PkiRequest("new-ca", ca=CaRequest(CA.subject, key=EC_P256, passphrase=b"ca-pw"), leaves=leaves)
    )

    files = _files(result)
    assert files["ca-key.pem"].content.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert load_private_key_any(files["ca-key.pem"].content, b"ca-pw")
    assert load_private_key_any(files["server-key.pem"].content, b"server-pw")
    assert files["client-key.pem"].content.startswith(b"-----BEGIN PRIVATE KEY-----")
    clear_text = [w for w in result.warnings if "without a passphrase" in w]
    assert [w.split(":")[0] for w in clear_text] == ["client-key.pem"]


def test_key_warnings():
    result = generate_pki(PkiRequest("new-ca", ca=CA, leaves=[_leaf(Usage.TLS_SERVER, "srv")]))

    assert any(w.startswith("server-key.pem: RSA key below the 4096-bit") for w in result.warnings)
    assert any(w.startswith("ca-key.pem: EC keys are not covered") for w in result.warnings)


def test_opcua_without_organization_is_warned_about():
    leaf = LeafRequest(
        Usage.OPCUA_APPLICATION, SubjectSpec("app"), SanSpec(uris=("urn:a:b",), dns_names=("h",)), key=RSA_2048
    )

    result = generate_pki(PkiRequest("self-signed", leaves=[leaf]))

    assert any("organization" in warning for warning in result.warnings)


def test_leaf_ending_shortly_before_its_ca_is_warned_about():
    ca = CaRequest(CA.subject, key=EC_P256, validity_days=100)
    leaf = _leaf(Usage.TLS_CLIENT, "cli", validity_days=90)

    result = generate_pki(PkiRequest("new-ca", ca=ca, leaves=[leaf]))

    assert any("less than 30 days before its CA" in warning for warning in result.warnings)


def test_issue_time_can_be_injected():
    now = datetime(2031, 5, 1, tzinfo=UTC)

    result = generate_pki(PkiRequest("self-signed", leaves=[_leaf(Usage.TLS_CLIENT, "cli", key=EC_P256)]), now=now)

    assert _cert(result, "client.pem").not_valid_before_utc == now - timedelta(minutes=5)


def _opcua(name: str, **kwargs) -> LeafRequest:
    return _leaf(Usage.OPCUA_APPLICATION, name, **kwargs)


@pytest.mark.parametrize(
    ("request_", "message"),
    [
        (PkiRequest("ca-only", ca=CA, leaves=[_leaf(Usage.TLS_CLIENT, "c")]), "CA-only"),
        (PkiRequest("ca-only"), "CA settings"),
        (PkiRequest("new-ca", ca=CA), "at least one certificate"),
        (PkiRequest("new-ca", leaves=[_leaf(Usage.TLS_CLIENT, "c")]), "CA settings"),
        (PkiRequest("existing-ca", leaves=[_leaf(Usage.TLS_CLIENT, "c")]), "CA certificate and key"),
        (PkiRequest("self-signed", ca=CA, leaves=[_leaf(Usage.TLS_CLIENT, "c")]), "do not use a CA"),
        (PkiRequest("self-signed"), "at least one certificate"),
        (
            PkiRequest("self-signed", leaves=[_leaf(Usage.TLS_CLIENT, f"c{i}", basename=f"c{i}") for i in range(21)]),
            "20",
        ),
        (
            PkiRequest("self-signed", leaves=[_leaf(Usage.CA, "x")]),
            "usage 'ca'",
        ),
        (
            PkiRequest(
                "self-signed",
                leaves=[LeafRequest(Usage.OPCUA_APPLICATION, SubjectSpec("a"), SanSpec(dns_names=("h",)))],
            ),
            "application URI",
        ),
        (PkiRequest("self-signed", leaves=[_opcua("a", key=EC_P256)]), "key types"),
        (PkiRequest("self-signed", leaves=[_opcua("a"), _opcua("b")]), "unique"),
        (PkiRequest("self-signed", leaves=[_leaf(Usage.TLS_CLIENT, "a", basename="bad name")]), "invalid file name"),
        (PkiRequest("new-ca", ca=CA, leaves=[_leaf(Usage.TLS_CLIENT, "a", basename="ca")]), "unique"),
        (
            PkiRequest(
                "new-ca",
                ca=CaRequest(CA.subject, key=EC_P256, validity_days=100),
                leaves=[_leaf(Usage.TLS_CLIENT, "a", validity_days=200)],
            ),
            "outlive",
        ),
    ],
)
def test_invalid_requests_raise_pki_error(request_: PkiRequest, message: str):
    with pytest.raises(PkiError, match=message):
        validate_request(request_)


def test_generate_validates_first():
    with pytest.raises(PkiError):
        generate_pki(PkiRequest("ca-only", ca=CA, leaves=[_leaf(Usage.TLS_CLIENT, "c")]))


def test_existing_ca_must_match_its_key(ca_material: CaMaterial, rsa2048_key):
    other = rsa2048_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    request = PkiRequest(
        "existing-ca",
        existing_ca=ExistingCa(ca_material.certificate_pem, other),
        leaves=[_leaf(Usage.TLS_CLIENT, "c")],
    )

    with pytest.raises(PkiError, match="does not belong"):
        validate_request(request)


def test_existing_ca_with_a_wrong_passphrase_is_rejected_without_leaking_it(ca_material: CaMaterial):
    existing = ExistingCa(ca_material.certificate_pem, ca_material.encrypted_key_pem, b"wrong-secret")

    with pytest.raises(PkiError) as error:
        validate_request(PkiRequest("existing-ca", existing_ca=existing, leaves=[_leaf(Usage.TLS_CLIENT, "c")]))

    assert "wrong-secret" not in str(error.value)


def test_existing_ca_must_be_a_ca(ca_material: CaMaterial):
    leaf = generate_pki(PkiRequest("self-signed", leaves=[_leaf(Usage.TLS_CLIENT, "c", key=EC_P256)]))
    existing = ExistingCa(_files(leaf)["client.pem"].content, _files(leaf)["client-key.pem"].content)

    with pytest.raises(PkiError, match="not a CA"):
        validate_request(PkiRequest("existing-ca", existing_ca=existing, leaves=[_leaf(Usage.TLS_CLIENT, "d")]))


def test_existing_ca_without_basic_constraints_is_rejected(ec_p256_key):
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "bare")])
    now = datetime.now(UTC)
    bare = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ec_p256_key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(ec_p256_key, __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256())
    )
    existing = ExistingCa(
        bare.public_bytes(serialization.Encoding.PEM),
        ec_p256_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    )

    with pytest.raises(PkiError, match="not a CA"):
        validate_request(PkiRequest("existing-ca", existing_ca=existing, leaves=[_leaf(Usage.TLS_CLIENT, "d")]))


def test_expired_existing_ca_is_rejected(ca_material: CaMaterial):
    existing = ExistingCa(ca_material.certificate_pem, ca_material.key_pem)
    far_future = datetime.now(UTC) + timedelta(days=4000)

    with pytest.raises(PkiError, match="expired"):
        validate_request(
            PkiRequest("existing-ca", existing_ca=existing, leaves=[_leaf(Usage.TLS_CLIENT, "d")]), now=far_future
        )


def test_leaf_validity_beyond_an_existing_cas_expiry_is_rejected(ca_material: CaMaterial):
    existing = ExistingCa(ca_material.certificate_pem, ca_material.key_pem)
    near_end = datetime.now(UTC) + timedelta(days=3600)
    leaf = _leaf(Usage.TLS_CLIENT, "d", validity_days=100)

    with pytest.raises(PkiError, match="outlive"):
        validate_request(PkiRequest("existing-ca", existing_ca=existing, leaves=[leaf]), now=near_end)
