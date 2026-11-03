# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Common pytest hooks and fixtures for configurator."""

from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from dg_configurator.pki.builder import SanSpec, SubjectSpec, build_certificate
from dg_configurator.pki.profiles import PROFILES, Usage
from dg_configurator.signing import KeyPair, generate_keypair

TEST_TYPES = ("unit", "integration", "functional")

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VALID_CONFIGS = sorted((FIXTURES_DIR / "configs" / "valid").rglob("*.json"))
INVALID_CONFIGS = sorted(
    path for path in (FIXTURES_DIR / "configs" / "invalid").glob("*.json") if not path.name.endswith(".expected.json")
)


@pytest.fixture(scope="session")
def keypair_a() -> KeyPair:
    """A 2048-bit RSA key pair (generated once per session to keep tests fast)."""
    return generate_keypair(bits=2048)


@pytest.fixture(scope="session")
def keypair_b() -> KeyPair:
    """A second, unrelated 2048-bit RSA key pair."""
    return generate_keypair(bits=2048)


@dataclass(frozen=True)
class CaMaterial:
    """A self-signed EC P-256 CA in object and PEM form, with its key also stored encrypted with ``passphrase``."""

    key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate
    certificate_pem: bytes
    key_pem: bytes
    encrypted_key_pem: bytes
    passphrase: bytes


@pytest.fixture(scope="session")
def rsa2048_key() -> rsa.RSAPrivateKey:
    """A 2048-bit RSA private key (generated once per session)."""
    return rsa.generate_private_key(65537, 2048)


@pytest.fixture(scope="session")
def ec_p256_key() -> ec.EllipticCurvePrivateKey:
    """An EC P-256 private key (generated once per session)."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="session")
def ca_material(ec_p256_key: ec.EllipticCurvePrivateKey) -> CaMaterial:
    """A self-signed CA valid for 10 years."""
    certificate = build_certificate(
        profile=PROFILES[Usage.CA],
        subject=SubjectSpec("Test Root CA", organization="Test"),
        public_key=ec_p256_key.public_key(),
        san=SanSpec(),
        validity_days=3650,
        issuer_key=ec_p256_key,
        issuer_cert=None,
    )
    passphrase = b"ca-passphrase"
    pkcs8 = serialization.PrivateFormat.PKCS8
    return CaMaterial(
        key=ec_p256_key,
        certificate=certificate,
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
        key_pem=ec_p256_key.private_bytes(serialization.Encoding.PEM, pkcs8, serialization.NoEncryption()),
        encrypted_key_pem=ec_p256_key.private_bytes(
            serialization.Encoding.PEM, pkcs8, serialization.BestAvailableEncryption(passphrase)
        ),
        passphrase=passphrase,
    )


@pytest.fixture
def minimal_v11() -> bytes:
    """The minimal valid v1.1 config document."""
    return (FIXTURES_DIR / "configs" / "valid" / "v1.1" / "minimal.json").read_bytes()


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Order tests unit -> integration -> functional and mark them by their directory."""
    order = {name: index for index, name in enumerate(TEST_TYPES)}

    def test_type(item: pytest.Item) -> str | None:
        parts = Path(item.path).parts
        return next((t for t in TEST_TYPES if t in parts), None)

    items.sort(key=lambda item: order.get(test_type(item) or "", len(order)))
    for item in items:
        marker = test_type(item)
        if marker is not None:
            item.add_marker(getattr(pytest.mark, marker))
