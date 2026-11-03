# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for RSA signing helpers."""

import pytest

from dg_configurator import signing
from dg_configurator.errors import KeyLoadError


def test_default_keypair_is_4096_bits():
    pair = signing.generate_keypair()

    assert signing.load_public_key(pair.public_pem).key_size == 4096
    assert not signing.is_weak_key(signing.load_public_key(pair.public_pem))


def test_small_keys_are_refused():
    with pytest.raises(ValueError, match="2048"):
        signing.generate_keypair(bits=1024)


def test_private_key_round_trips_without_passphrase(keypair_a: signing.KeyPair):
    assert signing.load_private_key(keypair_a.private_pem).key_size == 2048


def test_private_key_round_trips_with_passphrase():
    pair = signing.generate_keypair(bits=2048, passphrase=b"s3cret")

    assert b"ENCRYPTED" in pair.private_pem
    assert signing.load_private_key(pair.private_pem, b"s3cret").key_size == 2048
    with pytest.raises(KeyLoadError):
        signing.load_private_key(pair.private_pem, b"wrong")
    with pytest.raises(KeyLoadError):
        signing.load_private_key(pair.private_pem)


def test_private_key_loading_rejects_garbage_and_foreign_key_types():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    ec_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )

    with pytest.raises(KeyLoadError):
        signing.load_private_key(b"garbage")
    with pytest.raises(KeyLoadError, match="not an RSA"):
        signing.load_private_key(ec_pem)


def test_private_key_loading_rejects_keys_below_the_minimum_size():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    small = rsa.generate_private_key(public_exponent=65537, key_size=1024).private_bytes(  # noqa: S505 - deliberately weak
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )

    with pytest.raises(KeyLoadError, match="smaller"):
        signing.load_private_key(small)


def test_public_key_loads_from_pem_and_base64_der(keypair_a: signing.KeyPair):
    from_pem = signing.load_public_key(keypair_a.public_pem)
    from_der = signing.load_public_key(keypair_a.public_b64der)
    wrapped = keypair_a.public_b64der[:60] + "\n" + keypair_a.public_b64der[60:]
    from_wrapped_der = signing.load_public_key(wrapped)

    assert from_pem.public_numbers() == from_der.public_numbers() == from_wrapped_der.public_numbers()


@pytest.mark.parametrize(
    "value", ["not a key", "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----", b"\xff\xfe"]
)
def test_public_key_loading_rejects_garbage(value: str | bytes):
    with pytest.raises(KeyLoadError):
        signing.load_public_key(value)


def test_public_key_loading_rejects_non_rsa_keys():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    pem = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )

    with pytest.raises(KeyLoadError, match="not an RSA"):
        signing.load_public_key(pem)


def test_sign_and_verify_round_trip(keypair_a: signing.KeyPair):
    private_key = signing.load_private_key(keypair_a.private_pem)
    public_key = signing.load_public_key(keypair_a.public_pem)

    signature = signing.sign(b"payload", private_key)

    assert signing.verify(b"payload", signature, public_key) is True


def test_verify_returns_false_for_tampered_data_or_foreign_key(keypair_a: signing.KeyPair, keypair_b: signing.KeyPair):
    signature = signing.sign(b"payload", signing.load_private_key(keypair_a.private_pem))

    assert signing.verify(b"tampered", signature, signing.load_public_key(keypair_a.public_pem)) is False
    assert signing.verify(b"payload", signature, signing.load_public_key(keypair_b.public_pem)) is False


def test_weak_key_detection(keypair_a: signing.KeyPair):
    assert signing.is_weak_key(signing.load_public_key(keypair_a.public_pem)) is True
