# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for dg_configurator.pki.keys."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from dg_configurator.errors import PkiError
from dg_configurator.pki import keys
from dg_configurator.pki.keys import ALLOWED_KEYS, DEFAULT_KEY, KeySpec

RSA_2048 = KeySpec("rsa", 2048)
EC_P256 = KeySpec("ec", "P-256")
EC_P384 = KeySpec("ec", "P-384")


def _weak_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(65537, 1024)  # noqa: S505 - a weak key is the test input


@pytest.mark.parametrize("spec", ALLOWED_KEYS, ids=lambda s: s.label)
def test_labels_round_trip_through_parse(spec: KeySpec):
    assert KeySpec.parse(spec.label) == spec
    assert KeySpec.parse(spec.label.upper()) == spec


def test_default_and_allowed_keys():
    assert DEFAULT_KEY == KeySpec("rsa", 4096)
    assert [spec.label for spec in ALLOWED_KEYS] == ["rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384"]


@pytest.mark.parametrize("text", ["rsa-1024", "rsa", "ec-p521", "dsa-2048", ""])
def test_parse_rejects_unknown_keys(text: str):
    with pytest.raises(PkiError):
        KeySpec.parse(text)


def test_generate_rsa_and_ec_keys():
    rsa_key = keys.generate_private_key(RSA_2048)
    p256 = keys.generate_private_key(EC_P256)
    p384 = keys.generate_private_key(EC_P384)

    assert isinstance(rsa_key, rsa.RSAPrivateKey)
    assert rsa_key.key_size == 2048
    assert isinstance(p256.curve, ec.SECP256R1)
    assert isinstance(p384.curve, ec.SECP384R1)


@pytest.mark.parametrize("spec", [RSA_2048, EC_P256, EC_P384], ids=lambda s: s.label)
def test_key_spec_of_matches_the_generated_key(spec: KeySpec):
    key = keys.generate_private_key(spec)

    assert keys.key_spec_of(key) == spec
    assert keys.key_spec_of(key.public_key()) == spec


def test_key_spec_of_rejects_other_key_types_and_sizes():
    with pytest.raises(PkiError):
        keys.key_spec_of(ec.generate_private_key(ec.SECP521R1()))
    with pytest.raises(PkiError):
        keys.key_spec_of(_weak_rsa_key())
    with pytest.raises(PkiError):
        keys.key_spec_of(object())


@pytest.mark.parametrize("spec", [RSA_2048, EC_P256], ids=lambda s: s.label)
def test_serialize_and_load_round_trip(spec: KeySpec):
    key = keys.generate_private_key(spec)

    plain = keys.serialize_private_key(key, None)
    encrypted = keys.serialize_private_key(key, b"pw")

    assert plain.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert encrypted.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert keys.key_spec_of(keys.load_private_key_any(plain, None)) == spec
    assert keys.key_spec_of(keys.load_private_key_any(encrypted, b"pw")) == spec


def test_empty_passphrase_means_no_encryption():
    key = keys.generate_private_key(EC_P256)

    assert keys.serialize_private_key(key, b"").startswith(b"-----BEGIN PRIVATE KEY-----")


def test_missing_and_wrong_passphrases_are_rejected_without_leaking_them():
    encrypted = keys.serialize_private_key(keys.generate_private_key(EC_P256), b"right-pass")

    with pytest.raises(PkiError, match="passphrase") as missing:
        keys.load_private_key_any(encrypted, None)
    with pytest.raises(PkiError) as wrong:
        keys.load_private_key_any(encrypted, b"wrong-pass")

    assert "wrong-pass" not in str(wrong.value)
    assert "right-pass" not in str(missing.value)


def test_garbage_is_rejected():
    with pytest.raises(PkiError):
        keys.load_private_key_any(b"not a key", None)


def test_non_rsa_ec_private_keys_are_rejected():
    pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )

    with pytest.raises(PkiError, match="RSA or EC"):
        keys.load_private_key_any(pem, None)


def test_small_rsa_keys_are_rejected():
    pem = _weak_rsa_key().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )

    with pytest.raises(PkiError, match="2048"):
        keys.load_private_key_any(pem, None)


def test_load_certificate_rejects_garbage():
    with pytest.raises(PkiError):
        keys.load_certificate(b"garbage")
