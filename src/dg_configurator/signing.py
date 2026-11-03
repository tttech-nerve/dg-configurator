# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""RSA key generation, signing, and signature verification (PKCS#1 v1.5 + SHA-256)."""

import base64
import binascii
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from .errors import KeyLoadError

MIN_KEY_BITS = 2048
RECOMMENDED_KEY_BITS = 4096

_WHITESPACE = re.compile(r"\s+")


@dataclass
class KeyPair:
    """A freshly generated RSA key pair in multiple encodings."""

    private_pem: bytes
    public_pem: bytes
    public_b64der: str


def generate_keypair(bits: int = RECOMMENDED_KEY_BITS, passphrase: bytes | None = None) -> KeyPair:
    """Generate a new RSA key pair.

    The public key is returned both as PEM and as base64 DER (the format of the supervisor's
    ``CONFIG_VERIFICATION_KEY`` setting: no PEM headers, no line breaks).
    """
    if bits < MIN_KEY_BITS:
        raise ValueError(f"RSA key size must be >= {MIN_KEY_BITS} bits")
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    encryption = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_key = key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return KeyPair(private_pem=private_pem, public_pem=public_pem, public_b64der=base64.b64encode(der).decode("ascii"))


def load_private_key(pem: bytes, password: bytes | None = None) -> RSAPrivateKey:
    """Load a PEM-encoded RSA private key, optionally password-protected."""
    try:
        key = serialization.load_pem_private_key(pem, password=password)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyLoadError(f"could not load private key: {exc}") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyLoadError("key is not an RSA private key")
    if key.key_size < MIN_KEY_BITS:
        raise KeyLoadError(f"RSA key is smaller than the minimum of {MIN_KEY_BITS} bits")
    return key


def load_public_key(value: str | bytes) -> RSAPublicKey:
    """Load an RSA public key from PEM text or from base64 DER SubjectPublicKeyInfo.

    Accepts the textual format of the supervisor's ``CONFIG_VERIFICATION_KEY`` setting (base64 DER without PEM headers)
    as well as full PEM text.
    """
    try:
        text = value.decode("ascii") if isinstance(value, bytes) else value
    except UnicodeDecodeError as exc:
        raise KeyLoadError("public key is not text") from exc
    stripped = text.strip()
    try:
        if "-----BEGIN" in stripped:
            key = serialization.load_pem_public_key(stripped.encode("ascii"))
        else:
            key = serialization.load_der_public_key(base64.b64decode(_WHITESPACE.sub("", stripped), validate=True))
    except (ValueError, binascii.Error, UnsupportedAlgorithm) as exc:
        raise KeyLoadError(f"could not load public key (expected PEM or base64 DER): {exc}") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyLoadError("key is not an RSA public key")
    return key


def sign(data: bytes, private_key: RSAPrivateKey) -> bytes:
    """Produce a detached RSA PKCS#1 v1.5 + SHA-256 signature over data."""
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def verify(data: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
    """Verify a detached RSA PKCS#1 v1.5 + SHA-256 signature. Never raises for a bad signature."""
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def is_weak_key(public_key: RSAPublicKey) -> bool:
    """Whether the key is smaller than the recommended 4096 bits (a warning, not an error)."""
    return public_key.key_size < RECOMMENDED_KEY_BITS
