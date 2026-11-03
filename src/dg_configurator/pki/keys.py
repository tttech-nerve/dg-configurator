# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Key generation, PKCS#8 serialisation and loading for the PKI generator (RSA and EC P-256/P-384)."""

from dataclasses import dataclass
from typing import Literal

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from dg_configurator.errors import PkiError
from dg_configurator.signing import MIN_KEY_BITS, RECOMMENDED_KEY_BITS

_RSA_EXPONENT = 65537
_CURVES: dict[str, type[ec.EllipticCurve]] = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1}
_CURVE_NAMES = {"secp256r1": "P-256", "secp384r1": "P-384"}

type PrivateKey = RSAPrivateKey | EllipticCurvePrivateKey
type PublicKey = RSAPublicKey | EllipticCurvePublicKey


@dataclass(frozen=True)
class KeySpec:
    """Algorithm and size/curve of a key: RSA with 2048/3072/4096 bits or EC with P-256/P-384."""

    algorithm: Literal["rsa", "ec"]
    parameter: int | str

    @property
    def label(self) -> str:
        """Canonical text form, e.g. ``rsa-4096`` or ``ec-p256``."""
        if self.algorithm == "rsa":
            return f"rsa-{self.parameter}"
        return "ec-" + str(self.parameter).replace("-", "").lower()

    @classmethod
    def parse(cls, text: str) -> KeySpec:
        """Parse ``rsa-2048``, ``rsa-3072``, ``rsa-4096``, ``ec-p256`` or ``ec-p384`` (case-insensitive).

        Raises:
            PkiError: The text names no supported key.
        """
        normalized = text.strip().lower()
        for spec in ALLOWED_KEYS:
            if spec.label == normalized:
                return spec
        supported = ", ".join(spec.label for spec in ALLOWED_KEYS)
        raise PkiError(f"unsupported key type {text!r} (supported: {supported})")


DEFAULT_KEY = KeySpec("rsa", RECOMMENDED_KEY_BITS)
ALLOWED_KEYS: tuple[KeySpec, ...] = (
    KeySpec("rsa", MIN_KEY_BITS),
    KeySpec("rsa", 3072),
    KeySpec("rsa", RECOMMENDED_KEY_BITS),
    KeySpec("ec", "P-256"),
    KeySpec("ec", "P-384"),
)


def generate_private_key(spec: KeySpec) -> PrivateKey:
    """Generate a new private key of the given type."""
    if spec.algorithm == "rsa":
        return rsa.generate_private_key(_RSA_EXPONENT, int(spec.parameter))
    return ec.generate_private_key(_CURVES[str(spec.parameter)]())


def serialize_private_key(key: PrivateKey, passphrase: bytes | None) -> bytes:
    """Serialise a key as PKCS#8 PEM, encrypted when a non-empty passphrase is given."""
    encryption = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)


def load_private_key_any(pem: bytes, passphrase: bytes | None) -> PrivateKey:
    """Load an RSA or EC private key from PEM.

    Raises:
        PkiError: The key is encrypted and no or a wrong passphrase was given, is not RSA/EC, or is a too small RSA
            key. The message never contains the passphrase or key text.
    """
    try:
        key = serialization.load_pem_private_key(pem, passphrase)
    except TypeError as exc:
        raise PkiError("the private key is encrypted: a passphrase is required") from exc
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise PkiError("could not load the private key: wrong passphrase or not a PEM private key") from exc
    if not isinstance(key, RSAPrivateKey | EllipticCurvePrivateKey):
        raise PkiError("the private key must be an RSA or EC key")
    if isinstance(key, RSAPrivateKey) and key.key_size < MIN_KEY_BITS:
        raise PkiError(f"RSA keys below {MIN_KEY_BITS} bits are not supported")
    return key


def load_certificate(pem: bytes) -> x509.Certificate:
    """Load a PEM certificate.

    Raises:
        PkiError: The data is not a PEM certificate.
    """
    try:
        return x509.load_pem_x509_certificate(pem)
    except ValueError as exc:
        raise PkiError("could not load the certificate: not a PEM certificate") from exc


def key_spec_of(key: PrivateKey | PublicKey) -> KeySpec:
    """Derive the KeySpec of an RSA or EC key.

    Raises:
        PkiError: The key type, size or curve is not supported.
    """
    if isinstance(key, RSAPrivateKey | RSAPublicKey):
        spec = KeySpec("rsa", key.key_size)
    elif isinstance(key, EllipticCurvePrivateKey | EllipticCurvePublicKey) and key.curve.name in _CURVE_NAMES:
        spec = KeySpec("ec", _CURVE_NAMES[key.curve.name])
    else:
        raise PkiError("unsupported key type (supported: RSA 2048/3072/4096, EC P-256/P-384)")
    if spec not in ALLOWED_KEYS:
        raise PkiError(f"unsupported key size {spec.parameter}")
    return spec
