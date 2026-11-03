# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Convert certificates, keys and keystores (DER, PKCS#7, PKCS#12, traditional/OpenSSH keys) to PEM."""

import base64
import binascii
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PureWindowsPath

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12

from dg_configurator.errors import ConversionError
from dg_configurator.signing import MIN_KEY_BITS

from .generator import GeneratedFile
from .keys import PrivateKey, PublicKey, serialize_private_key

MAX_INPUT_BYTES = 1024 * 1024

_PEM_BLOCK = re.compile(r"-----BEGIN (?P<label>[A-Z0-9 ]+)-----.*?-----END (?P=label)-----", re.DOTALL)
_PRIVATE_KEY_LABELS = frozenset({"PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"})
_PUBLIC_KEY_LABELS = frozenset({"PUBLIC KEY", "RSA PUBLIC KEY"})
_SSH_PUBLIC_PREFIXES = (b"ssh-", b"ecdsa-sha2-")
_JAVA_KEYSTORE_MAGIC = (b"\xfe\xed\xfe\xed", b"\xce\xce\xce\xce")
_BASE64_TEXT = re.compile(rb"[A-Za-z0-9+/=]+")
_ENCRYPTED_KEY_MESSAGE = "a password is required to decrypt the private key"
_SPKI = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
_SUPPORTED_FORMATS = "PEM, DER, PKCS#7, PKCS#12, PKCS#1/SEC1/PKCS#8 keys, OpenSSH keys"


@dataclass(frozen=True)
class ConversionResult:
    """PEM files produced from one input, with warnings and a description of what was detected."""

    files: list[GeneratedFile]
    warnings: list[str]
    detected: list[str]


@dataclass
class _Parsed:
    format_name: str
    private_key: PrivateKey | None = None
    certificates: list[x509.Certificate] = field(default_factory=list)
    public_key: PublicKey | None = None
    warnings: list[str] = field(default_factory=list)


def _first_der_element(data: bytes) -> bytes:
    """Return the first DER SEQUENCE of ``data`` (OpenSSL's trusted-certificate format appends trust data)."""
    if len(data) < 2 or data[0] != 0x30:
        raise ValueError("not a DER sequence")
    first = data[1]
    if first < 0x80:
        header, length = 2, first
    else:
        count = first & 0x7F
        header, length = 2 + count, int.from_bytes(data[2 : 2 + count], "big")
    if header + length > len(data):
        raise ValueError("truncated DER element")
    return data[: header + length]


def _pem_body(block: str) -> bytes:
    lines = [line for line in block.splitlines()[1:-1] if ":" not in line and line.strip()]
    try:
        return base64.b64decode("".join(lines), validate=True)
    except binascii.Error as exc:
        raise ConversionError("a PEM block is not valid base64") from exc


def _check_key_type(key: object) -> PrivateKey:
    if not isinstance(key, RSAPrivateKey | EllipticCurvePrivateKey):
        raise ConversionError("only RSA and EC private keys are supported (not DSA, Ed25519 or others)")
    return key


def _check_public_key_type(key: object) -> PublicKey:
    if not isinstance(key, RSAPublicKey | EllipticCurvePublicKey):
        raise ConversionError("only RSA and EC public keys are supported (not DSA, Ed25519 or others)")
    return key


def _load_private(loader: Callable[[], object]) -> PrivateKey:
    try:
        return _check_key_type(loader())
    except TypeError as exc:
        raise ConversionError(_ENCRYPTED_KEY_MESSAGE) from exc
    except UnsupportedAlgorithm as exc:
        raise ConversionError(
            "the private key uses an unsupported algorithm or cipher; encrypted OpenSSH keys must be decrypted "
            "first (ssh-keygen -p -m PEM)"
        ) from exc
    except ValueError as exc:
        raise ConversionError("could not read the private key: wrong password or damaged data") from exc


def _parse_pem_block(label: str, block: str, password: bytes | None, parsed: _Parsed) -> None:
    raw = block.encode("ascii", errors="ignore")
    try:
        if label == "CERTIFICATE":
            parsed.certificates.append(x509.load_pem_x509_certificate(raw))
        elif label == "TRUSTED CERTIFICATE":
            parsed.certificates.append(x509.load_der_x509_certificate(_first_der_element(_pem_body(block))))
        elif label == "PKCS7":
            parsed.certificates.extend(pkcs7.load_pem_pkcs7_certificates(raw))
        elif label == "CMS":
            parsed.certificates.extend(pkcs7.load_der_pkcs7_certificates(_pem_body(block)))
        elif label in _PRIVATE_KEY_LABELS:
            _set_private_key(parsed, _load_private(lambda: serialization.load_pem_private_key(raw, password)))
        elif label == "OPENSSH PRIVATE KEY":
            _set_private_key(parsed, _load_private(lambda: serialization.load_ssh_private_key(raw, password)))
        elif label in _PUBLIC_KEY_LABELS:
            _set_public_key(parsed, _check_public_key_type(serialization.load_pem_public_key(raw)))
        else:
            parsed.warnings.append(f"ignored an unknown PEM block ({label})")
    except ValueError as exc:
        raise ConversionError(f"could not read the PEM block {label}: damaged or unsupported data") from exc


def _set_private_key(parsed: _Parsed, key: PrivateKey) -> None:
    if parsed.private_key is not None:
        raise ConversionError("the file contains more than one private key; convert them separately")
    parsed.private_key = key


def _set_public_key(parsed: _Parsed, key: PublicKey) -> None:
    if parsed.public_key is not None:
        raise ConversionError("the file contains more than one public key; convert them separately")
    parsed.public_key = key


def _parse_pem_text(text: str, password: bytes | None) -> _Parsed:
    parsed = _Parsed("PEM")
    blocks = list(_PEM_BLOCK.finditer(text))
    if not blocks:
        raise ConversionError("the PEM data is incomplete (no matching BEGIN/END lines)")
    for match in blocks:
        _parse_pem_block(match["label"], match[0], password, parsed)
    return parsed


def _parse_ssh_public_key(data: bytes) -> _Parsed:
    parsed = _Parsed("OpenSSH public key")
    try:
        key = serialization.load_ssh_public_key(data.strip())
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ConversionError("could not read the OpenSSH public key") from exc
    parsed.public_key = _check_public_key_type(key)
    return parsed


def _looks_like_pkcs12(data: bytes) -> bool:
    """A PFX is a SEQUENCE that starts with INTEGER 3; checked structurally because error messages are ambiguous."""
    if len(data) < 5 or data[0] != 0x30:
        return False
    header = 2 if data[1] < 0x80 else 2 + (data[1] & 0x7F)
    return data[header : header + 3] == b"\x02\x01\x03"


def _parse_pkcs12(data: bytes, password: bytes | None) -> _Parsed:
    try:
        key, certificate, additional = pkcs12.load_key_and_certificates(data, password)
    except UnsupportedAlgorithm as exc:
        raise ConversionError(
            "the PKCS#12 file uses an unsupported cipher; re-export the file with a modern cipher (AES-256)"
        ) from exc
    except ValueError as exc:
        if _looks_like_pkcs12(data):
            raise ConversionError("PKCS#12 password required or incorrect") from exc
        raise ConversionError(f"unrecognised format; supported formats: {_SUPPORTED_FORMATS}") from exc
    parsed = _Parsed("PKCS#12 keystore")
    if key is not None:
        parsed.private_key = _check_key_type(key)
    parsed.certificates = [*([certificate] if certificate else []), *additional]
    return parsed


def _parse_binary(data: bytes, password: bytes | None) -> _Parsed:
    if data.startswith(_JAVA_KEYSTORE_MAGIC):
        raise ConversionError(
            "Java keystores are not supported; convert with "
            "'keytool -importkeystore -srckeystore x.jks -destkeystore x.p12 -deststoretype PKCS12' "
            "and convert the .p12 file"
        )
    try:
        return _Parsed("DER certificate", certificates=[x509.load_der_x509_certificate(data)])
    except ValueError:
        pass
    try:
        return _Parsed("PKCS#7 bundle", certificates=pkcs7.load_der_pkcs7_certificates(data))
    except ValueError:
        pass
    try:
        key = serialization.load_der_private_key(data, password)
    except TypeError as exc:
        raise ConversionError(_ENCRYPTED_KEY_MESSAGE) from exc
    except ValueError, UnsupportedAlgorithm:
        pass
    else:
        return _Parsed("DER private key", private_key=_check_key_type(key))
    try:
        return _Parsed("DER public key", public_key=_check_public_key_type(serialization.load_der_public_key(data)))
    except ValueError:
        pass
    return _parse_pkcs12(data, password)


def _parse(data: bytes, password: bytes | None) -> _Parsed:
    if b"-----BEGIN " in data:
        return _parse_pem_text(data.decode("ascii", errors="ignore"), password)
    stripped = data.lstrip()
    if stripped.startswith(_SSH_PUBLIC_PREFIXES):
        return _parse_ssh_public_key(data)
    if stripped.startswith(b"PuTTY-User-Key-File"):
        raise ConversionError("PuTTY .ppk keys are not supported; export an OpenSSH key with PuTTYgen first")
    compact = b"".join(stripped.split())
    if _BASE64_TEXT.fullmatch(compact) and len(compact) % 4 == 0:
        try:
            decoded = base64.b64decode(compact, validate=True)
        except binascii.Error:
            return _parse_binary(data, password)
        parsed = _parse_binary(decoded, password)
        parsed.format_name = f"base64 {parsed.format_name}"
        return parsed
    return _parse_binary(data, password)


def _spki(key: CertificatePublicKeyTypes | PublicKey) -> bytes:
    return key.public_bytes(*_SPKI)


def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        if certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return True
    except x509.ExtensionNotFound:
        pass
    return certificate.subject == certificate.issuer


def _order_chain(certificates: list[x509.Certificate]) -> list[x509.Certificate]:
    """Order certificates leaf-to-root where the issuer links allow it, otherwise keep the input order."""
    remaining = list(certificates)
    ordered: list[x509.Certificate] = []
    bottoms = [
        c
        for c in remaining
        if not any(o is not c and o.issuer == c.subject and o.subject != c.subject for o in remaining)
    ]
    current: x509.Certificate | None = bottoms[0] if bottoms else (remaining[0] if remaining else None)
    while current is not None:
        ordered.append(current)
        remaining.remove(current)
        current = next((c for c in remaining if c.subject == current.issuer), None)
    return ordered + remaining


def _pem(certificates: list[x509.Certificate]) -> bytes:
    return b"".join(certificate.public_bytes(serialization.Encoding.PEM) for certificate in certificates)


def _plural(count: int, singular: str) -> str:
    return f"{count} {singular}s" if count != 1 else singular


def _base_name(filename: str | None, basename: str | None) -> str:
    stem = basename or (PureWindowsPath(filename).stem if filename else "")
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", stem).strip("._-")[:64]
    return cleaned or "converted"


def convert_to_pem(
    data: bytes,
    *,
    filename: str | None = None,
    password: bytes | None = None,
    output_passphrase: bytes | None = None,
    basename: str | None = None,
) -> ConversionResult:
    """Convert a certificate, key or keystore to PEM files.

    Args:
        data: The file content (at most ``MAX_INPUT_BYTES``).
        filename: The original file name; its stem names the output files.
        password: Password for PKCS#12 files and encrypted private keys.
        output_passphrase: Encrypts the output private key (PKCS#8); without it the key is written unencrypted.
        basename: Overrides the output name stem.

    Returns:
        The PEM files (``<base>.pem`` certificate, ``<base>-key.pem`` key, ``<base>-ca.pem`` CA chain,
        ``<base>-public.pem`` public key), warnings, and a description of the detected format.

    Raises:
        ConversionError: The input is empty, too large, unrecognised, unsupported, needs a password or has a
            certificate that does not match the key. Messages never contain passwords or key material.
    """
    if not data:
        raise ConversionError("the file is empty")
    if len(data) > MAX_INPUT_BYTES:
        raise ConversionError(f"the file is larger than {MAX_INPUT_BYTES // 1024} KiB")
    parsed = _parse(data, password)
    if not (parsed.private_key or parsed.certificates or parsed.public_key):
        raise ConversionError(f"the file contains no certificate or key; supported formats: {_SUPPORTED_FORMATS}")

    base = _base_name(filename, basename)
    warnings = list(parsed.warnings)
    files: list[GeneratedFile] = []
    leaves, authorities = _classify(parsed, warnings)
    key = parsed.private_key
    if leaves:
        files.append(GeneratedFile(f"{base}.pem", _pem(leaves), secret=False))
        chain = authorities
    else:
        if authorities:
            files.append(GeneratedFile(f"{base}.pem", _pem(authorities), secret=False))
        chain = []
    if chain:
        files.append(GeneratedFile(f"{base}-ca.pem", _pem(chain), secret=False))
    if key is not None:
        if isinstance(key, RSAPrivateKey) and key.key_size < MIN_KEY_BITS:
            warnings.append(f"the RSA key is smaller than {MIN_KEY_BITS} bits")
        files.append(GeneratedFile(f"{base}-key.pem", serialize_private_key(key, output_passphrase), secret=True))
        if not output_passphrase:
            warnings.append(f"{base}-key.pem is not protected by a passphrase and stored in clear text")
    if parsed.public_key is not None:
        pem = parsed.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        files.append(GeneratedFile(f"{base}-public.pem", pem, secret=False))
    return ConversionResult(files=files, warnings=warnings, detected=[_describe(parsed, leaves, authorities)])


def _classify(parsed: _Parsed, warnings: list[str]) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    """Split certificates into end-entity certificates and a leaf-to-root ordered CA chain."""
    certificates = parsed.certificates
    key = parsed.private_key
    if key is not None and certificates:
        match = next((c for c in certificates if _spki(c.public_key()) == _spki(key.public_key())), None)
        if match is not None:
            others = [c for c in certificates if c is not match]
            extra = [c for c in others if not _is_ca(c)]
            if extra:
                warnings.append(
                    f"ignored {_plural(len(extra), 'additional end-entity certificate')} that do not match the key"
                )
            return [match], _order_chain([c for c in others if _is_ca(c)])
        if len(certificates) == 1:
            raise ConversionError("the certificate does not match the private key")
        warnings.append("none of the certificates matches the private key")
    authorities = _order_chain([c for c in certificates if _is_ca(c)])
    return [c for c in certificates if not _is_ca(c)], authorities


def _describe(parsed: _Parsed, leaves: list[x509.Certificate], authorities: list[x509.Certificate]) -> str:
    parts = []
    if parsed.private_key is not None:
        parts.append("key")
    if leaves:
        parts.append(_plural(len(leaves), "certificate"))
    if authorities:
        parts.append(_plural(len(authorities), "CA certificate"))
    if parsed.public_key is not None:
        parts.append("public key")
    return f"{parsed.format_name} ({', '.join(parts)})"
