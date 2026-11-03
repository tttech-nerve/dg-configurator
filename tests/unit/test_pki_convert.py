# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for the PEM converter; every input format is generated at runtime."""

import base64
from dataclasses import dataclass

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12

from dg_configurator.errors import ConversionError
from dg_configurator.pki import convert
from dg_configurator.pki.builder import SanSpec, SubjectSpec, build_certificate
from dg_configurator.pki.convert import MAX_INPUT_BYTES, convert_to_pem
from dg_configurator.pki.profiles import PROFILES, Usage
from tests.conftest import CaMaterial

ENC = serialization.Encoding
FMT = serialization.PrivateFormat
NO_ENCRYPTION = serialization.NoEncryption()
PASSWORD = b"input-pw"


@dataclass(frozen=True)
class Chain:
    """A leaf certificate with its key, an intermediate CA and a root CA."""

    key: rsa.RSAPrivateKey
    leaf: x509.Certificate
    intermediate: x509.Certificate
    root: x509.Certificate


@pytest.fixture(scope="module")
def chain(rsa2048_key: rsa.RSAPrivateKey, ca_material: CaMaterial) -> Chain:
    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    intermediate = build_certificate(
        profile=PROFILES[Usage.CA],
        subject=SubjectSpec("Intermediate CA"),
        public_key=intermediate_key.public_key(),
        san=SanSpec(),
        validity_days=1000,
        issuer_key=ca_material.key,
        issuer_cert=ca_material.certificate,
    )
    leaf = build_certificate(
        profile=PROFILES[Usage.TLS_SERVER],
        subject=SubjectSpec("leaf"),
        public_key=rsa2048_key.public_key(),
        san=SanSpec(dns_names=("leaf.example",)),
        validity_days=365,
        issuer_key=intermediate_key,
        issuer_cert=intermediate,
    )
    return Chain(rsa2048_key, leaf, intermediate, ca_material.certificate)


def _pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(ENC.PEM)


def _files(result: convert.ConversionResult) -> dict[str, bytes]:
    return {item.name: item.content for item in result.files}


def _certs(pem: bytes) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(pem)


def _key_bytes(key, encoding: serialization.Encoding, fmt: serialization.PrivateFormat, password: bytes | None):
    encryption = serialization.BestAvailableEncryption(password) if password else NO_ENCRYPTION
    return key.private_bytes(encoding, fmt, encryption)


def test_pem_certificate(chain: Chain):
    result = convert_to_pem(_pem(chain.leaf), filename="server.crt")

    assert list(_files(result)) == ["server.pem"]
    assert _certs(_files(result)["server.pem"]) == [chain.leaf]
    assert result.detected == ["PEM (certificate)"]


def test_der_certificate(chain: Chain):
    result = convert_to_pem(chain.leaf.public_bytes(ENC.DER), filename="C:\\certs\\server.cer")

    assert _certs(_files(result)["server.pem"]) == [chain.leaf]
    assert result.detected == ["DER certificate (certificate)"]


@pytest.mark.parametrize("encoding", [ENC.PEM, ENC.DER])
def test_pkcs7_bundles_split_into_leaf_and_ca_chain(chain: Chain, encoding: serialization.Encoding):
    bundle = pkcs7.serialize_certificates([chain.root, chain.leaf, chain.intermediate], encoding)

    result = convert_to_pem(bundle, filename="bundle.p7b")

    files = _files(result)
    assert _certs(files["bundle.pem"]) == [chain.leaf]
    assert _certs(files["bundle-ca.pem"]) == [chain.intermediate, chain.root]


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_pkcs12_with_a_chain(chain: Chain, password: bytes | None):
    encryption = serialization.BestAvailableEncryption(password) if password else NO_ENCRYPTION
    data = pkcs12.serialize_key_and_certificates(
        b"name", chain.key, chain.leaf, [chain.root, chain.intermediate], encryption
    )

    result = convert_to_pem(data, filename="store.p12", password=password)

    files = _files(result)
    assert set(files) == {"store.pem", "store-ca.pem", "store-key.pem"}
    assert _certs(files["store.pem"]) == [chain.leaf]
    assert _certs(files["store-ca.pem"]) == [chain.intermediate, chain.root]
    key = serialization.load_pem_private_key(files["store-key.pem"], None)
    assert key.public_key().public_numbers() == chain.key.public_key().public_numbers()
    assert result.detected == ["PKCS#12 keystore (key, certificate, 2 CA certificates)"]
    assert any("clear text" in warning for warning in result.warnings)
    assert [item.secret for item in result.files] == [False, False, True]


def test_pkcs12_password_problems_do_not_leak_the_password(chain: Chain):
    data = pkcs12.serialize_key_and_certificates(
        b"n", chain.key, chain.leaf, None, serialization.BestAvailableEncryption(PASSWORD)
    )

    with pytest.raises(ConversionError, match="PKCS#12 password required or incorrect") as missing:
        convert_to_pem(data)
    with pytest.raises(ConversionError, match="PKCS#12 password required or incorrect") as wrong:
        convert_to_pem(data, password=b"wrong-pw")

    assert "wrong-pw" not in str(wrong.value) + str(missing.value)


def test_legacy_pkcs12_cipher_is_converted(chain: Chain):
    encryption = (
        FMT.PKCS12.encryption_builder()
        .kdf_rounds(2048)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(chain.leaf.signature_hash_algorithm)
        .build(b"pw")
    )
    data = pkcs12.serialize_key_and_certificates(b"n", chain.key, chain.leaf, None, encryption)

    result = convert_to_pem(data, password=b"pw")

    assert "converted-key.pem" in _files(result)


def test_unsupported_pkcs12_cipher_gets_a_hint(chain: Chain, monkeypatch: pytest.MonkeyPatch):
    data = pkcs12.serialize_key_and_certificates(b"n", chain.key, chain.leaf, None, NO_ENCRYPTION)

    def unsupported(*_args: object) -> None:
        raise UnsupportedAlgorithm("rc2")

    monkeypatch.setattr(pkcs12, "load_key_and_certificates", unsupported)

    with pytest.raises(ConversionError, match="AES-256"):
        convert_to_pem(data)


def _new_key(kind: str):
    if kind == "rsa":
        return rsa.generate_private_key(65537, 2048)
    return ec.generate_private_key(ec.SECP256R1())


@pytest.mark.parametrize("encoding", [ENC.PEM, ENC.DER])
@pytest.mark.parametrize("fmt", [FMT.PKCS8, FMT.TraditionalOpenSSL], ids=["pkcs8", "traditional"])
@pytest.mark.parametrize("password", [None, PASSWORD], ids=["plain", "encrypted"])
@pytest.mark.parametrize("kind", ["rsa", "ec"])
def test_private_keys_in_every_container(kind, password, fmt, encoding):
    if encoding is ENC.DER and fmt is FMT.TraditionalOpenSSL and password:
        pytest.skip("traditional DER keys cannot be encrypted")
    key = _new_key(kind)
    data = _key_bytes(key, encoding, fmt, password)
    result = convert_to_pem(data, filename="my key.key", password=password, output_passphrase=None)

    files = _files(result)
    assert list(files) == ["my_key-key.pem"]
    assert files["my_key-key.pem"].startswith(b"-----BEGIN PRIVATE KEY-----")
    converted = serialization.load_pem_private_key(files["my_key-key.pem"], None)
    assert converted.public_key().public_numbers() == key.public_key().public_numbers()


def test_openssh_private_keys():
    key = ec.generate_private_key(ec.SECP256R1())
    data = _key_bytes(key, ENC.PEM, FMT.OpenSSH, None)

    result = convert_to_pem(data, filename="id_ecdsa")

    assert "id_ecdsa-key.pem" in _files(result)


def test_encrypted_openssh_keys_without_bcrypt_get_a_hint(monkeypatch: pytest.MonkeyPatch):
    def need_bcrypt(*_args: object) -> None:
        raise UnsupportedAlgorithm("Need bcrypt module")

    monkeypatch.setattr(serialization, "load_ssh_private_key", need_bcrypt)
    pem = b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"

    with pytest.raises(ConversionError, match="ssh-keygen -p"):
        convert_to_pem(pem, password=b"x")


def test_encrypted_keys_need_the_right_password():
    key = ec.generate_private_key(ec.SECP256R1())
    pem = _key_bytes(key, ENC.PEM, FMT.PKCS8, PASSWORD)
    der = _key_bytes(key, ENC.DER, FMT.PKCS8, PASSWORD)

    with pytest.raises(ConversionError, match="password is required"):
        convert_to_pem(pem)
    with pytest.raises(ConversionError, match="password is required"):
        convert_to_pem(der)
    with pytest.raises(ConversionError, match="wrong password") as wrong:
        convert_to_pem(pem, password=b"not-it-pw")
    with pytest.raises(ConversionError) as wrong_der:
        convert_to_pem(der, password=b"not-it-pw")

    assert "not-it-pw" not in str(wrong.value) + str(wrong_der.value)


def test_output_passphrase_encrypts_the_key():
    key = ec.generate_private_key(ec.SECP256R1())

    result = convert_to_pem(_key_bytes(key, ENC.PEM, FMT.PKCS8, None), filename="k", output_passphrase=b"out-pw")

    pem = _files(result)["k-key.pem"]
    assert pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert serialization.load_pem_private_key(pem, b"out-pw")
    assert not any("clear text" in warning for warning in result.warnings)


@pytest.mark.parametrize("key", [rsa.generate_private_key(65537, 2048), ec.generate_private_key(ec.SECP256R1())])
def test_public_keys(key):
    public = key.public_key()
    inputs = [
        public.public_bytes(ENC.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        public.public_bytes(ENC.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        public.public_bytes(ENC.OpenSSH, serialization.PublicFormat.OpenSSH),
        base64.b64encode(public.public_bytes(ENC.DER, serialization.PublicFormat.SubjectPublicKeyInfo)) + b"\n",
    ]
    if isinstance(key, rsa.RSAPrivateKey):
        inputs.append(public.public_bytes(ENC.PEM, serialization.PublicFormat.PKCS1))

    for data in inputs:
        result = convert_to_pem(data, filename="pub.pub")

        assert list(_files(result)) == ["pub-public.pem"]
        loaded = serialization.load_pem_public_key(_files(result)["pub-public.pem"])
        assert loaded.public_numbers() == public.public_numbers()


def test_private_key_with_chain_in_one_pem_file(chain: Chain):
    data = b"\n".join(
        [
            b"Bag Attributes\n    friendlyName: demo",
            chain.key.private_bytes(ENC.PEM, FMT.TraditionalOpenSSL, NO_ENCRYPTION),
            b"subject=CN=leaf",
            _pem(chain.root),
            _pem(chain.leaf),
            _pem(chain.intermediate),
        ]
    )

    result = convert_to_pem(data, filename="all.pem")

    files = _files(result)
    assert _certs(files["all.pem"]) == [chain.leaf]
    assert _certs(files["all-ca.pem"]) == [chain.intermediate, chain.root]
    assert "all-key.pem" in files


def test_lone_ca_certificate_is_written_as_the_main_file(chain: Chain):
    result = convert_to_pem(_pem(chain.root), filename="root.crt")

    assert list(_files(result)) == ["root.pem"]
    assert result.detected == ["PEM (CA certificate)"]


def test_openssl_trusted_certificate_format(chain: Chain):
    body = base64.b64encode(chain.leaf.public_bytes(ENC.DER) + b"\x30\x03\x0c\x01\x41").decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    text = "\n".join(["-----BEGIN TRUSTED CERTIFICATE-----", *lines, "-----END TRUSTED CERTIFICATE-----", ""])

    result = convert_to_pem(text.encode(), filename="trusted")

    assert _certs(_files(result)["trusted.pem"]) == [chain.leaf]


def test_cms_pem_block(chain: Chain):
    der = pkcs7.serialize_certificates([chain.leaf], ENC.DER)
    body = base64.b64encode(der).decode()
    text = f"-----BEGIN CMS-----\n{body}\n-----END CMS-----\n"

    result = convert_to_pem(text.encode(), filename="cms")

    assert _certs(_files(result)["cms.pem"]) == [chain.leaf]


def test_unknown_pem_blocks_are_ignored_with_a_warning(chain: Chain):
    data = b"-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n" + _pem(chain.leaf)

    result = convert_to_pem(data, filename="c")

    assert "c.pem" in _files(result)
    assert any("X509 CRL" in warning for warning in result.warnings)


def test_certificate_must_match_the_private_key(chain: Chain):
    other = ec.generate_private_key(ec.SECP256R1())
    data = _pem(chain.leaf) + other.private_bytes(ENC.PEM, FMT.PKCS8, NO_ENCRYPTION)

    with pytest.raises(ConversionError, match="does not match"):
        convert_to_pem(data)


def test_unmatched_key_with_several_certificates_only_warns(chain: Chain):
    other = ec.generate_private_key(ec.SECP256R1())
    data = _pem(chain.leaf) + _pem(chain.root) + other.private_bytes(ENC.PEM, FMT.PKCS8, NO_ENCRYPTION)

    result = convert_to_pem(data, filename="x")

    assert any("none of the certificates" in warning for warning in result.warnings)
    assert {"x.pem", "x-ca.pem", "x-key.pem"} == set(_files(result))


def test_additional_end_entity_certificates_are_dropped_with_a_warning(chain: Chain, ca_material: CaMaterial):
    stranger = build_certificate(
        profile=PROFILES[Usage.TLS_CLIENT],
        subject=SubjectSpec("stranger"),
        public_key=ec.generate_private_key(ec.SECP256R1()).public_key(),
        san=SanSpec(),
        validity_days=30,
        issuer_key=ca_material.key,
        issuer_cert=ca_material.certificate,
    )
    data = chain.key.private_bytes(ENC.PEM, FMT.PKCS8, NO_ENCRYPTION) + _pem(chain.leaf) + _pem(stranger)

    result = convert_to_pem(data, filename="x")

    assert _certs(_files(result)["x.pem"]) == [chain.leaf]
    assert any("additional end-entity" in warning for warning in result.warnings)


def test_several_end_entity_certificates_without_a_key(chain: Chain, ca_material: CaMaterial):
    other = build_certificate(
        profile=PROFILES[Usage.TLS_CLIENT],
        subject=SubjectSpec("other"),
        public_key=ec.generate_private_key(ec.SECP256R1()).public_key(),
        san=SanSpec(),
        validity_days=30,
        issuer_key=ca_material.key,
        issuer_cert=ca_material.certificate,
    )

    result = convert_to_pem(_pem(chain.leaf) + _pem(other), filename="two")

    assert len(_certs(_files(result)["two.pem"])) == 2
    assert result.detected == ["PEM (2 certificates)"]


def test_small_rsa_keys_are_converted_with_a_warning():
    key = rsa.generate_private_key(65537, 1024)  # noqa: S505 - a weak key is the test input

    result = convert_to_pem(key.private_bytes(ENC.PEM, FMT.PKCS8, NO_ENCRYPTION))

    assert any("2048" in warning for warning in result.warnings)


@pytest.mark.parametrize(
    "key",
    [
        ed25519.Ed25519PrivateKey.generate(),
        dsa.generate_private_key(2048),
    ],
    ids=["ed25519", "dsa"],
)
def test_other_key_types_are_rejected(key):
    pem = key.private_bytes(ENC.PEM, FMT.PKCS8, NO_ENCRYPTION)

    with pytest.raises(ConversionError, match="RSA and EC"):
        convert_to_pem(pem)
    with pytest.raises(ConversionError, match="RSA and EC"):
        convert_to_pem(key.private_bytes(ENC.DER, FMT.PKCS8, NO_ENCRYPTION))


def test_other_public_key_types_are_rejected():
    public = ed25519.Ed25519PrivateKey.generate().public_key()

    with pytest.raises(ConversionError, match="RSA and EC"):
        convert_to_pem(public.public_bytes(ENC.OpenSSH, serialization.PublicFormat.OpenSSH))


def test_more_than_one_private_key_is_rejected():
    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(ENC.PEM, FMT.PKCS8, NO_ENCRYPTION)

    with pytest.raises(ConversionError, match="more than one private key"):
        convert_to_pem(pem + pem)


def test_more_than_one_public_key_is_rejected():
    public = ec.generate_private_key(ec.SECP256R1()).public_key()
    pem = public.public_bytes(ENC.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    with pytest.raises(ConversionError, match="more than one public key"):
        convert_to_pem(pem + pem)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "empty"),
        (b"x" * (MAX_INPUT_BYTES + 1), "larger"),
        (b"this is not a certificate", "unrecognised"),
        (b"\x00\x01\x02\x03", "unrecognised"),
        (b"\xfe\xed\xfe\xed rest", "keytool"),
        (b"PuTTY-User-Key-File-3: ssh-rsa", "PuTTY"),
        (b"-----BEGIN CERTIFICATE-----\nAAAA", "incomplete"),
        (b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "damaged"),
        (b"-----BEGIN TRUSTED CERTIFICATE-----\n!!!\n-----END TRUSTED CERTIFICATE-----\n", "base64"),
        (b"-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n-----END TRUSTED CERTIFICATE-----\n", "damaged"),
        (b"ssh-rsa AAAA", "OpenSSH"),
        (b"0\x82\x00\x04\x02\x01\x03", "PKCS#12 password"),
    ],
)
def test_unusable_input_is_rejected(data: bytes, message: str):
    with pytest.raises(ConversionError, match=message):
        convert_to_pem(data)


def test_a_pem_block_that_contains_nothing_useful_is_rejected():
    with pytest.raises(ConversionError, match="no certificate or key"):
        convert_to_pem(b"-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n")


def test_output_names_come_from_basename_or_filename(chain: Chain):
    assert list(_files(convert_to_pem(_pem(chain.leaf), filename="/data/dir/My Cert.crt"))) == ["My_Cert.pem"]
    assert list(_files(convert_to_pem(_pem(chain.leaf), filename="x.crt", basename="gateway"))) == ["gateway.pem"]
    assert list(_files(convert_to_pem(_pem(chain.leaf), basename="../../etc"))) == ["etc.pem"]
    assert list(_files(convert_to_pem(_pem(chain.leaf), filename="..."))) == ["converted.pem"]
    assert list(_files(convert_to_pem(_pem(chain.leaf)))) == ["converted.pem"]
