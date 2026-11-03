# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Interoperability of dg_configurator.signing and the generated PKI with the openssl command line and ssl module."""

import shutil
import socket
import ssl
import subprocess  # noqa: S404 - tests drive the openssl binary
import threading
from pathlib import Path

import pytest

from dg_configurator import signing
from dg_configurator.pki.builder import SanSpec, SubjectSpec
from dg_configurator.pki.generator import CaRequest, LeafRequest, PkiRequest, generate_pki
from dg_configurator.pki.keys import KeySpec
from dg_configurator.pki.profiles import client_usage_for, server_usage_for

OPENSSL = shutil.which("openssl")

pytestmark = pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")


def _run(*args: str) -> None:
    assert OPENSSL is not None
    subprocess.run([OPENSSL, *args], check=True, capture_output=True)  # noqa: S603


def test_openssl_verifies_a_signature_made_by_the_tool(tmp_path: Path, keypair_a: signing.KeyPair):
    data = tmp_path / "data.bin"
    data.write_bytes(b"config.tar content")
    signature = tmp_path / "data.sig"
    signature.write_bytes(signing.sign(data.read_bytes(), signing.load_private_key(keypair_a.private_pem)))
    public = tmp_path / "public.pem"
    public.write_bytes(keypair_a.public_pem)

    _run("dgst", "-sha256", "-verify", str(public), "-signature", str(signature), str(data))


def test_tool_verifies_a_signature_made_by_openssl(tmp_path: Path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    data = tmp_path / "data.bin"
    signature = tmp_path / "data.sig"
    data.write_bytes(b"config.tar content")
    _run("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private))
    _run("rsa", "-in", str(private), "-pubout", "-out", str(public))
    _run("dgst", "-sha256", "-sign", str(private), "-out", str(signature), str(data))

    public_key = signing.load_public_key(public.read_bytes())

    assert signing.verify(data.read_bytes(), signature.read_bytes(), public_key) is True


def _write_pki(directory: Path, domain: str, key: KeySpec, passphrase: bytes | None = None) -> None:
    leaves = [
        LeafRequest(
            server_usage_for(domain),
            SubjectSpec("srv", organization="Org"),
            SanSpec(dns_names=("localhost",), ip_addresses=("127.0.0.1",), uris=_uris(domain, "server")),
            key=key,
            passphrase=passphrase,
            basename="server",
        ),
        LeafRequest(
            client_usage_for(domain),
            SubjectSpec("cli", organization="Org"),
            SanSpec(dns_names=("client.local",), uris=_uris(domain, "client")),
            key=key,
            basename="client",
        ),
    ]
    result = generate_pki(PkiRequest("new-ca", ca=CaRequest(SubjectSpec("Test CA"), key=key), leaves=leaves))
    for item in result.files:
        (directory / item.name).write_bytes(item.content)


def _uris(domain: str, role: str) -> tuple[str, ...]:
    return (f"urn:test:{role}",) if domain == "opcua" else ()


@pytest.mark.parametrize("key", [KeySpec("rsa", 2048), KeySpec("ec", "P-256")], ids=lambda k: k.label)
def test_openssl_verifies_the_generated_tls_chain(tmp_path: Path, key: KeySpec):
    _write_pki(tmp_path, "tls", key)
    ca, server, client = (str(tmp_path / name) for name in ("ca.pem", "server.pem", "client.pem"))

    _run("verify", "-CAfile", ca, server, client)
    _run("verify", "-CAfile", ca, "-purpose", "sslserver", "-x509_strict", server)
    _run("verify", "-CAfile", ca, "-purpose", "sslclient", "-x509_strict", client)


@pytest.mark.parametrize("domain", ["mqtt", "sql", "opcua"])
def test_openssl_verifies_the_other_domains(tmp_path: Path, domain: str):
    _write_pki(tmp_path, domain, KeySpec("rsa", 2048))

    _run("verify", "-CAfile", str(tmp_path / "ca.pem"), str(tmp_path / "server.pem"), str(tmp_path / "client.pem"))


def test_openssl_reads_passphrase_protected_keys(tmp_path: Path):
    _write_pki(tmp_path, "tls", KeySpec("ec", "P-256"), passphrase=b"secret-pw")

    _run("pkey", "-in", str(tmp_path / "server-key.pem"), "-passin", "pass:secret-pw", "-noout")


@pytest.mark.slow
def test_generated_certificates_work_for_mutual_tls(tmp_path: Path):
    _write_pki(tmp_path, "tls", KeySpec("rsa", 2048))
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(tmp_path / "server.pem", tmp_path / "server-key.pem")
    server_context.load_verify_locations(tmp_path / "ca.pem")
    server_context.verify_mode = ssl.CERT_REQUIRED
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_cert_chain(tmp_path / "client.pem", tmp_path / "client-key.pem")
    client_context.load_verify_locations(tmp_path / "ca.pem")
    peer: list[str] = []

    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]

        def serve() -> None:
            connection, _ = listener.accept()
            with server_context.wrap_socket(connection, server_side=True) as tls:
                peer.append(tls.getpeercert()["subject"][-1][0][1])
                tls.sendall(tls.recv(4))

        thread = threading.Thread(target=serve)
        thread.start()
        with socket.create_connection(("127.0.0.1", port)) as raw:
            with client_context.wrap_socket(raw, server_hostname="localhost") as tls:
                tls.sendall(b"ping")
                echoed = tls.recv(4)
        thread.join(timeout=10)

    assert echoed == b"ping"
    assert peer == ["cli"]
