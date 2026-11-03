# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Integration tests of the HTTP API using Starlette's test client."""

import base64
import io
import json
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi.testclient import TestClient

from dg_configurator import packaging, project, signing
from dg_configurator.web.app import ServerSettings, create_app
from tests.conftest import FIXTURES_DIR, CaMaterial

VALID = FIXTURES_DIR / "configs" / "valid"
MINIMAL_V10 = json.loads((VALID / "v1.0" / "minimal.json").read_text())
MINIMAL_V11 = json.loads((VALID / "v1.1" / "minimal.json").read_text())


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app(ServerSettings()), base_url="http://localhost") as test_client:
        yield test_client


def _tls_config() -> dict[str, Any]:
    document = json.loads(json.dumps(MINIMAL_V10))
    document["endpoints"][0].update(url="mqtts://h", security={"tlsEnabled": True, "ca": "certs/ca.pem"})
    return document


def _config_part(document: Any) -> tuple[str, bytes, str]:
    return ("config.json", json.dumps(document).encode(), "application/json")


def test_healthz(client: TestClient):
    response = client.get("/healthz")

    assert (response.status_code, response.json()) == (200, {"status": "ok"})


def test_security_headers_are_set(client: TestClient):
    headers = client.get("/healthz").headers

    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"


def test_static_index_is_served(client: TestClient):
    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_meta_lists_endpoint_types_and_limits(client: TestClient):
    body = client.get("/api/meta").json()

    assert {e["endpointType"] for e in body["endpointTypes"]} == {"mqtt-client", "opcua-client", "sql-client"}
    assert body["configVersions"] == ["1.0", "1.1"]
    assert body["limits"]["maxEndpoints"] == 100
    sql = next(e for e in body["endpointTypes"] if e["endpointType"] == "sql-client")
    assert (sql["minVersion"], sql["inputTypes"]) == ("1.1", [])


def test_schema_endpoint(client: TestClient):
    assert "$defs" in client.get("/api/schema/1.1").json()
    assert client.get("/api/schema/9.9").status_code == 404


def test_validate_valid_and_invalid_documents(client: TestClient):
    ok = client.post("/api/validate", json={"config": MINIMAL_V11}).json()
    bad = client.post("/api/validate", json={"config": MINIMAL_V11 | {"connections": []}}).json()

    assert ok == {"valid": True, "version": "1.1", "diagnostics": []}
    assert bad["valid"] is False
    assert {d["code"] for d in bad["diagnostics"]} == {"orphan_port"}
    assert bad["diagnostics"][0]["path"][0] == "endpoints"


def test_validate_checks_supporting_file_names(client: TestClient):
    body = client.post("/api/validate", json={"config": _tls_config(), "files": []}).json()

    assert [d["code"] for d in body["diagnostics"]] == ["file_missing"]


def test_validate_rejects_non_object_config(client: TestClient):
    assert client.post("/api/validate", json={"config": []}).status_code == 422


def _import(client: TestClient, data: bytes, **form: str) -> Any:
    return client.post("/api/import", files={"file": ("upload.bin", data)}, data=form)


def test_import_plain_zip_runs_auto_layout(client: TestClient):
    data = packaging.build_plain_zip(json.dumps(_tls_config()).encode(), {"certs/ca.pem": b"ca"})

    body = _import(client, data).json()

    assert body["packageKind"] == "plain-zip"
    assert body["signature"] is None
    assert body["report"]["valid"] is True
    assert set(body["layout"]["nodes"]) == {"1", "2"}
    assert base64.b64decode(body["files"][0]["contentBase64"]) == b"ca"
    assert body["files"][0]["name"] == "certs/ca.pem"


def test_import_signed_zip_with_and_without_public_key(client: TestClient, keypair_a: signing.KeyPair):
    private_key = signing.load_private_key(keypair_a.private_pem)
    data = packaging.build_signed_zip(json.dumps(MINIMAL_V10).encode(), {}, private_key)

    unchecked = _import(client, data).json()
    valid = _import(client, data, publicKey=keypair_a.public_b64der).json()

    assert (unchecked["packageKind"], unchecked["signature"]) == ("signed-zip", "unchecked")
    assert (valid["packageKind"], valid["signature"]) == ("signed-zip", "valid")


def test_import_signed_zip_with_foreign_public_key(client: TestClient, keypair_a: signing.KeyPair, keypair_b):
    data = packaging.build_signed_zip(
        json.dumps(MINIMAL_V10).encode(), {}, signing.load_private_key(keypair_a.private_pem)
    )

    assert _import(client, data, publicKey=keypair_b.public_pem.decode()).json()["signature"] == "invalid"


def test_import_rejects_a_garbage_public_key(client: TestClient):
    response = _import(client, json.dumps(MINIMAL_V10).encode(), publicKey="garbage")

    assert response.status_code == 400


def test_import_bare_json(client: TestClient):
    body = _import(client, json.dumps(MINIMAL_V10).encode()).json()

    assert (body["packageKind"], body["files"], body["config"]) == ("json", [], MINIMAL_V10)


def test_import_invalid_config_reports_without_layout(client: TestClient):
    body = _import(client, json.dumps(MINIMAL_V10 | {"connections": []}).encode()).json()

    assert body["report"]["valid"] is False
    assert body["layout"] is None


def test_import_project_keeps_its_layout(client: TestClient):
    layout = {"nodes": {"1": {"x": 1, "y": 2}}}
    data = project.write_project(json.dumps(MINIMAL_V10).encode(), {}, layout)

    body = _import(client, data).json()

    assert (body["packageKind"], body["layout"]) == ("project", layout)


@pytest.mark.parametrize("data", [b"not a package", b"PK\x03\x04broken"])
def test_import_rejects_garbage(client: TestClient, data: bytes):
    assert _import(client, data).status_code == 422


def test_package_plain_round_trips(client: TestClient):
    response = client.post(
        "/api/package",
        files=[("config", _config_part(_tls_config())), ("files", ("certs/ca.pem", b"ca")), ("files", ("x.pem", b"x"))],
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    loaded = packaging.read_package(response.content)
    assert (loaded.kind, loaded.files) == ("plain-zip", {"certs/ca.pem": b"ca"})
    assert json.loads(loaded.config_json)["$schema"].endswith("config-schema-v1.0.json")


def test_package_signed_round_trips(client: TestClient, keypair_a: signing.KeyPair):
    response = client.post(
        "/api/package",
        files=[("config", _config_part(MINIMAL_V10)), ("signingKey", ("private.pem", keypair_a.private_pem))],
    )

    assert response.status_code == 200
    loaded = packaging.read_package(response.content, signing.load_public_key(keypair_a.public_pem))
    assert loaded.signature_status == "valid"
    assert keypair_a.private_pem not in response.content


def test_package_signed_with_encrypted_key(client: TestClient):
    pair = signing.generate_keypair(bits=2048, passphrase=b"pw")
    files = [("config", _config_part(MINIMAL_V10)), ("signingKey", ("private.pem", pair.private_pem))]

    ok = client.post("/api/package", files=files, data={"keyPassword": "pw"})
    bad = client.post("/api/package", files=files, data={"keyPassword": "wrong"})

    assert ok.status_code == 200
    assert bad.status_code == 400
    assert "wrong" not in bad.text


def test_package_with_garbage_key_is_rejected(client: TestClient):
    response = client.post(
        "/api/package", files=[("config", _config_part(MINIMAL_V10)), ("signingKey", ("private.pem", b"garbage"))]
    )

    assert response.status_code == 400


def test_package_with_missing_supporting_file_is_rejected(client: TestClient):
    response = client.post("/api/package", files=[("config", _config_part(_tls_config()))])

    assert response.status_code == 422
    assert "certs/ca.pem" in response.json()["detail"]


def test_package_with_invalid_config_returns_the_report(client: TestClient):
    response = client.post("/api/package", files=[("config", _config_part(MINIMAL_V10 | {"connections": []}))])

    assert response.status_code == 422
    assert response.json()["detail"]["valid"] is False


def test_package_with_malformed_json_is_rejected(client: TestClient):
    response = client.post("/api/package", files=[("config", ("config.json", b"{", "application/json"))])

    assert response.status_code == 422


def test_project_round_trips(client: TestClient):
    layout = {"nodes": {"1": {"x": 40, "y": 40}}}

    response = client.post(
        "/api/project",
        files=[("config", _config_part(_tls_config())), ("files", ("certs/ca.pem", b"ca"))],
        data={"layout": json.dumps(layout)},
    )

    loaded = project.read_project(response.content)
    assert response.status_code == 200
    assert (loaded.layout, loaded.files) == (layout, {"certs/ca.pem": b"ca"})


@pytest.mark.parametrize("layout", ["{", "[]"])
def test_project_rejects_bad_layout(client: TestClient, layout: str):
    response = client.post("/api/project", files=[("config", _config_part(MINIMAL_V10))], data={"layout": layout})

    assert response.status_code == 422


def test_oversized_body_is_rejected_with_413():
    app = create_app(ServerSettings(max_upload_bytes=100))
    with TestClient(app, base_url="http://localhost") as small_client:
        declared = small_client.post("/api/validate", content=b"x" * 500)
        chunked = small_client.post("/api/validate", content=iter([b"x" * 60, b"x" * 60]))
        small = small_client.get("/healthz")

    assert declared.status_code == 413
    assert chunked.status_code == 413
    assert small.status_code == 200


def test_untrusted_host_is_rejected(client: TestClient):
    assert client.get("/healthz", headers={"Host": "evil.example"}).status_code == 400


def test_non_http_scopes_pass_through():
    import asyncio

    from dg_configurator.web.security import BodySizeLimitMiddleware, SecurityHeadersMiddleware

    seen: list[str] = []

    async def app(scope: Any, _receive: Any, _send: Any) -> None:
        seen.append(scope["type"])

    for middleware in (BodySizeLimitMiddleware(app, 1), SecurityHeadersMiddleware(app)):
        asyncio.run(middleware({"type": "lifespan"}, None, None))

    assert seen == ["lifespan", "lifespan"]


def test_unrelated_errors_inside_the_app_are_not_swallowed():
    import asyncio

    from dg_configurator.web.security import BodySizeLimitMiddleware

    async def failing_app(_scope: Any, _receive: Any, _send: Any) -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        asyncio.run(BodySizeLimitMiddleware(failing_app, 10)({"type": "http", "headers": []}, None, None))


def test_no_response_leaks_private_key_material(client: TestClient, keypair_a: signing.KeyPair):
    key_line = keypair_a.private_pem.splitlines()[1]
    responses = [
        client.post(
            "/api/package",
            files=[("config", _config_part(MINIMAL_V10)), ("signingKey", ("private.pem", keypair_a.private_pem))],
        ),
        client.post(
            "/api/package",
            files=[("config", _config_part(MINIMAL_V10)), ("signingKey", ("private.pem", keypair_a.private_pem[:-30]))],
        ),
        client.get("/api/meta"),
    ]

    assert all(key_line not in response.content for response in responses)


def test_keypair_returns_the_three_files_and_a_usable_key_pair(client: TestClient):
    response = client.post("/api/keypair", json={"bits": 2048})

    body = response.json()
    files = {item["name"]: item for item in body["files"]}
    assert response.status_code == 200
    assert set(files) == {"private.pem", "public.pem", "public.txt"}
    assert files["private.pem"]["secret"] is True
    assert files["public.pem"]["secret"] is False
    public_pem = base64.b64decode(files["public.pem"]["contentBase64"])
    public_key = signing.load_public_key(public_pem)
    assert signing.load_public_key(body["publicKeyBase64Der"]).public_numbers() == public_key.public_numbers()
    assert base64.b64decode(files["public.txt"]["contentBase64"]) == body["publicKeyBase64Der"].encode() + b"\n"
    private_key = signing.load_private_key(base64.b64decode(files["private.pem"]["contentBase64"]))
    assert signing.verify(b"data", signing.sign(b"data", private_key), public_key)
    assert any("4096" in warning for warning in body["warnings"])
    assert any("passphrase" in warning for warning in body["warnings"])


def test_keypair_with_a_passphrase_encrypts_the_private_key(client: TestClient):
    body = client.post("/api/keypair", json={"bits": 2048, "passphrase": "s3cret-pass"}).json()

    private_pem = base64.b64decode(next(f for f in body["files"] if f["name"] == "private.pem")["contentBase64"])
    assert private_pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert signing.load_private_key(private_pem, b"s3cret-pass")
    assert not any("passphrase" in warning for warning in body["warnings"])


def test_keypair_defaults_to_4096_bits(client: TestClient, monkeypatch: pytest.MonkeyPatch, keypair_a: signing.KeyPair):
    requested: list[int] = []

    def fake_generate(bits: int, passphrase: bytes | None = None) -> signing.KeyPair:
        requested.append(bits)
        return keypair_a

    monkeypatch.setattr("dg_configurator.web.api.generate_keypair", fake_generate)

    body = client.post("/api/keypair", json={}).json()

    assert requested == [4096]
    assert not any("4096" in warning for warning in body["warnings"])


def test_invalid_keypair_request_is_rejected_without_echoing_the_passphrase(client: TestClient):
    response = client.post("/api/keypair", json={"bits": 1024, "passphrase": "s3cret-pass"})

    assert response.status_code == 422
    assert "s3cret-pass" not in response.text
    assert "input" not in response.json()["detail"][0]


def _subject(name: str) -> dict[str, Any]:
    return {"commonName": name, "organization": "Org"}


def _leaf(usage: str, name: str, **extra: Any) -> dict[str, Any]:
    san = {"dns": [f"{name}.example"], "uri": ["urn:test:app"] if usage == "opcua-application" else []}
    return {"usage": usage, "subject": _subject(name), "san": san, "key": "rsa-2048", **extra}


def _generate(client: TestClient, body: dict[str, Any]) -> Any:
    return client.post("/api/pki/generate", json=body)


def _certificate(body: dict[str, Any], name: str) -> x509.Certificate:
    item = next(f for f in body["files"] if f["name"] == name)
    return x509.load_pem_x509_certificate(base64.b64decode(item["contentBase64"]))


def test_meta_contains_the_pki_catalog(client: TestClient):
    pki = client.get("/api/meta").json()["pki"]

    usages = {item["usage"]: item for item in pki["usages"]}
    assert set(usages) == {
        "ca",
        "opcua-application",
        "mqtt-server",
        "mqtt-client",
        "sql-server",
        "sql-client",
        "tls-server",
        "tls-client",
    }
    assert usages["opcua-application"]["role"] == "application"
    assert usages["opcua-application"]["requiresApplicationUri"] is True
    assert usages["opcua-application"]["allowedKeys"] == ["rsa-2048", "rsa-3072", "rsa-4096"]
    assert (usages["ca"]["role"], usages["mqtt-server"]["role"], usages["sql-client"]["role"]) == (
        "ca",
        "server",
        "client",
    )
    assert pki["keys"] == ["rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384"]
    assert pki["domains"]["mqtt"] == {"server": "mqtt-server", "client": "mqtt-client"}
    assert pki["domains"]["opcua"] == {"server": "opcua-application", "client": "opcua-application"}


@pytest.mark.parametrize("domain", ["opcua", "mqtt", "sql", "tls"])
def test_pki_generate_full_pki_for_each_domain(client: TestClient, domain: str):
    usages = client.get("/api/meta").json()["pki"]["domains"][domain]
    body = {
        "issuer": "new-ca",
        "ca": {"subject": _subject("Test CA"), "key": "ec-p256"},
        "leaves": [
            _leaf(usages["server"], "srv", basename="server"),
            _leaf(usages["client"], "cli", basename="client"),
        ],
    }

    response = _generate(client, body)

    result = response.json()
    assert response.status_code == 200
    assert [f["name"] for f in result["files"]] == [
        "ca.pem",
        "ca-key.pem",
        "server.pem",
        "server-key.pem",
        "client.pem",
        "client-key.pem",
    ]
    assert {f["name"] for f in result["files"] if f["secret"]} == {"ca-key.pem", "server-key.pem", "client-key.pem"}
    ca = _certificate(result, "ca.pem")
    _certificate(result, "server.pem").verify_directly_issued_by(ca)
    _certificate(result, "client.pem").verify_directly_issued_by(ca)
    assert [c["file"] for c in result["certificates"]] == ["ca.pem", "server.pem", "client.pem"]
    assert len(result["certificates"][1]["sha256Fingerprint"].split(":")) == 32
    assert result["warnings"]


def test_pki_generate_with_an_existing_encrypted_ca(client: TestClient, ca_material: CaMaterial):
    body = {
        "issuer": "existing-ca",
        "existingCa": {
            "certificateBase64": base64.b64encode(ca_material.certificate_pem).decode(),
            "privateKeyBase64": base64.b64encode(ca_material.encrypted_key_pem).decode(),
            "passphrase": ca_material.passphrase.decode(),
        },
        "leaves": [{**_leaf("tls-client", "cli"), "passphrase": "leaf-secret"}],
    }

    result = _generate(client, body).json()

    _certificate(result, "client.pem").verify_directly_issued_by(ca_material.certificate)
    key_pem = base64.b64decode(next(f for f in result["files"] if f["name"] == "client-key.pem")["contentBase64"])
    assert key_pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")


def test_pki_generate_with_a_wrong_ca_passphrase_does_not_leak_it(client: TestClient, ca_material: CaMaterial):
    body = {
        "issuer": "existing-ca",
        "existingCa": {
            "certificateBase64": base64.b64encode(ca_material.certificate_pem).decode(),
            "privateKeyBase64": base64.b64encode(ca_material.encrypted_key_pem).decode(),
            "passphrase": "wrong-secret",
        },
        "leaves": [_leaf("tls-client", "cli")],
    }

    response = _generate(client, body)

    assert response.status_code == 422
    assert "wrong-secret" not in response.text


def test_pki_generate_rejects_invalid_requests(client: TestClient):
    unknown_usage = {"issuer": "self-signed", "leaves": [_leaf("nonsense", "x")]}
    ca_only_with_leaves = {"issuer": "ca-only", "ca": {"subject": _subject("CA")}, "leaves": [_leaf("tls-client", "x")]}
    bad_base64 = {
        "issuer": "existing-ca",
        "existingCa": {"certificateBase64": "!!", "privateKeyBase64": "!!"},
        "leaves": [_leaf("tls-client", "x")],
    }
    bad_key = {"issuer": "self-signed", "leaves": [_leaf("tls-client", "x", key="rsa-1024")]}

    assert _generate(client, unknown_usage).status_code == 422
    assert _generate(client, ca_only_with_leaves).status_code == 422
    bad = _generate(client, bad_base64)
    assert (bad.status_code, bad.json()["detail"]) == (422, "existingCa: invalid base64")
    assert _generate(client, bad_key).status_code == 422


def test_pki_generate_limits_the_number_of_leaves(client: TestClient):
    leaves = [_leaf("tls-client", f"c{i}", basename=f"c{i}") for i in range(21)]

    assert _generate(client, {"issuer": "self-signed", "leaves": leaves}).status_code == 422


def _archive(client: TestClient, files: list[tuple[str, bytes]]) -> Any:
    return client.post("/api/pki/archive", files=[("files", (name, content)) for name, content in files])


def test_pki_archive_zips_the_files_with_restrictive_key_permissions(client: TestClient):
    response = _archive(client, [("ca.pem", b"cert"), ("server-key.pem", b"key")])

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert archive.namelist() == ["ca.pem", "server-key.pem"]
        assert archive.read("ca.pem") == b"cert"
        modes = {info.filename: info.external_attr >> 16 for info in archive.infolist()}
    assert modes == {"ca.pem": 0o644, "server-key.pem": 0o600}


@pytest.mark.parametrize("name", ["../evil.pem", "a/b.pem", "ca.txt", ".pem", "ca pem.pem"])
def test_pki_archive_rejects_bad_names(client: TestClient, name: str):
    assert _archive(client, [(name, b"x")]).status_code == 422


def test_pki_archive_rejects_duplicate_names(client: TestClient):
    assert _archive(client, [("a.pem", b"1"), ("a.pem", b"2")]).status_code == 422


def _p12_bytes(password: bytes) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "leaf")])
    now = datetime.now(UTC)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(5)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=5))
        .sign(key, hashes.SHA256())
    )
    return pkcs12.serialize_key_and_certificates(
        b"n", key, leaf, [leaf], serialization.BestAvailableEncryption(password)
    )


def _convert(client: TestClient, data: bytes, name: str, form: dict[str, str] | None = None) -> Any:
    return client.post("/api/pki/convert", files={"file": (name, data)}, data=form or {})


def test_convert_pkcs12_with_a_password(client: TestClient):
    response = _convert(client, _p12_bytes(b"pw"), "store.p12", {"password": "pw"})

    body = response.json()
    assert response.status_code == 200
    assert [(f["name"], f["secret"]) for f in body["files"]] == [
        ("store.pem", False),
        ("store-ca.pem", False),
        ("store-key.pem", True),
    ]
    assert body["detected"][0].startswith("PKCS#12 keystore")
    assert any("clear text" in warning for warning in body["warnings"])


def test_convert_can_encrypt_the_output_key_and_set_the_basename(client: TestClient):
    form = {"password": "pw", "outputPassphrase": "out-secret", "basename": "gateway"}
    response = _convert(client, _p12_bytes(b"pw"), "store.p12", form)

    files = {f["name"]: base64.b64decode(f["contentBase64"]) for f in response.json()["files"]}
    assert files["gateway-key.pem"].startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")


def test_convert_with_a_wrong_password_does_not_leak_it(client: TestClient):
    response = _convert(client, _p12_bytes(b"pw"), "store.p12", {"password": "wrong-secret"})

    assert response.status_code == 422
    assert "wrong-secret" not in response.text


def test_convert_der_certificate(client: TestClient):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "c")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=5))
        .sign(key, hashes.SHA256())
    )

    body = _convert(client, certificate.public_bytes(serialization.Encoding.DER), "cert.der").json()

    assert [f["name"] for f in body["files"]] == ["cert.pem"]


def test_convert_rejects_garbage_and_oversized_input(client: TestClient):
    assert _convert(client, b"garbage", "x.bin").status_code == 422
    assert _convert(client, b"x" * (1024 * 1024 + 2), "big.bin").status_code == 422
