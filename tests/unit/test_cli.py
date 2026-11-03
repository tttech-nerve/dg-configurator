# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for the dg-configurator command-line interface."""

import json
import runpy
import shutil
import sys
from datetime import UTC, datetime, timedelta
from importlib.metadata import version
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12

from dg_configurator import __version__, cli, signing
from dg_configurator.cli import PROG, main
from dg_configurator.packaging import read_package
from dg_configurator.pki import keys as pki_keys
from tests.conftest import FIXTURES_DIR, INVALID_CONFIGS, VALID_CONFIGS

MINIMAL_V10 = FIXTURES_DIR / "configs" / "valid" / "v1.0" / "minimal.json"


def _tls_config(tmp_path: Path) -> Path:
    """A directory with a config referencing ca.pem plus the file itself."""
    directory = tmp_path / "project"
    directory.mkdir()
    document = json.loads(MINIMAL_V10.read_text())
    document["endpoints"][0].update(url="mqtts://h", security={"tlsEnabled": True, "ca": "certs/ca.pem"})
    (directory / "config.json").write_text(json.dumps(document))
    (directory / "certs").mkdir()
    (directory / "certs" / "ca.pem").write_bytes(b"ca-pem")
    return directory


def test_version_matches_distribution_metadata():
    assert __version__ == version("dg-configurator")


def test_version_flag_prints_program_and_version(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"{PROG} {__version__}"


def test_missing_command_is_a_usage_error(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exc_info:
        main([])

    assert exc_info.value.code == 2
    assert "required" in capsys.readouterr().err


def test_unknown_argument_exits_with_usage_error(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exc_info:
        main(["validate", "x.json", "--does-not-exist"])

    assert exc_info.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_python_dash_m_entrypoint_delegates_to_main(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sys, "argv", [PROG, "--version"])

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_module("dg_configurator", run_name="__main__")

    assert exc_info.value.code == 0


@pytest.mark.parametrize("path", VALID_CONFIGS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_validate_accepts_valid_fixtures(path: Path, tmp_path: Path):
    target = tmp_path / "config.json"
    shutil.copy(path, target)

    assert main(["validate", str(target)]) == 0


@pytest.mark.parametrize("path", INVALID_CONFIGS, ids=lambda p: p.stem)
def test_validate_rejects_invalid_fixtures(path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    target = tmp_path / "config.json"
    shutil.copy(path, target)

    if path.stem == "malformed_json":
        assert main(["validate", str(target)]) == 1
        assert "json_invalid" in capsys.readouterr().err
    else:
        assert main(["validate", str(target)]) == 1
        assert capsys.readouterr().out.strip().endswith("invalid")


def test_validate_json_format(capsys: pytest.CaptureFixture[str]):
    exit_code = main(["validate", "--format", "json", str(FIXTURES_DIR / "configs" / "invalid" / "orphan_port.json")])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload["valid"] is False
    assert payload["diagnostics"][0]["code"] == "orphan_port"


def test_validate_directory_with_supporting_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    directory = _tls_config(tmp_path)

    assert main(["validate", str(directory)]) == 0

    (directory / "certs" / "ca.pem").unlink()
    assert main(["validate", "--format", "json", str(directory)]) == 1
    assert "file_missing" in capsys.readouterr().out


def test_validate_directory_with_invalid_config_reports_the_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    directory = tmp_path / "project"
    directory.mkdir()
    (directory / "config.json").write_text("{}")

    assert main(["validate", str(directory)]) == 1
    assert "schema_invalid" in capsys.readouterr().err


def test_validate_directory_without_config_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["validate", str(tmp_path)]) == 1
    assert "does not contain config.json" in capsys.readouterr().err


def test_validate_missing_path_fails_cleanly(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["validate", str(tmp_path / "absent.json")]) == 1
    assert "absent.json" in capsys.readouterr().err


def test_pack_writes_a_plain_package(tmp_path: Path):
    output = tmp_path / "plain.zip"

    assert main(["pack", str(_tls_config(tmp_path)), "-o", str(output)]) == 0

    loaded = read_package(output.read_bytes())
    assert loaded.kind == "plain-zip"
    assert loaded.files == {"certs/ca.pem": b"ca-pem"}
    assert json.loads(loaded.config_json)["version"] == "1.0"


def test_pack_signs_with_a_key(tmp_path: Path, keypair_a: signing.KeyPair, capsys: pytest.CaptureFixture[str]):
    key = tmp_path / "private.pem"
    key.write_bytes(keypair_a.private_pem)
    output = tmp_path / "signed.zip"

    assert main(["pack", str(MINIMAL_V10), "-o", str(output), "--sign-key", str(key)]) == 0

    loaded = read_package(output.read_bytes(), signing.load_public_key(keypair_a.public_pem))
    assert loaded.signature_status == "valid"
    assert "weak_signing_key" in capsys.readouterr().err


def test_pack_with_a_password_protected_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pair = signing.generate_keypair(bits=2048, passphrase=b"pw")
    key = tmp_path / "private.pem"
    key.write_bytes(pair.private_pem)
    monkeypatch.setenv("KEY_PW", "pw")
    password_file = tmp_path / "pw.txt"
    password_file.write_text("pw\n")
    argv = ["pack", str(MINIMAL_V10), "--sign-key", str(key)]

    assert main([*argv, "-o", str(tmp_path / "env.zip"), "--key-password-env", "KEY_PW"]) == 0
    assert main([*argv, "-o", str(tmp_path / "file.zip"), "--key-password-file", str(password_file)]) == 0
    monkeypatch.setattr("getpass.getpass", lambda _prompt: "pw")
    assert main([*argv, "-o", str(tmp_path / "prompt.zip"), "--prompt-password"]) == 0
    assert main([*argv, "-o", str(tmp_path / "none.zip")]) == 1


def test_pack_with_empty_prompted_password_uses_no_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, keypair_a):
    key = tmp_path / "private.pem"
    key.write_bytes(keypair_a.private_pem)
    monkeypatch.setattr("getpass.getpass", lambda _prompt: "")

    assert (
        main(["pack", str(MINIMAL_V10), "-o", str(tmp_path / "o.zip"), "--sign-key", str(key), "--prompt-password"])
        == 0
    )


def test_pack_fails_when_the_password_variable_is_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, keypair_a):
    key = tmp_path / "private.pem"
    key.write_bytes(keypair_a.private_pem)
    monkeypatch.delenv("MISSING_PW", raising=False)

    argv = ["pack", str(MINIMAL_V10), "-o", str(tmp_path / "o.zip"), "--sign-key", str(key)]
    assert main([*argv, "--key-password-env", "MISSING_PW"]) == 1


def test_pack_refuses_to_overwrite_without_force(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    output = tmp_path / "out.zip"
    output.write_bytes(b"existing")

    assert main(["pack", str(MINIMAL_V10), "-o", str(output)]) == 1
    assert output.read_bytes() == b"existing"
    assert "--force" in capsys.readouterr().err

    assert main(["pack", str(MINIMAL_V10), "-o", str(output), "--force"]) == 0
    assert output.read_bytes() != b"existing"


def test_pack_refuses_an_invalid_config_unless_told_otherwise(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    source = FIXTURES_DIR / "configs" / "invalid" / "orphan_port.json"
    output = tmp_path / "out.zip"

    assert main(["pack", str(source), "-o", str(output)]) == 1
    assert not output.exists()
    assert "refusing to pack" in capsys.readouterr().err

    assert main(["pack", str(source), "-o", str(output), "--no-validate"]) == 0
    assert output.exists()


def test_pack_accepts_packages_as_source(tmp_path: Path):
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    assert main(["pack", str(_tls_config(tmp_path)), "-o", str(first)]) == 0

    assert main(["pack", str(first), "-o", str(second)]) == 0
    assert first.read_bytes() == second.read_bytes()


def test_keygen_writes_key_files_with_private_permissions(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    out = tmp_path / "keys"

    assert main(["keygen", "-o", str(out), "--bits", "2048"]) == 0

    assert (out / "private.pem").stat().st_mode & 0o777 == 0o600
    public_text = (out / "public.txt").read_text()
    assert signing.load_public_key(public_text).key_size == 2048
    assert signing.load_public_key((out / "public.pem").read_bytes()).key_size == 2048
    assert capsys.readouterr().out.strip() == public_text.strip()
    assert signing.load_private_key((out / "private.pem").read_bytes()).key_size == 2048


def test_keygen_refuses_to_overwrite_without_force(tmp_path: Path):
    argv = ["keygen", "-o", str(tmp_path), "--bits", "2048"]
    assert main(argv) == 0
    before = (tmp_path / "private.pem").read_bytes()

    assert main(argv) == 1
    assert (tmp_path / "private.pem").read_bytes() == before
    assert main([*argv, "--force"]) == 0
    assert (tmp_path / "private.pem").read_bytes() != before


def test_keygen_with_passphrase_from_environment_or_prompt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("KEY_PASSPHRASE", "pw")
    assert main(["keygen", "-o", str(tmp_path / "env"), "--bits", "2048", "--passphrase-env", "KEY_PASSPHRASE"]) == 0
    assert b"ENCRYPTED" in (tmp_path / "env" / "private.pem").read_bytes()

    monkeypatch.setattr("getpass.getpass", lambda _prompt: "pw")
    assert main(["keygen", "-o", str(tmp_path / "prompt"), "--bits", "2048", "--passphrase"]) == 0
    assert b"ENCRYPTED" in (tmp_path / "prompt" / "private.pem").read_bytes()

    monkeypatch.setattr("getpass.getpass", lambda _prompt: "")
    assert main(["keygen", "-o", str(tmp_path / "empty"), "--bits", "2048", "--passphrase"]) == 0
    assert b"ENCRYPTED" not in (tmp_path / "empty" / "private.pem").read_bytes()


def test_keygen_fails_when_the_passphrase_variable_is_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MISSING_PASSPHRASE", raising=False)

    assert main(["keygen", "-o", str(tmp_path), "--passphrase-env", "MISSING_PASSPHRASE"]) == 1


def test_verify_accepts_valid_signatures_and_rejects_others(
    tmp_path: Path, keypair_a: signing.KeyPair, keypair_b: signing.KeyPair, capsys: pytest.CaptureFixture[str]
):
    key = tmp_path / "private.pem"
    key.write_bytes(keypair_a.private_pem)
    signed = tmp_path / "signed.zip"
    plain = tmp_path / "plain.zip"
    main(["pack", str(MINIMAL_V10), "-o", str(signed), "--sign-key", str(key)])
    main(["pack", str(MINIMAL_V10), "-o", str(plain)])
    public_file = tmp_path / "public.pem"
    public_file.write_bytes(keypair_a.public_pem)
    capsys.readouterr()

    assert main(["verify", str(signed), "--public-key", str(public_file)]) == 0
    assert main(["verify", str(signed), "--public-key", keypair_a.public_b64der]) == 0
    assert capsys.readouterr().out.count("valid") == 2
    assert main(["verify", str(signed), "--public-key", keypair_b.public_b64der]) == 1
    assert "invalid" in capsys.readouterr().err
    assert main(["verify", str(plain), "--public-key", str(public_file)]) == 1
    assert "not signed" in capsys.readouterr().err


def test_verify_with_a_garbage_public_key_fails_cleanly(tmp_path: Path):
    plain = tmp_path / "plain.zip"
    main(["pack", str(MINIMAL_V10), "-o", str(plain)])

    assert main(["verify", str(plain), "--public-key", "garbage"]) == 1


@pytest.mark.parametrize("config_version", ["1.0", "1.1"])
def test_schema_command_prints_json_schema(config_version: str, capsys: pytest.CaptureFixture[str]):
    assert main(["schema", "--config-version", config_version]) == 0

    schema = json.loads(capsys.readouterr().out)
    assert "$defs" in schema
    assert config_version in schema["$comment"]


def test_schema_command_writes_a_file(tmp_path: Path):
    target = tmp_path / "schema.json"

    assert main(["schema", "-o", str(target)]) == 0

    assert "$defs" in json.loads(target.read_text())


def test_serve_starts_uvicorn(monkeypatch: pytest.MonkeyPatch):
    calls: dict[str, Any] = {}
    monkeypatch.setattr(cli.uvicorn, "run", lambda app, **kwargs: calls.update(app=app, **kwargs))

    assert main(["serve", "--port", "9999", "--allowed-host", "example.test"]) == 0

    assert calls["port"] == 9999
    assert calls["host"] == "127.0.0.1"
    assert calls["app"].state.settings.allowed_hosts == ["example.test"]
    assert calls["app"].state.settings.max_upload_bytes == 50 * 1024 * 1024


def test_serve_can_open_the_browser(monkeypatch: pytest.MonkeyPatch):
    started: list[tuple[Any, ...]] = []

    class FakeTimer:
        def __init__(self, interval: float, function: Any, args: tuple[Any, ...]) -> None:
            started.append((interval, function, args))

        def start(self) -> None:
            started.append(("started",))

    monkeypatch.setattr(cli.uvicorn, "run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli.threading, "Timer", FakeTimer)

    assert main(["serve", "--open-browser", "--max-upload-mb", "1"]) == 0

    assert started[0][2] == ("http://127.0.0.1:8080",)
    assert started[1] == ("started",)


def _pki(*args: str) -> list[str]:
    return ["pki", *args]


def _full_opcua(out: Path, *extra: str) -> list[str]:
    return _pki(
        "full",
        "--domain",
        "opcua",
        "-o",
        str(out),
        "--key",
        "rsa-2048",
        "--org",
        "Example",
        "--server-cn",
        "gw",
        "--server-dns",
        "gw.local",
        "--server-uri",
        "urn:gw:server",
        "--client-cn",
        "gwc",
        "--client-dns",
        "gwc.local",
        "--client-uri",
        "urn:gw:client",
        *extra,
    )


def test_pki_full_writes_all_files_with_private_key_permissions(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    out = tmp_path / "pki"

    assert main(_full_opcua(out)) == 0

    names = ["ca.pem", "ca-key.pem", "server.pem", "server-key.pem", "client.pem", "client-key.pem"]
    assert sorted(path.name for path in out.iterdir()) == sorted(names)
    for name in names:
        assert (out / name).stat().st_mode & 0o777 == (0o600 if name.endswith("-key.pem") else 0o644)
    assert out.stat().st_mode & 0o777 == 0o700
    captured = capsys.readouterr()
    assert "SHA-256" in captured.out
    assert "WARNING" in captured.err


def test_pki_full_refuses_to_overwrite_and_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    out = tmp_path / "pki"
    out.mkdir()
    (out / "client-key.pem").write_text("keep")

    assert main(_full_opcua(out)) == 1

    assert "already exists" in capsys.readouterr().err
    assert [path.name for path in out.iterdir()] == ["client-key.pem"]
    assert main(_full_opcua(out, "--force")) == 0


def test_pki_full_for_mqtt_without_a_uri(tmp_path: Path):
    argv = _pki("full", "--domain", "mqtt", "-o", str(tmp_path), "--key", "ec-p256", "--server-cn", "broker")
    argv += ["--server-dns", "broker.local", "--client-cn", "dev"]

    assert main(argv) == 0

    assert (tmp_path / "server.pem").is_file()


def test_pki_full_with_passphrases_from_env_and_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setenv("CA_PW", "ca-secret")
    secret_file = tmp_path / "server.pw"
    secret_file.write_text("server-secret\n")
    out = tmp_path / "pki"

    assert main(_full_opcua(out, "--ca-passphrase-env", "CA_PW", "--server-passphrase-file", str(secret_file))) == 0

    assert (out / "ca-key.pem").read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert (out / "client-key.pem").read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    assert pki_keys.load_private_key_any((out / "server-key.pem").read_bytes(), b"server-secret")
    captured = capsys.readouterr()
    assert "ca-secret" not in captured.out + captured.err
    assert "server-secret" not in captured.out + captured.err


def test_pki_prompt_mismatch_exits_with_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    answers = iter(["first", "second"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(answers))

    assert main(_full_opcua(tmp_path / "pki", "--ca-passphrase-prompt")) == 1

    assert not (tmp_path / "pki").exists()


def test_pki_prompt_with_matching_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "same")

    assert main(_full_opcua(tmp_path / "pki", "--ca-passphrase-prompt")) == 0

    assert pki_keys.load_private_key_any((tmp_path / "pki" / "ca-key.pem").read_bytes(), b"same")


def test_pki_ca_command(tmp_path: Path):
    assert main(_pki("ca", "-o", str(tmp_path), "--key", "ec-p256", "--org", "Acme")) == 0

    assert sorted(path.name for path in tmp_path.iterdir()) == ["ca-key.pem", "ca.pem"]
    certificate = x509.load_pem_x509_certificate((tmp_path / "ca.pem").read_bytes())
    assert certificate.subject.rfc4514_string() == "CN=Acme Root CA,O=Acme"


def _make_ca(directory: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CA_PW", "ca-secret")
    assert main(_pki("ca", "-o", str(directory), "--key", "ec-p256", "--ca-passphrase-env", "CA_PW")) == 0


def test_pki_client_with_an_encrypted_ca_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ca_dir, out = tmp_path / "ca", tmp_path / "out"
    _make_ca(ca_dir, monkeypatch)
    argv = _pki("client", "--usage", "mqtt-client", "-o", str(out), "--key", "ec-p256", "--cn", "device-1")
    argv += ["--ca-cert", str(ca_dir / "ca.pem"), "--ca-key", str(ca_dir / "ca-key.pem")]

    assert main([*argv, "--ca-passphrase-env", "CA_PW"]) == 0

    leaf = x509.load_pem_x509_certificate((out / "client.pem").read_bytes())
    leaf.verify_directly_issued_by(x509.load_pem_x509_certificate((ca_dir / "ca.pem").read_bytes()))
    assert main(argv) == 1


def test_pki_server_signed_by_a_ca_from_a_passphrase_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ca_dir = tmp_path / "ca"
    _make_ca(ca_dir, monkeypatch)
    secret_file = tmp_path / "ca.pw"
    secret_file.write_text("ca-secret")
    argv = _pki("server", "--domain", "sql", "-o", str(tmp_path / "out"), "--key", "ec-p256", "--cn", "db")
    argv += ["--dns", "db.local", "--ip", "192.0.2.5", "--ca-cert", str(ca_dir / "ca.pem")]
    argv += ["--ca-key", str(ca_dir / "ca-key.pem"), "--ca-passphrase-file", str(secret_file)]

    assert main(argv) == 0

    leaf = x509.load_pem_x509_certificate((tmp_path / "out" / "server.pem").read_bytes())
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName
    ) == ["db.local"]


def test_pki_self_signed_opcua(tmp_path: Path):
    argv = _pki("client", "--domain", "opcua", "-o", str(tmp_path), "--key", "rsa-2048", "--cn", "app", "--org", "X")
    argv += ["--uri", "urn:x:app", "--dns", "h.local", "--self-signed", "--basename", "opcua"]

    assert main(argv) == 0

    assert sorted(path.name for path in tmp_path.iterdir()) == ["opcua-key.pem", "opcua.pem"]


def test_pki_leaf_needs_an_issuer_choice(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exc_info:
        main(_pki("server", "--domain", "tls", "-o", str(tmp_path), "--cn", "x"))

    assert exc_info.value.code == 2
    assert "--ca-cert" in capsys.readouterr().err


def test_pki_ca_cert_without_ca_key_exits_with_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    argv = _pki("server", "--domain", "tls", "-o", str(tmp_path), "--cn", "x", "--dns", "x", "--ca-cert", "ca.pem")

    assert main(argv) == 1

    assert "--ca-key" in capsys.readouterr().err


def test_pki_opcua_without_a_uri_explains_what_to_do(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    argv = _pki("client", "--domain", "opcua", "-o", str(tmp_path), "--cn", "x", "--dns", "x", "--self-signed")

    assert main(argv) == 1

    assert "--uri" in capsys.readouterr().err
    assert not list(tmp_path.iterdir())


def _p12(directory: Path, name: str = "store.p12", password: bytes = b"pw") -> Path:
    ca = ec.generate_private_key(ec.SECP256R1())
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    ca_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "CA")])
    leaf_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "leaf")])
    builder = x509.CertificateBuilder().serial_number(7).not_valid_before(now).not_valid_after(now + timedelta(days=9))
    leaf = builder.subject_name(leaf_name).issuer_name(ca_name).public_key(key.public_key()).sign(ca, hashes.SHA256())
    data = pkcs12.serialize_key_and_certificates(b"n", key, leaf, None, serialization.BestAvailableEncryption(password))
    path = directory / name
    path.write_bytes(data)
    return path


def test_convert_writes_pem_files_and_reports_the_detected_format(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    source = _p12(tmp_path)
    monkeypatch.setenv("P12_PW", "pw")
    out = tmp_path / "out"

    assert main(["convert", str(source), "-o", str(out), "--password-env", "P12_PW"]) == 0

    assert sorted(path.name for path in out.iterdir()) == ["store-key.pem", "store.pem"]
    assert (out / "store-key.pem").stat().st_mode & 0o777 == 0o600
    captured = capsys.readouterr()
    assert "PKCS#12 keystore (key, certificate)" in captured.out
    assert "clear text" in captured.err


def test_convert_with_password_file_output_passphrase_and_basename(tmp_path: Path):
    source = _p12(tmp_path)
    password_file = tmp_path / "in.pw"
    password_file.write_text("pw\n")
    out_file = tmp_path / "out.pw"
    out_file.write_text("new-secret\n")
    out = tmp_path / "out"

    argv = ["convert", str(source), "-o", str(out), "--password-file", str(password_file)]
    assert main([*argv, "--output-passphrase-file", str(out_file), "--basename", "gateway"]) == 0

    assert pki_keys.load_private_key_any((out / "gateway-key.pem").read_bytes(), b"new-secret")


def test_convert_prompts_for_the_password_and_confirms_the_output_passphrase(tmp_path: Path, monkeypatch):
    source = _p12(tmp_path)
    answers = iter(["pw", "out", "out"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(answers))

    argv = ["convert", str(source), "-o", str(tmp_path / "out"), "--prompt-password", "--output-passphrase-prompt"]

    assert main(argv) == 0
    assert pki_keys.load_private_key_any((tmp_path / "out" / "store-key.pem").read_bytes(), b"out")


def test_convert_wrong_password_exits_with_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    source = _p12(tmp_path)
    secret_file = tmp_path / "wrong.pw"
    secret_file.write_text("totally-wrong")

    assert main(["convert", str(source), "-o", str(tmp_path / "out"), "--password-file", str(secret_file)]) == 1

    captured = capsys.readouterr()
    assert "password" in captured.err
    assert "totally-wrong" not in captured.out + captured.err
    assert not (tmp_path / "out").exists()


def test_convert_detects_colliding_output_names_and_writes_nothing(tmp_path: Path):
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    sources = [_p12(first, "same.p12"), _p12(second, "same.p12")]
    secret = tmp_path / "pw"
    secret.write_text("pw")

    argv = ["convert", *map(str, sources), "-o", str(tmp_path / "out"), "--password-file", str(secret)]

    assert main(argv) == 1
    assert not (tmp_path / "out").exists()


def test_convert_several_inputs(tmp_path: Path):
    sources = [_p12(tmp_path, "one.p12"), _p12(tmp_path, "two.p12")]
    secret = tmp_path / "pw"
    secret.write_text("pw")

    argv = ["convert", *map(str, sources), "-o", str(tmp_path / "out"), "--password-file", str(secret)]

    assert main(argv) == 0
    assert len(list((tmp_path / "out").iterdir())) == 4


def test_convert_basename_needs_exactly_one_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    sources = [_p12(tmp_path, "one.p12"), _p12(tmp_path, "two.p12")]

    assert main(["convert", *map(str, sources), "-o", str(tmp_path / "o"), "--basename", "x"]) == 1

    assert "--basename" in capsys.readouterr().err


def test_convert_refuses_to_overwrite_without_force(tmp_path: Path):
    source = _p12(tmp_path)
    secret = tmp_path / "pw"
    secret.write_text("pw")
    argv = ["convert", str(source), "-o", str(tmp_path), "--password-file", str(secret)]

    assert main(argv) == 0
    assert main(argv) == 1
    assert main([*argv, "--force"]) == 0
