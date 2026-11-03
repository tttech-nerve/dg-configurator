# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Command-line interface of dg-configurator."""

import argparse
import contextlib
import getpass
import json
import os
import sys
import threading
import webbrowser
from collections.abc import Sequence
from pathlib import Path

import uvicorn
from pydantic import ValidationError

from dg_configurator import __version__
from dg_configurator.errors import ConfiguratorError, OutputExistsError
from dg_configurator.files import load_files_from_dir
from dg_configurator.model import ConfigVersion, UserConfig
from dg_configurator.packaging import build_plain_zip, build_signed_zip, read_package
from dg_configurator.pki import (
    ALLOWED_KEYS,
    CaRequest,
    ExistingCa,
    GeneratedFile,
    KeySpec,
    LeafRequest,
    PkiRequest,
    SanSpec,
    SubjectSpec,
    Usage,
    convert_to_pem,
    generate_pki,
)
from dg_configurator.pki.generator import CertificateSummary
from dg_configurator.pki.profiles import client_usage_for, server_usage_for
from dg_configurator.signing import generate_keypair, is_weak_key, load_private_key, load_public_key
from dg_configurator.validation import ValidationReport, validate
from dg_configurator.web.app import ServerSettings, create_app

PROG = "dg-configurator"
_MIB = 1024 * 1024
_PRIVATE_FILE_MODE = 0o600
_PRIVATE_DIR_MODE = 0o700
_DOMAINS = ("opcua", "mqtt", "sql", "tls")


def _write_output(path: Path, data: bytes, force: bool) -> None:
    if path.exists() and not force:
        raise OutputExistsError(f"{path} already exists (use --force to overwrite)")
    path.write_bytes(data)


def _read_secret_from_env(name: str) -> bytes:
    value = os.environ.get(name)
    if not value:
        raise ConfiguratorError(f"environment variable {name} is not set or empty")
    return value.encode("utf-8")


def _resolve_key_password(args: argparse.Namespace) -> bytes | None:
    if args.key_password_env:
        return _read_secret_from_env(args.key_password_env)
    if args.key_password_file:
        return Path(args.key_password_file).read_bytes().strip() or None
    if args.prompt_password:
        value = getpass.getpass("Key password (leave empty for none): ")
        return value.encode("utf-8") if value else None
    return None


def _load_directory(path: Path) -> tuple[bytes, dict[str, bytes]]:
    config_path = path / "config.json"
    if not config_path.is_file():
        raise ConfiguratorError(f"{path} does not contain config.json")
    config_json = config_path.read_bytes()
    try:
        config = UserConfig.model_validate_json(config_json)
    except ValidationError:
        # validation reports the problems; without a parsed config there are no linked files to load
        return config_json, {}
    files: dict[str, bytes] = {}
    for linked in config.linked_files():
        # a missing file is reported by the validation as file_missing
        with contextlib.suppress(FileNotFoundError):
            files.update(load_files_from_dir(path, [linked.name]))
    return config_json, files


def _load_source(path: Path) -> tuple[bytes, dict[str, bytes]]:
    """Load a SOURCE argument: a directory with config.json, a config.json file or any package format."""
    if path.is_dir():
        return _load_directory(path)
    data = path.read_bytes()
    if not data.startswith(b"PK"):
        # a bare document: let the validation report syntax errors with line and column
        return data, {}
    loaded = read_package(data)
    return loaded.config_json, loaded.files


def _print_diagnostics(report: ValidationReport, *, errors_only: bool = False) -> None:
    for diagnostic in report.diagnostics:
        if errors_only and diagnostic.severity != "error":
            continue
        location = ".".join(str(segment) for segment in diagnostic.path) or "<document>"
        text = f"{diagnostic.severity.upper()} [{diagnostic.code}] {location}: {diagnostic.message}"
        print(text, file=sys.stderr if diagnostic.severity == "error" else sys.stdout)


def _cmd_validate(args: argparse.Namespace) -> int:
    config_json, files = _load_source(Path(args.path))
    report = validate(config_json, available_files=set(files))
    if args.format == "json":
        payload = {
            "valid": report.valid,
            "version": report.version,
            "diagnostics": [
                {
                    "severity": d.severity,
                    "code": d.code,
                    "path": list(d.path),
                    "message": d.message,
                    "line": d.line,
                    "column": d.column,
                }
                for d in report.diagnostics
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        _print_diagnostics(report)
        print("valid" if report.valid else "invalid")
    return 0 if report.valid else 1


def _cmd_pack(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if output.exists() and not args.force:
        raise OutputExistsError(f"{output} already exists (use --force to overwrite)")
    config_json, files = _load_source(Path(args.source))
    if not args.no_validate:
        report = validate(config_json, available_files=set(files))
        if not report.valid:
            _print_diagnostics(report, errors_only=True)
            print("refusing to pack an invalid config (use --no-validate to override)", file=sys.stderr)
            return 1

    if args.sign_key:
        private_key = load_private_key(Path(args.sign_key).read_bytes(), _resolve_key_password(args))
        if is_weak_key(private_key.public_key()):
            print("WARNING [weak_signing_key]: RSA keys below 4096 bits are not recommended", file=sys.stderr)
        data = build_signed_zip(config_json, files, private_key)
    else:
        data = build_plain_zip(config_json, files)

    _write_output(output, data, args.force)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    key_argument = Path(args.public_key)
    public_key = load_public_key(key_argument.read_text() if key_argument.is_file() else args.public_key)
    loaded = read_package(Path(args.package).read_bytes(), public_key=public_key)
    if loaded.signature_status == "valid":
        print("valid")
        return 0
    print(f"signature status: {loaded.signature_status or 'not signed'}", file=sys.stderr)
    return 1


def _write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _PRIVATE_FILE_MODE)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
    path.chmod(_PRIVATE_FILE_MODE)


def _cmd_keygen(args: argparse.Namespace) -> int:
    out_dir = Path(args.output)
    targets = [out_dir / name for name in ("private.pem", "public.pem", "public.txt")]
    existing = [target for target in targets if target.exists()]
    if existing and not args.force:
        raise OutputExistsError(f"{existing[0]} already exists (use --force to overwrite)")

    passphrase: bytes | None = None
    if args.passphrase_env:
        passphrase = _read_secret_from_env(args.passphrase_env)
    elif args.passphrase:
        value = getpass.getpass("Passphrase for the private key (leave empty for none): ")
        passphrase = value.encode("utf-8") if value else None

    keypair = generate_keypair(bits=args.bits, passphrase=passphrase)
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_private(targets[0], keypair.private_pem)
    targets[1].write_bytes(keypair.public_pem)
    targets[2].write_text(keypair.public_b64der + "\n")
    print(keypair.public_b64der)
    return 0


def _resolve_secret(*, env: str | None, file: str | None, prompt: bool, label: str, confirm: bool) -> bytes | None:
    """Read a secret from an environment variable, a file or an interactive prompt (never from an argument)."""
    if env:
        return _read_secret_from_env(env)
    if file:
        return Path(file).read_bytes().strip() or None
    if not prompt:
        return None
    value = getpass.getpass(f"{label} (leave empty for none): ")
    if confirm and value != getpass.getpass("Repeat to confirm: "):
        raise ConfiguratorError(f"the {label} entries do not match")
    return value.encode("utf-8") if value else None


def _resolve_passphrase(args: argparse.Namespace, role: str, *, confirm: bool) -> bytes | None:
    return _resolve_secret(
        env=getattr(args, f"{role}_passphrase_env", None),
        file=getattr(args, f"{role}_passphrase_file", None),
        prompt=getattr(args, f"{role}_passphrase_prompt", False),
        label=f"{role} key passphrase",
        confirm=confirm,
    )


def _write_generated(out_dir: Path, files: Sequence[GeneratedFile], force: bool) -> None:
    """Write generated files; every target is checked first so that nothing is written on a conflict."""
    targets = [out_dir / item.name for item in files]
    existing = [target for target in targets if target.exists()]
    if existing and not force:
        raise OutputExistsError(f"{existing[0]} already exists (use --force to overwrite)")
    out_dir.mkdir(parents=True, exist_ok=True, mode=_PRIVATE_DIR_MODE)
    for target, item in zip(targets, files, strict=True):
        if item.secret:
            _write_private(target, item.content)
        else:
            target.write_bytes(item.content)
        print(f"wrote {target}")


def _print_certificates(certificates: Sequence[CertificateSummary]) -> None:
    for summary in certificates:
        print(
            f"{summary.file}: {summary.subject}; expires {summary.not_after:%Y-%m-%d}; "
            f"SHA-256 {summary.sha256_fingerprint}"
        )


def _print_warnings(warnings: Sequence[str]) -> None:
    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)


def _subject(args: argparse.Namespace, common_name: str) -> SubjectSpec:
    return SubjectSpec(
        common_name=common_name,
        organization=args.org,
        organizational_unit=args.ou,
        country=args.country,
        state=args.state,
        locality=args.locality,
    )


def _leaf_request(args: argparse.Namespace, prefix: str, usage: Usage, role: str) -> LeafRequest:
    san = SanSpec(
        dns_names=tuple(getattr(args, f"{prefix}dns", None) or ()),
        ip_addresses=tuple(getattr(args, f"{prefix}ip", None) or ()),
        uris=tuple(getattr(args, f"{prefix}uri", None) or ()),
        emails=tuple(getattr(args, f"{prefix}email", None) or ()),
    )
    if usage is Usage.OPCUA_APPLICATION and not san.uris:
        raise ConfiguratorError(
            f"an OPC UA application certificate needs the application URI: pass --{prefix.replace('_', '-')}uri "
            "urn:<host>:<application> (it must match the URI the peer expects)"
        )
    return LeafRequest(
        usage=usage,
        subject=_subject(args, getattr(args, f"{prefix}cn")),
        san=san,
        key=KeySpec.parse(args.key),
        validity_days=args.validity_days,
        passphrase=_resolve_passphrase(args, role, confirm=True),
        basename=getattr(args, "basename", None) or role,
    )


def _ca_request(args: argparse.Namespace, common_name: str | None, validity_days: int | None) -> CaRequest:
    return CaRequest(
        subject=_subject(args, common_name or f"{args.org or 'Data Gateway'} Root CA"),
        key=KeySpec.parse(args.key),
        validity_days=validity_days,
        passphrase=_resolve_passphrase(args, "ca", confirm=True),
    )


def _existing_ca(args: argparse.Namespace) -> ExistingCa:
    if not args.ca_key:
        raise ConfiguratorError("--ca-cert needs --ca-key")
    return ExistingCa(
        certificate_pem=Path(args.ca_cert).read_bytes(),
        private_key_pem=Path(args.ca_key).read_bytes(),
        passphrase=_resolve_passphrase(args, "ca", confirm=False),
    )


def _pki_request(args: argparse.Namespace) -> PkiRequest:
    command = args.pki_command
    if command == "full":
        return PkiRequest(
            "new-ca",
            ca=_ca_request(args, args.ca_cn, args.ca_validity_days),
            leaves=[
                _leaf_request(args, "server_", server_usage_for(args.domain), "server"),
                _leaf_request(args, "client_", client_usage_for(args.domain), "client"),
            ],
        )
    if command == "ca":
        return PkiRequest("ca-only", ca=_ca_request(args, args.cn, args.validity_days))
    if args.usage:
        usage = Usage(args.usage)
    elif command == "server":
        usage = server_usage_for(args.domain)
    else:
        usage = client_usage_for(args.domain)
    leaf = _leaf_request(args, "", usage, command)
    if args.self_signed:
        return PkiRequest("self-signed", leaves=[leaf])
    return PkiRequest("existing-ca", existing_ca=_existing_ca(args), leaves=[leaf])


def _cmd_pki(args: argparse.Namespace) -> int:
    result = generate_pki(_pki_request(args))
    _write_generated(Path(args.output), result.files, args.force)
    _print_certificates(result.certificates)
    _print_warnings(result.warnings)
    return 0


def _cmd_convert(args: argparse.Namespace) -> int:
    if args.basename and len(args.input) != 1:
        raise ConfiguratorError("--basename is only valid with exactly one input file")
    password = _resolve_secret(
        env=args.password_env,
        file=args.password_file,
        prompt=args.prompt_password,
        label="input password",
        confirm=False,
    )
    output_passphrase = _resolve_secret(
        env=args.output_passphrase_env,
        file=args.output_passphrase_file,
        prompt=args.output_passphrase_prompt,
        label="passphrase for the output key",
        confirm=True,
    )
    files: dict[str, GeneratedFile] = {}
    sources: dict[str, str] = {}
    warnings: list[str] = []
    for source in args.input:
        path = Path(source)
        result = convert_to_pem(
            path.read_bytes(),
            filename=path.name,
            password=password,
            output_passphrase=output_passphrase,
            basename=args.basename,
        )
        for item in result.files:
            if item.name in files:
                raise ConfiguratorError(
                    f"{source} and {sources[item.name]} would both be written to {item.name} (convert them separately)"
                )
            files[item.name] = item
            sources[item.name] = source
        print(f"{source}: detected {', '.join(result.detected)}")
        warnings.extend(f"{source}: {warning}" for warning in result.warnings)
    _write_generated(Path(args.output), list(files.values()), args.force)
    _print_warnings(warnings)
    return 0


def _cmd_schema(args: argparse.Namespace) -> int:
    version = ConfigVersion(args.config_version)
    schema = UserConfig.model_json_schema(by_alias=True)
    schema["$comment"] = f"Generated by {PROG} for config version {version.value}; informational only."
    text = json.dumps(schema, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text)
    else:
        print(text, end="")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    settings = ServerSettings(
        host=args.host,
        port=args.port,
        allowed_hosts=args.allowed_host or ["localhost", "127.0.0.1"],
        max_upload_bytes=args.max_upload_mb * _MIB,
    )
    if args.open_browser:
        url = f"http://{settings.host}:{settings.port}"
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)
    return 0


def _add_pki_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-o", "--output", required=True, help="directory receiving the generated .pem files")
    parser.add_argument("--force", action="store_true", help="overwrite existing files")
    parser.add_argument(
        "--key",
        choices=[spec.label for spec in ALLOWED_KEYS],
        default="rsa-4096",
        help="key type (default rsa-4096; OPC UA needs RSA; smaller RSA keys and EC keys produce a warning)",
    )
    parser.add_argument("--validity-days", type=int, help="validity in days (default depends on the usage)")
    parser.add_argument("--org", help="organisation (O)")
    parser.add_argument("--ou", help="organisational unit (OU)")
    parser.add_argument("--country", help="two-letter country code (C)")
    parser.add_argument("--state", help="state or province (ST)")
    parser.add_argument("--locality", help="locality (L)")


def _add_san_options(parser: argparse.ArgumentParser, prefix: str = "") -> None:
    flag = prefix.replace("_", "-")
    parser.add_argument(f"--{flag}dns", action="append", metavar="NAME", help="DNS name (repeatable)")
    parser.add_argument(f"--{flag}ip", action="append", metavar="ADDR", help="IP address (repeatable)")
    parser.add_argument(
        f"--{flag}uri",
        action="append",
        metavar="URI",
        help="URI (repeatable; for OPC UA the first is the application URI)",
    )
    parser.add_argument(f"--{flag}email", action="append", metavar="ADDR", help="e-mail address (repeatable)")


def _add_passphrase_options(parser: argparse.ArgumentParser, role: str, purpose: str) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(f"--{role}-passphrase-env", metavar="NAME", help=f"environment variable holding the {purpose}")
    group.add_argument(f"--{role}-passphrase-file", metavar="FILE", help=f"file holding the {purpose}")
    group.add_argument(f"--{role}-passphrase-prompt", action="store_true", help=f"prompt for the {purpose}")


def _add_pki_parsers(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p_pki = sub.add_parser("pki", help="generate a CA and server/client/OPC UA certificates as PEM files")
    pki_sub = p_pki.add_subparsers(dest="pki_command", required=True)
    new_key_help = "passphrase protecting the new {} key"

    p_full = pki_sub.add_parser("full", help="new CA plus one server and one client certificate for a domain")
    _add_pki_common(p_full)
    p_full.add_argument("--domain", choices=_DOMAINS, required=True)
    p_full.add_argument("--ca-cn", help="CA common name (default: '<org> Root CA')")
    p_full.add_argument("--ca-validity-days", type=int, help="CA validity in days (default 3650)")
    p_full.add_argument("--server-cn", required=True, help="server common name")
    _add_san_options(p_full, "server_")
    p_full.add_argument("--client-cn", required=True, help="client common name")
    _add_san_options(p_full, "client_")
    for role in ("ca", "server", "client"):
        _add_passphrase_options(p_full, role, new_key_help.format(role))
    p_full.set_defaults(func=_cmd_pki)

    p_ca = pki_sub.add_parser("ca", help="only a new CA")
    _add_pki_common(p_ca)
    p_ca.add_argument("--cn", help="CA common name (default: '<org> Root CA')")
    _add_passphrase_options(p_ca, "ca", new_key_help.format("CA"))
    p_ca.set_defaults(func=_cmd_pki)

    for command, role_name in (("server", "server"), ("client", "client")):
        p_leaf = pki_sub.add_parser(command, help=f"only a {role_name} certificate (CA-signed or self-signed)")
        _add_pki_common(p_leaf)
        target = p_leaf.add_mutually_exclusive_group(required=True)
        target.add_argument("--domain", choices=_DOMAINS)
        target.add_argument("--usage", choices=[usage.value for usage in Usage if usage is not Usage.CA])
        p_leaf.add_argument("--cn", required=True, help="common name")
        p_leaf.add_argument("--basename", help=f"file name stem (default {command})")
        _add_san_options(p_leaf)
        issuer = p_leaf.add_mutually_exclusive_group(required=True)
        issuer.add_argument("--ca-cert", metavar="FILE", help="PEM certificate of the issuing CA (needs --ca-key)")
        issuer.add_argument("--self-signed", action="store_true", help="sign the certificate with its own key")
        p_leaf.add_argument("--ca-key", metavar="FILE", help="PEM private key of the issuing CA")
        _add_passphrase_options(p_leaf, command, new_key_help.format(command))
        _add_passphrase_options(p_leaf, "ca", "passphrase unlocking the CA key")
        p_leaf.set_defaults(func=_cmd_pki)


def _add_convert_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = sub.add_parser("convert", help="convert certificates and keys (DER, PKCS#7, PKCS#12, ...) to PEM")
    parser.add_argument("input", nargs="+", help="files to convert; each file is converted separately")
    parser.add_argument("-o", "--output", required=True, help="directory receiving the .pem files")
    password = parser.add_mutually_exclusive_group()
    password.add_argument("--password-env", metavar="NAME", help="environment variable with the input password")
    password.add_argument("--password-file", metavar="FILE", help="file with the input password")
    password.add_argument("--prompt-password", action="store_true", help="prompt for the input password")
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--output-passphrase-env", metavar="NAME", help="environment variable with the new key passphrase"
    )
    output.add_argument("--output-passphrase-file", metavar="FILE", help="file with the new key passphrase")
    output.add_argument("--output-passphrase-prompt", action="store_true", help="prompt for the new key passphrase")
    parser.add_argument("--basename", help="output file name stem (only with a single input)")
    parser.add_argument("--force", action="store_true", help="overwrite existing files")
    parser.set_defaults(func=_cmd_convert)


def build_parser() -> argparse.ArgumentParser:
    """Build the dg-configurator argument parser.

    Returns:
        The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        prog=PROG, description="Graphical editor, validator and packager for Nerve Data Gateway configurations."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="validate a config.json, directory, zip or .dgproj")
    p_validate.add_argument("path")
    p_validate.add_argument("--format", choices=["text", "json"], default="text")
    p_validate.set_defaults(func=_cmd_validate)

    p_pack = sub.add_parser("pack", help="package a config into a deployable zip, optionally signed")
    p_pack.add_argument("source")
    p_pack.add_argument("-o", "--output", required=True)
    p_pack.add_argument("--sign-key", help="PEM file with the RSA private key used to sign the package")
    p_pack.add_argument("--key-password-env", help="name of an environment variable holding the key password")
    p_pack.add_argument("--key-password-file", help="file holding the key password")
    p_pack.add_argument("--prompt-password", action="store_true", help="prompt for the key password")
    p_pack.add_argument("--force", action="store_true", help="overwrite an existing output file")
    p_pack.add_argument("--no-validate", action="store_true", help="pack even if the config is invalid")
    p_pack.set_defaults(func=_cmd_pack)

    p_verify = sub.add_parser("verify", help="verify a signed package's signature")
    p_verify.add_argument("package")
    p_verify.add_argument("--public-key", required=True, help="path to a PEM file, or the base64 DER value directly")
    p_verify.set_defaults(func=_cmd_verify)

    p_keygen = sub.add_parser("keygen", help="generate an RSA signing key pair")
    p_keygen.add_argument("-o", "--output", required=True, help="directory receiving private.pem and the public keys")
    p_keygen.add_argument("--bits", type=int, default=4096)
    p_keygen.add_argument("--passphrase", action="store_true", help="prompt for a private-key passphrase")
    p_keygen.add_argument("--passphrase-env", help="name of an environment variable holding the passphrase")
    p_keygen.add_argument("--force", action="store_true", help="overwrite existing key files")
    p_keygen.set_defaults(func=_cmd_keygen)

    _add_pki_parsers(sub)
    _add_convert_parser(sub)

    p_schema = sub.add_parser("schema", help="print the JSON Schema generated from the Pydantic model")
    p_schema.add_argument("--config-version", choices=[v.value for v in ConfigVersion], default="1.1")
    p_schema.add_argument("-o", "--output")
    p_schema.set_defaults(func=_cmd_schema)

    p_serve = sub.add_parser("serve", help="start the web UI")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.add_argument("--allowed-host", action="append", help="accepted Host header (repeatable)")
    p_serve.add_argument("--max-upload-mb", type=int, default=50)
    p_serve.add_argument("--open-browser", action="store_true")
    p_serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface.

    Args:
        argv: Arguments without the program name. ``None`` means ``sys.argv[1:]``.

    Returns:
        The process exit code.
    """
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ConfiguratorError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
