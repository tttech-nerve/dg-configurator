# Changelog

All notable changes to `dg-configurator` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Web UI: graphical editor for endpoints, inputs, outputs and connections with live validation.
- CLI: `validate`, `pack`, `verify`, `keygen`, `schema` and `serve`.
- Web UI: certificate, key and public-key pickers only accept `.pem` files; configurations that reference CA, certificate or key files not named `*.pem` get the new `file_not_pem` warning.
- Web UI: *Keys & certificates…* dialog with a signing keypair generator (shows the `CONFIG_VERIFICATION_KEY` value), a PKI generator and a PEM converter.
- `pki` CLI command and web PKI generator: CA, server, client and OPC UA application certificates with usage profiles for OPC UA, MQTT, SQL and generic TLS, RSA 2048/3072/4096 (default 4096) and EC P-256/P-384 keys, optional passphrase per key, download as zip and "add to project files".
- `convert` CLI command and web converter: DER, PKCS#7, PKCS#12, traditional (PKCS#1/SEC1) and OpenSSH keys and certificates to PEM.
- API routes `POST /api/keypair`, `/api/pki/generate`, `/api/pki/archive`, `/api/pki/convert`; `GET /api/meta` returns the `pki` catalog.
- Support for Data Gateway config versions `1.0` and `1.1`.
- Plain and RSA-signed (PKCS#1 v1.5 + SHA-256) package creation, compatible with `openssl dgst`.
- `.dgproj` project files that keep the graph layout and supporting files.
- Docker image usable as web server and as CLI.
- MIT license.

### Notes

- `pydantic` is constrained to `>=2.12,<2.12.4`: later releases call a `typing` internal that is missing from Python 3.14.0 release candidates. Relax the bound once a final Python 3.14 is the baseline.
- The web API receives the configuration as a file part rather than a text form field, because text parts are limited to 1 MiB by the multipart parser.
