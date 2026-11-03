# Nerve Data Gateway Configurator

[![Python 3.14+](https://img.shields.io/badge/python-3.14%2B-blue?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Data Gateway 1.2 – 1.7](https://img.shields.io/badge/Data%20Gateway-1.0.0%20%E2%80%93%201.1.0-0a7d5a)](https://docs.nerve.cloud/datagate/)
[![Config versions 1.0 | 1.1](https://img.shields.io/badge/config%20versions-1.0%20%7C%201.1-lightgrey)](docs/configuration-model.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

`dg-configurator` is a graphical editor, validator and packager for **Nerve Data Gateway** configuration files (`config.json`). Build the endpoint/input/output/connection graph in your browser, validate it continuously against the rules of the Data Gateway configuration schema, and export a deployable (optionally signed) package — or do the same from the command line.

> [!IMPORTANT]
> **This is not official software and not part of the Data Gateway.** `dg-configurator` is an example project. It shows how Data Gateway configuration workflows (editing, validating, packaging, signing, certificate handling) can be automated, and it offers an easier setup for your first steps with the Data Gateway. Use it as a reference for your own tooling or as a convenient starting point. It is provided as is, without warranty and without official support. Always check a configuration against the Data Gateway itself before using it in production.
>
> The authoritative description of the Data Gateway, its configuration and its behavior is the official documentation: **<https://docs.nerve.cloud/datagate/>**

## Compatibility

| | Supported |
|---|---|
| Python | 3.14 and newer |
| Data Gateway | 1.0.0 - 1.1.0 (checked against the configuration schema of release 1.1.0) |
| Data Gateway configuration versions | `1.0` and `1.1` |

Configuration version `1.1` requires Data Gateway 1.2 or newer. For the full list of options, see the [Data Gateway documentation](https://docs.nerve.cloud/datagate/).

## Features

- Graphical editor: endpoints as nodes, inputs and outputs as ports, connections as edges, with live validation.
- Imports `config.json`, plain zip packages, signed zip packages and `.dgproj` project files.
- Builds plain or signed (RSA PKCS#1 v1.5 + SHA-256) deployment packages.
- Command-line parity: `validate`, `pack`, `verify`, `keygen`, `pki`, `convert`, `schema`, `serve`.
- Generates signing key pairs, and CA / server / client / OPC UA application certificates (RSA and EC, optional passphrases) as `.pem` files; converts DER, PKCS#7, PKCS#12 and OpenSSH/traditional keys to PEM — in the web UI and on the command line. See [docs/certificates.md](docs/certificates.md).
- Certificate and key file pickers only accept `.pem` files; other names produce a `file_not_pem` warning.
- Supports config versions `1.0` and `1.1`.
- Ships as a Docker image that works as web server and as CLI.

## Quick start

```bash
git clone <url of this repository>
cd dg-configurator
pip install .

dg-configurator serve --open-browser
```

Or with Docker (see [docs/docker.md](docs/docker.md)):

```bash
make dockerbuild
make dockerrun        # http://127.0.0.1:8080
```

## CLI cheat sheet

| Command | Purpose |
|---|---|
| `dg-configurator validate <path> [--format json]` | Validate a `config.json`, a directory, a zip package or a `.dgproj` |
| `dg-configurator pack <source> -o out.zip [--sign-key private.pem]` | Build a plain or signed package |
| `dg-configurator verify <package> --public-key <pem-file-or-base64>` | Verify the signature of a signed package |
| `dg-configurator keygen -o <dir>` | Generate an RSA signing key pair |
| `dg-configurator pki full\|ca\|server\|client -o <dir> ...` | Generate a CA and certificates (OPC UA, MQTT, SQL, TLS) as PEM files |
| `dg-configurator convert <file>... -o <dir>` | Convert DER, PKCS#7, PKCS#12 and other formats to PEM |
| `dg-configurator schema [--config-version 1.1]` | Print the JSON Schema generated from the model |
| `dg-configurator serve [--port 8080]` | Start the web UI |

## Supported config versions

Versions `1.0` and `1.1` of the Data Gateway configuration are supported; `1.1` adds the `sql-client` endpoint, the `binary` MQTT message format, `variableSchema`, `timestampFormat` and the `passwordPolicy`. See [docs/configuration-model.md](docs/configuration-model.md) for the model used by this tool and the [Data Gateway documentation](https://docs.nerve.cloud/datagate/) for the official reference.

## Documentation

For the Data Gateway itself (deployment, configuration reference, behavior), see the official documentation at <https://docs.nerve.cloud/datagate/>. The documents below only cover this tool.

- [docs/index.md](docs/index.md) — overview and table of contents
- [docs/installation.md](docs/installation.md)
- [docs/quickstart.md](docs/quickstart.md)
- [docs/web-ui-guide.md](docs/web-ui-guide.md)
- [docs/cli-reference.md](docs/cli-reference.md)
- [docs/configuration-model.md](docs/configuration-model.md)
- [docs/packages-and-signing.md](docs/packages-and-signing.md)
- [docs/certificates.md](docs/certificates.md)
- [docs/project-files.md](docs/project-files.md)
- [docs/docker.md](docs/docker.md)
- [docs/security.md](docs/security.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/development.md](docs/development.md)

## Development

Requires Python 3.14 and [poetry](https://python-poetry.org/). All commands run from the repository root:

| Command | Purpose |
|---|---|
| `make setup` | Create `.venv` (use `PYTHON=<path to python3.14>` to pick an interpreter) |
| `make test` | Run tests with coverage → `reports/` |
| `make lint` | `ruff check` + `ruff format --check` → `reports/lint/` |
| `make check` | `lint` + `test` + `vendor-check` (must be green before committing) |
| `make serve ARGS="..."` | Run the web UI from the dev environment |
| `make run ARGS="..."` | Run the CLI from the dev environment |
| `make build` | Build wheel + sdist into `build/dist/` |

## Disclaimer

This project is an independent example. It is not an official product, is not part of the Nerve Data Gateway, and is not endorsed or supported as such. Product and company names are the property of their respective owners.

## License

MIT — see [LICENSE](LICENSE). Third-party components are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
