# Architecture

## Components

```text
                       ┌────────────────────── dg_configurator ──────────────────────┐
 Browser (static SPA)  │                                                             │
 ┌─────────────────┐   │  web/        FastAPI app (stateless JSON + multipart API)   │
 │ Drawflow canvas │─HTTP─▶ api.py ─┐                                                │
 │ schema forms    │   │            │                                                │
 │ diagnostics     │   │  cli.py ───┤  (argparse sub-commands)                       │
 └─────────────────┘   │            ▼                                                │
                       │  services (pure Python, no I/O framework):                  │
                       │   validation.py  ── model/ (Pydantic v2: endpoints, inputs, │
                       │                     outputs, connections, version gating,   │
                       │                     cross-object rules)                     │
                       │   files.py        linked supporting files of a config       │
                       │   packaging.py    plain zip / signed zip (tar + signature)  │
                       │   signing.py      RSA keygen, sign, verify, key formats     │
                       │   pki/            keys -> profiles -> builder -> generator  │
                       │                   (CA, server, client, OPC UA certs) and    │
                       │                   convert (DER/PKCS#7/PKCS#12/... to PEM)   │
                       │   project.py      .dgproj read/write                        │
                       │   layout.py       automatic placement of graph nodes        │
                       │   safe_archive.py zip/tar reading with safety limits        │
                       └─────────────────────────────────────────────────────────────┘
```

The core (`model/` and the service modules) knows nothing about HTTP or `argparse`. `cli.py` and `web/` are thin adapters calling the same functions, so the CLI and the UI behave identically. The core raises domain exceptions (`errors.ConfiguratorError` and subclasses); only the adapters turn them into exit codes and HTTP status codes.

## Package layout

```text
src/dg_configurator/
├── __init__.py  __main__.py  cli.py  errors.py
├── model/        version.py  base.py  limits.py  common.py  mqtt.py  opcua.py  sql.py
│                 connection.py  password_policy.py  config.py
├── validation.py  files.py  packaging.py  signing.py  project.py  layout.py  safe_archive.py
├── pki/          keys.py  profiles.py  builder.py  generator.py  convert.py
└── web/          app.py  api.py  dto.py  security.py  static/
```

## Data-flow contract

- Configuration objects are created only through `UserConfig.model_validate(...)` / `UserConfig.model_validate_json(...)`.
- `validation.validate()` is the only place that turns a `pydantic.ValidationError` into user-facing diagnostics. Cross-object rules raise coded errors (`[code] message`) from the model; `validation.py` maps them, and every other pydantic error, to a diagnostic code and a document path.
- `packaging.py` never imports `fastapi` or `argparse`; `model/` never imports `packaging`, `signing` or `web`.
- The web server is stateless: the browser holds the configuration, layout and supporting files and sends them with every request.

## PKI package

`pki/` is built in layers: `keys` (key specs, PKCS#8 serialisation, loading) → `profiles` (the extension set per usage) → `builder` (one X.509 certificate from a profile) → `generator` (CA, leaves, files, warnings). `convert` turns DER, PKCS#7, PKCS#12, traditional and OpenSSH keys into PEM and only depends on `keys` and the `GeneratedFile` type. The package raises `PkiError` / `ConversionError`; `cli.py` and `web/api.py` translate them to exit code 1 and HTTP 422.

Routes served from `web/api.py` besides the editor routes: `POST /api/keypair`, `POST /api/pki/generate`, `POST /api/pki/archive` and `POST /api/pki/convert`; `GET /api/meta` additionally returns the `pki` catalog (usages, key types, domains) that the UI renders its forms from.

## Validation pipeline

1. JSON parsing and field-level validation by the Pydantic model (`extra="forbid"`).
2. Cross-field rules inside the endpoint models (URL scheme vs. TLS, conditional required fields, QuestDB restrictions).
3. Cross-object rules in `UserConfig`: version gating, unique ids, connection references, encoding compatibility, unused ports.
4. File checks and warnings in `validation.validate_model`.
