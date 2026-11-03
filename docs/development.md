# Development

All commands run from `tools/configurator/`.

## Make targets

| Target | Purpose |
|---|---|
| `make setup` | Create `.venv` and install dependencies (`PYTHON=<python3.14>` selects the interpreter) |
| `make lint` | `ruff check` + `ruff format --check`; fails on findings |
| `make format` | Auto-format and apply safe fixes |
| `make test` | Run the tests with branch coverage (fails below 90 %) |
| `make check` | `lint` + `test` + `vendor-check` — the definition of done |
| `make build` | Build wheel and sdist into `build/dist/` |
| `make run ARGS="..."` | Run the CLI |
| `make serve ARGS="..."` | Run the web UI |
| `make vendor-check` | Verify the vendored Drawflow files against `SHA256SUMS` |
| `make dockerbuild` / `make dockerrun` | Build / run the container image |
| `make cleanup` | Remove `.venv`, reports and caches |

## Workflow

Work test-first: write a failing test, make it pass with the smallest change, refactor while green. Tests live in `tests/unit`, `tests/integration` (web API, schema conformance, OpenSSL interoperability, CLI subprocess) and `tests/functional` (end-to-end flows). Fixtures are in `tests/fixtures/`: the vendored public JSON Schemas, valid configurations per version and invalid configurations with `*.expected.json` files listing the diagnostics they must produce.

## Adding a new endpoint type

1. Add the Pydantic model in `model/<type>.py`; set `MIN_CONFIG_VERSION` if it is version-gated.
2. Add it to `EndpointUnion` in `model/config.py`.
3. Add valid and invalid fixtures and extend `tests/integration/test_schema_conformance.py`.
4. Add it to `_ENDPOINT_CATALOG` in `web/api.py`.
5. Add a palette colour in `web/static/styles.css` and defaults in the frontend palette code.
6. Update [configuration-model.md](configuration-model.md).

## Manual UI checklist

Run once after changing the frontend (`make serve`):

1. Start the UI: `make run ARGS="serve --open-browser"`.
2. Create one endpoint of each type (`mqtt-client`, `opcua-client`, `sql-client` — select config version `1.1` first so `sql-client` is in the palette); add at least one input and one output across them.
3. Connect two compatible ports — accepted. Attempt to connect an `mqtt-subscriber` input with `messageFormat: "binary"` to an `mqtt-publisher` output — rejected client-side.
4. Attach a CA/certificate/key file to an MQTT or OPC UA endpoint's security section; confirm the diagnostics panel shows no `file_missing` once attached, and shows it if removed.
5. Switch the version selector from `1.1` to `1.0` while a `sql-client` endpoint exists; confirm `version_too_low` diagnostics appear instead of the endpoint silently disappearing.
6. Save a project (`.dgproj`), reload the page, import the project and confirm configuration, files and layout are restored.
7. Import a plain `config.json` with no layout; confirm nodes are auto-laid-out without overlap.
8. Import a signed zip package both without and with a public key supplied; confirm the UI surfaces `unchecked` vs `valid`/`invalid` appropriately.
9. Package the current project both without signing and with a freshly generated key pair (via a separate `dg-configurator keygen` run); verify the signed package with `dg-configurator verify`.
