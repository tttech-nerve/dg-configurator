# Configuration model

A Data Gateway configuration (`config.json`) is a graph: **endpoints** are the external systems the gateway talks to, each endpoint has **inputs** (data sources) and/or **outputs** (data sinks), and **connections** wire one input to one output. `dg-configurator` validates the document with its own model written from the public JSON Schemas (`config-schema-v1.0.json`, `config-schema-v1.1.json`), which are vendored as conformance-test fixtures in `tests/fixtures/schemas/`. Unknown fields are rejected.

## Document

| Field | Required | Notes |
|---|---|---|
| `$schema` | no | Informational; a URL not matching `version` yields a warning |
| `version` | yes | `"1.0"` or `"1.1"` |
| `endpoints` | yes | At most 100 |
| `connections` | yes | |
| `passwordPolicy` | no | `1.1` only |

Every endpoint, input, output and connection has an `id` (0 – 4294967295), a `name` and an optional `description`. Endpoint ids are unique within the document, input and output ids unique within their endpoint, connection ids unique within the document. An endpoint has at most 1000 inputs and 1000 outputs.

## Endpoint types

| `endpointType` | Inputs | Outputs | Since |
|---|---|---|---|
| `mqtt-client` | `mqtt-subscriber` | `mqtt-publisher` | 1.0 |
| `opcua-client` | `opcua-polling`, `opcua-subscriber` | none | 1.0 |
| `sql-client` | none | `sql-columnar-writer`, `sql-binary-writer` | 1.1 |

Highlights of the cross-field rules:

- MQTT: `mqtt://` requires `security.tlsEnabled = false`, `mqtts://` requires `true`.
- OPC UA: `opcua-polling` requires `pollingIntervalMS`; `opcua-subscriber` requires `samplingIntervalMS` and `publishingIntervalMS`.
- SQL: `bootstrap` needs `exportPublicKey` unless `allowPlaintextExport` is `true`.
- SQL with `dbType: "questdb"`: no `bootstrap`, no `sql-binary-writer`, no `nestedVariableDelimiter: "."`.
- Supporting files (`ca`, `certificate`, `key` in the `security` sections) are relative paths without `..`, `.` or empty segments.

## Differences between 1.0 and 1.1

Version `1.1` adds: the `sql-client` endpoint with its outputs, the root `passwordPolicy`, the `binary` message format for MQTT subscribers, `variableSchema` on MQTT subscribers and `timestampFormat` on MQTT publishers. Using any of these in a `1.0` document is reported as `version_too_low`.

## Encoding compatibility

A connection is valid only if the destination output accepts the encoding produced by the source input.

| Input produces | Accepted by |
|---|---|
| `mqtt-subscriber` with `messageFormat` `json` or `protobuf` | `mqtt-publisher` (any `messageFormat`), `sql-columnar-writer` |
| `mqtt-subscriber` with `messageFormat` `binary` | `sql-binary-writer` only |
| `opcua-polling` / `opcua-subscriber` (always `protobuf`) | `mqtt-publisher` (any `messageFormat`), `sql-columnar-writer` |

Non-binary inputs (`json`, `protobuf`) can feed any non-binary output; binary inputs can only feed binary outputs. An `mqtt-publisher` converts structured data to its own `messageFormat`; it can never publish `binary`. Every input and every output must be used by at least one connection; an input may feed several outputs.

## Diagnostics

| Code | Severity | Meaning |
|---|---|---|
| `json_invalid` | error | The input is not syntactically valid JSON |
| `schema_invalid` | error | Missing or unknown field, wrong type, value out of range or not allowed |
| `cross_field_invalid` | error | A rule combining several fields of one object is violated |
| `duplicate_id` | error | An `id` is not unique within its scope |
| `dangling_reference` | error | A connection refers to a non-existent endpoint, input or output |
| `encoding_mismatch` | error | The destination output does not accept the source input's encoding |
| `orphan_port` | error | An input or output is not used by any connection |
| `version_too_low` | error | An element requires a newer `version` than declared (1.1 features in 1.0) |
| `questdb_incompatible` | error | A feature unsupported for `dbType: "questdb"` is used (1.1) |
| `file_missing` | error | A referenced supporting file is not available |
| `file_unreferenced` | warning | A supplied file is not referenced by the configuration |
| `tls_insecure` | warning | `tlsInsecure: true` disables certificate verification |
| `file_not_pem` | warning | A CA, certificate or key file name does not end with `.pem` |
| `plaintext_export` | warning | `bootstrap.allowPlaintextExport: true` (1.1) |
| `schema_url_mismatch` | warning | `$schema` does not match the declared `version` |
| `weak_signing_key` | warning | A signing key below 4096 bits was used (reported when packing) |

A configuration is valid when it has no error diagnostics; warnings never block packaging.
