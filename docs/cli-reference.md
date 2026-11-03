# CLI reference

All commands are available as `dg-configurator <command>` and as `python -m dg_configurator <command>`.

Exit codes: `0` success, `1` the command ran but failed (invalid config, bad signature, existing output file, unreadable input), `2` usage error (unknown option, missing argument).

## validate

Validates a `config.json`, a directory containing `config.json` (and the supporting files it references), a plain/signed zip package or a `.dgproj` project.

| Option | Description |
|---|---|
| `path` | File or directory to validate |
| `--format {text,json}` | Output format (default `text`) |

Exit code `0` when the configuration is valid (warnings do not matter), otherwise `1`.

```bash
dg-configurator validate ./my-config --format json
```

### JSON output

```json
{
  "valid": false,
  "version": "1.1",
  "diagnostics": [
    {
      "severity": "error",
      "code": "orphan_port",
      "path": ["endpoints", 0, "inputs", 0],
      "message": "input 1 on endpoint 1 has no connection",
      "line": null,
      "column": null
    }
  ]
}
```

`severity` is `error` or `warning`; `path` addresses the offending element in the document; `line`/`column` are only set for JSON syntax errors. All codes are listed in [configuration-model.md](configuration-model.md).

## pack

Builds a deployable zip. The source is anything `validate` accepts. An invalid configuration is refused unless `--no-validate` is given.

| Option | Description |
|---|---|
| `source` | Directory, `config.json`, zip package or `.dgproj` |
| `-o, --output` | Output zip (required) |
| `--sign-key` | PEM file with the RSA private key; produces a signed package |
| `--key-password-env` | Name of an environment variable holding the key password |
| `--key-password-file` | File holding the key password |
| `--prompt-password` | Prompt for the key password |
| `--force` | Overwrite an existing output file |
| `--no-validate` | Pack even if the configuration is invalid |

```bash
dg-configurator pack ./my-config -o config.zip --sign-key keys/private.pem --key-password-env KEY_PASSWORD
```

## verify

Verifies the signature of a signed package. Plain packages and bad signatures exit with `1`.

| Option | Description |
|---|---|
| `package` | The zip package |
| `--public-key` | Path to a PEM file, or the base64 DER value itself (required) |

```bash
dg-configurator verify config.zip --public-key keys/public.pem
```

## keygen

Writes `private.pem` (mode `0600`), `public.pem` and `public.txt` (base64 DER, the format of the Data Gateway's `CONFIG_VERIFICATION_KEY` setting) and prints the public key.

| Option | Description |
|---|---|
| `-o, --output` | Target directory (required) |
| `--bits` | RSA key size, at least 2048 (default 4096) |
| `--passphrase` | Prompt for a passphrase protecting the private key |
| `--passphrase-env` | Name of an environment variable holding the passphrase |
| `--force` | Overwrite existing key files |

```bash
dg-configurator keygen -o keys
```

## pki

Generates a CA and server, client or OPC UA application certificates as PEM files. Keys are PKCS#8 PEM and are written with mode `0600`; the output directory is created with mode `0700`. Nothing is written when a target file already exists and `--force` is missing. The summary (file, subject, expiry, SHA-256 fingerprint) goes to stdout, warnings to stderr.

| Command | Meaning |
|---|---|
| `pki full` | New CA plus one server and one client certificate for a domain |
| `pki ca` | Only a new CA |
| `pki server` | Only a server certificate, signed by `--ca-cert`/`--ca-key` or self-signed |
| `pki client` | Only a client certificate, signed by `--ca-cert`/`--ca-key` or self-signed |

Options for all `pki` commands:

| Option | Description |
|---|---|
| `-o, --output` | Target directory (required) |
| `--force` | Overwrite existing files |
| `--key {rsa-2048,rsa-3072,rsa-4096,ec-p256,ec-p384}` | Key type (default `rsa-4096`). Smaller RSA keys and EC keys produce a warning; OPC UA needs RSA. In `full` it applies to the CA and both certificates |
| `--validity-days N` | Validity in days; the default and maximum depend on the usage (see [certificates.md](certificates.md)). In `pki ca` it is the CA validity |
| `--org`, `--ou`, `--country`, `--state`, `--locality` | Subject fields; in `full` they apply to all three certificates |

`pki full`:

| Option | Description |
|---|---|
| `--domain {opcua,mqtt,sql,tls}` | Selects the usage profiles (required) |
| `--ca-cn`, `--ca-validity-days` | CA common name (default `<org> Root CA`, or `Data Gateway Root CA`) and validity (default 3650) |
| `--server-cn` / `--client-cn` | Common names (required) |
| `--server-dns`, `--server-ip`, `--server-uri` | Server SAN entries, repeatable |
| `--client-dns`, `--client-ip`, `--client-uri`, `--client-email` | Client SAN entries, repeatable |

`pki ca` takes `--cn`. `pki server` and `pki client` take `--cn` (required), `--basename`, `--dns`, `--ip`, `--uri`, `--email` (all repeatable), exactly one of `--domain` or `--usage <usage>` (for example `mqtt-client`, see [certificates.md](certificates.md)), and exactly one issuer: `--ca-cert FILE` together with `--ca-key FILE`, or `--self-signed`.

For OPC UA the first `--uri` is the application URI (required), and at least one DNS name or IP address is required as well. Server certificates of the other domains need at least one DNS name or IP address.

Passphrases are never plain arguments. For each role (`ca`, `server`, `client`; `server`/`client` commands also accept `ca`) choose at most one of `--<role>-passphrase-env NAME`, `--<role>-passphrase-file FILE` and `--<role>-passphrase-prompt`. They **set** the passphrase of the key generated for that role (the prompt asks twice); in `pki server` and `pki client`, `--ca-passphrase-*` **unlocks** the supplied `--ca-key`.

Files written: `ca.pem`, `ca-key.pem`, `server.pem`, `server-key.pem`, `client.pem`, `client-key.pem` (only those the command creates). `--basename` changes the stem for `pki server` / `pki client`.

```bash
# MQTT: CA, broker and client certificates (the CA key is protected by a passphrase)
CA_PW=... dg-configurator pki full --domain mqtt -o pki --org Example --ca-cn "Example Root CA" \
  --server-cn broker --server-dns broker.example --client-cn gateway --ca-passphrase-env CA_PW

# OPC UA: CA plus application certificates for the gateway (client) and a test server
dg-configurator pki full --domain opcua -o pki --org Example \
  --server-cn "Test server" --server-dns opc.example --server-uri urn:opc.example:server \
  --client-cn "Data Gateway" --client-dns gw.example --client-uri urn:gw.example:DataGateway

# SQL: a client certificate from an existing CA
dg-configurator pki client --domain sql -o pki --cn dbuser --ca-cert ca.pem --ca-key ca-key.pem --ca-passphrase-prompt

# Generic TLS: a self-signed server certificate
dg-configurator pki server --domain tls -o pki --cn localhost --dns localhost --ip 127.0.0.1 --self-signed
```

## convert

Converts certificates, keys and keystores to PEM (see the format table in [certificates.md](certificates.md)). Every input is converted separately; all outputs are checked for name collisions and existing files before anything is written.

| Option | Description |
|---|---|
| `input...` | One or more files |
| `-o, --output` | Target directory (required) |
| `--password-env`, `--password-file`, `--prompt-password` | Password of the input (PKCS#12 or encrypted key); choose one |
| `--output-passphrase-env`, `--output-passphrase-file`, `--output-passphrase-prompt` | Encrypt the converted private key (the prompt asks twice); without it the key is written unencrypted and a warning is printed |
| `--basename NAME` | Output name stem (only with exactly one input) |
| `--force` | Overwrite existing files |

Output names: `<name>.pem` (certificate), `<name>-key.pem` (PKCS#8 private key, mode `0600`), `<name>-ca.pem` (CA chain, leaf to root) and `<name>-public.pem` (public key), where `<name>` is the input file name without extension.

```bash
dg-configurator convert client.p12 -o pem --password-env P12_PASSWORD
```

## schema

Prints the JSON Schema generated from the model.

| Option | Description |
|---|---|
| `--config-version {1.0,1.1}` | Version noted in the schema comment (default `1.1`) |
| `-o, --output` | Write to a file instead of stdout |

## serve

Starts the web UI.

| Option | Description |
|---|---|
| `--host` | Bind address (default `127.0.0.1`) |
| `--port` | Port (default `8080`) |
| `--allowed-host` | Accepted `Host` header, repeatable (default `localhost`, `127.0.0.1`) |
| `--max-upload-mb` | Maximum request body size in MiB (default 50) |
| `--open-browser` | Open the UI in the default browser |

```bash
dg-configurator serve --port 9090 --open-browser
```
