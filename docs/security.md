# Security

`dg-configurator` handles signing keys and configuration files that may contain credentials. This is its threat model and the measures taken.

## Web server

- **Localhost by default.** `serve` binds `127.0.0.1`. The UI has no authentication; do not expose it to untrusted networks.
- **Host header check.** `TrustedHostMiddleware` only accepts the configured hosts (`localhost`, `127.0.0.1` by default; extend with `--allowed-host`). This blocks DNS-rebinding attacks from web pages visited in the same browser.
- **Body size limit.** Requests above `--max-upload-mb` (default 50 MiB) are answered with HTTP 413, using the declared length and the bytes actually received.
- **Browser hardening.** Every response carries a restrictive `Content-Security-Policy` (same-origin only, no framing), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
- **Stateless.** The server stores nothing; the browser holds the project and sends it with each request.

## Archives and files

- Imported zip and tar archives are read into memory only and never extracted to disk. Absolute paths, `..` segments, symlinks and special files, duplicate entries, too many entries, oversized content and extreme compression ratios are rejected.
- Supporting-file names in a configuration are validated: relative, no `..`, `.`, empty segments, backslashes or NUL characters. Loading files from a directory additionally refuses paths whose resolved location leaves that directory.

## Keys

- Private keys are used in memory for signing and never stored. Uploaded keys and passwords are not logged and never echoed in error messages.
- `keygen` writes `private.pem` with mode `0600`. RSA keys below 2048 bits are refused; keys below 4096 bits produce a warning.
- The keypair, PKI and converter endpoints (`/api/keypair`, `/api/pki/*`) generate or convert keys in memory and return them in the response; nothing is stored on the server. Passphrases and passwords are masked (`SecretStr`) and stripped from validation error responses, which never echo the request input. Responses carry `Cache-Control: no-store`; the web UI empties its result areas when the dialog closes.
- `pki` and `convert` on the command line write private keys with mode `0600` in a directory created with mode `0700`; passphrases are only accepted through environment variables, files or an interactive prompt, never as plain arguments.

## Container

The image runs as a non-root user and is meant to be started with a read-only root filesystem (see [docker.md](docker.md)).

## Reporting a vulnerability

Please report security issues through the issue tracker of the repository hosting this tool, without including real keys or configurations in the report.
