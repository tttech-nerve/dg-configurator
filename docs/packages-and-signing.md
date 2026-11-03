# Packages and signing

## Package layouts

**Plain package** — a zip with `config.json` and the supporting files at the root:

```text
config.zip
├── config.json
├── ca.pem
└── certs/client.pem
```

**Signed package** — a zip with a tar archive of the same content and a detached signature over the tar bytes. This is the layout produced by the Data Gateway's own `pack-and-sign` tooling:

```text
config.zip
├── config.tar        # config.json + supporting files
└── signature.sig     # RSA PKCS#1 v1.5 + SHA-256 signature of config.tar
```

Packages are built deterministically (sorted entries, fixed timestamps and ownership), so packing the same content twice yields identical bytes.

## Signing workflow

1. Generate a key pair: `dg-configurator keygen -o keys`, or use **Keys & certificates… → Signing keypair** in the web UI. The dialog shows the `CONFIG_VERIFICATION_KEY` value with a copy button and offers `private.pem`, `public.pem` and `public.txt` for download.
2. Configure the Data Gateway with the public key: set `CONFIG_VERIFICATION_KEY` to the content of `keys/public.txt` (base64 DER, no PEM headers).
3. Pack and sign: `dg-configurator pack ./my-config -o config.zip --sign-key keys/private.pem`.
4. Verify locally: `dg-configurator verify config.zip --public-key keys/public.pem`.
5. Upload `config.zip` to the Data Gateway.

The signature is byte-compatible with `openssl dgst -sha256 -verify`, which is checked by `tests/integration/test_openssl_compat.py`.

## Key handling best practices

- Never commit `private.pem`. `keygen` writes it with mode `0600`.
- In automation prefer `--key-password-env` or `--key-password-file` over interactive prompts.
- Use 4096-bit keys (the default); keys below 4096 bits trigger the `weak_signing_key` warning, keys below 2048 bits are refused.
- Rotate keys by running `keygen` again and updating `CONFIG_VERIFICATION_KEY`.
