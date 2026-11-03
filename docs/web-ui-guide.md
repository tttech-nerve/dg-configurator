# Web UI guide

Start the UI with `dg-configurator serve` and open `http://127.0.0.1:8080`. The page has a toolbar at the top, a palette, the graph canvas and a properties panel in the middle, and a diagnostics panel at the bottom. The server keeps no state: your work lives in the browser page until you export it, so save a project or export the configuration before closing the tab.

No keyboard shortcuts are defined; every action is available through the toolbar, the palette and the panels. (Drawflow's built-in Delete key removes the selected node or connection, and the properties panel has explicit delete buttons.)

## Toolbar

| Control | Action |
|---|---|
| **New** | Start an empty configuration |
| **Import…** | Load a `config.json`, a plain or signed zip package or a `.dgproj` project |
| **Public key** | Optionally set a PEM public key (`public.pem`, not `public.txt`); signed packages imported afterwards are verified with it. Only `.pem` files can be chosen |
| **Save project** | Download a `.dgproj` file containing configuration, supporting files and layout (see [project-files.md](project-files.md)) |
| **Export config.json** | Download the configuration document only |
| **Package…** | Open the packaging dialog to download a deployable zip |
| **Keys & certificates…** | Open the dialog with the signing keypair generator, the PKI generator and the PEM converter (see [Keys & certificates](#keys--certificates)) |
| **Version selector** | Choose the configuration version (`1.0` or `1.1`) |

Changing the version selector never removes anything: elements that need a newer version are reported as `version_too_low` diagnostics, and the palette hides endpoint types that need a newer version.

## Palette

Lists the endpoint types the selected version supports. Adding one creates a node with sensible defaults. With an endpoint selected, the palette also offers the input and output types that endpoint can have.

## Canvas

Each endpoint is a node. Inputs and outputs appear as ports. Because an **input** of the Data Gateway is a *source* of data and an **output** is a *sink*, the connection arrows run from inputs to outputs:

```text
+---------------------+                    +----------------------+
| mqtt-in             |                    | mqtt-out             |
|                     |                    |                      |
|  Inputs (sources)   |   connection       |  Outputs (sinks)     |
|     [temp] o--------+--------------------+-->o [temp-out]       |
+---------------------+                    +----------------------+
```

Drag from an input port to an output port to create a connection. A connection whose encodings are incompatible is rejected immediately with a short message (for example a `binary` MQTT input to an MQTT publisher); the authoritative check is still the server-side validation shown in the diagnostics panel. Nodes can be moved freely; positions are stored in project files.

## Properties panel

Shows a form for the selected endpoint, input, output or connection, generated from the configuration model. Required fields are marked. Security sections offer file pickers for the CA certificate, client certificate and key; selected files are kept in the page and included in packages and projects. The pickers (like the public-key and signing-key pickers) only offer `.pem` files and reject other files with a message; convert other formats with the **Convert** tab of the Keys & certificates dialog.

## Diagnostics panel

Shows the result of the server-side validation, refreshed shortly after every change. Each entry shows the severity, the code, the message and the location. Selecting an entry highlights the affected node or connection.

## Importing and exporting

- **Import** accepts `config.json`, plain zip, signed zip and `.dgproj`. A signed package is reported as *unchecked* unless a public key is supplied, then as *valid* or *invalid*. If the imported configuration contains errors, they are shown immediately in the diagnostics panel.
- **Export config.json** produces just the document; **Save project** additionally keeps the layout and supporting files.
- **Package…** builds `config.zip`. Tick *Sign* and select a PEM private key (plus its password if it is encrypted) to produce a signed package. If the configuration is invalid or files are missing, the problems are shown instead of a download.

## Keys & certificates

The **Keys & certificates…** toolbar button opens a dialog with three tabs. Everything is generated or converted in memory on the server and returned to the page; nothing is stored. Closing the dialog empties all result areas and passphrase fields. Status and error messages appear inside the dialog.

- **Signing keypair** — generates an RSA key pair (2048, 3072 or 4096 bits, default 4096) with an optional passphrase. It shows the value for the Data Gateway's `CONFIG_VERIFICATION_KEY` setting (with a *Copy* button), warnings (key below 4096 bits, no passphrase) and download buttons for `private.pem`, `public.pem` and `public.txt`. To sign a package, download `private.pem` and select it in the *Package…* dialog.
- **PKI generator** — creates CA, server and client certificates as `.pem` files. Choose *Full PKI*, *CA only*, *Server certificate only* or *Client certificate only* and the domain (OPC UA, MQTT, SQL or generic TLS). For a single certificate choose the issuer: a new CA, an existing CA (CA certificate and key as `.pem`, plus its passphrase if the key is encrypted) or self-signed. Every certificate has its own form: subject fields, DNS names, IP addresses, URIs (for OPC UA the first line is the application URI) and e-mail addresses (comma or line separated), key type (RSA 2048/3072/4096 or EC P-256/P-384; EC is not offered for OPC UA), validity, an optional passphrase (entered twice) and the file name. The hints under each form come from the usage profiles described in [certificates.md](certificates.md). After *Generate* the result shows each certificate with its expiry and SHA-256 fingerprint, the warnings and three actions: a download per file, *Download all (zip)* and *Add to project files*. *Add to project files* stores every file as `certs/<name>.pem` in the project (asking before overwriting an existing file); enter the passphrase of an encrypted key in the endpoint's `keyPassword` field.
- **Convert to PEM** — converts a DER, PKCS#7, PKCS#12, traditional (PKCS#1/SEC1) or OpenSSH file to PEM. Enter the file's password for PKCS#12 files and encrypted keys, and optionally a passphrase for the converted private key and a file name. The result lists what was detected, then offers the same download and *Add to project files* actions as the PKI tab.
