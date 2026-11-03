# dg-configurator documentation

`dg-configurator` is a graphical editor, validator and packager for Nerve Data Gateway configuration files. It validates against its own model of the public configuration schemas (versions `1.0` and `1.1`), builds plain or RSA-signed deployment packages and offers the same functionality as a web UI and as a command-line tool.

| Document | Description |
|---|---|
| [installation.md](installation.md) | Installing from source, development setup, Docker |
| [quickstart.md](quickstart.md) | A ten-minute walkthrough in the web UI |
| [web-ui-guide.md](web-ui-guide.md) | Every area of the web UI explained |
| [cli-reference.md](cli-reference.md) | All sub-commands, options, exit codes |
| [configuration-model.md](configuration-model.md) | Endpoints, inputs, outputs, connections, versions, diagnostics |
| [packages-and-signing.md](packages-and-signing.md) | Package layouts and the signing workflow |
| [certificates.md](certificates.md) | Generating CA, server, client and OPC UA certificates; converting to PEM |
| [project-files.md](project-files.md) | The `.dgproj` project file format |
| [docker.md](docker.md) | Building and running the container image |
| [security.md](security.md) | Threat model and hardening |
| [architecture.md](architecture.md) | Components and data flow |
| [development.md](development.md) | Make targets, tests, adding an endpoint type |
