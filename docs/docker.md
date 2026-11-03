# Docker

## Build and run

```bash
make dockerbuild                      # docker build -f docker/Dockerfile -t dg-configurator:<version> -t dg-configurator:latest .
make dockerrun                        # http://127.0.0.1:8080
```

`dockerrun` is equivalent to:

```bash
docker run --rm --read-only --tmpfs /tmp -p 127.0.0.1:8080:8080 dg-configurator:latest
```

- `--read-only --tmpfs /tmp` — the tool is stateless and never writes to its filesystem; a read-only root filesystem limits what a compromised process can do.
- `-p 127.0.0.1:8080:8080` — the UI has no authentication, so it is published on the loopback interface only.

The image runs as the unprivileged user `app` (uid 10001). Inside the container the server listens on `0.0.0.0:8080` and accepts the `Host` headers `localhost` and `127.0.0.1`; add more with `--allowed-host`.

## Health check

The image defines a `HEALTHCHECK` that requests `http://127.0.0.1:8080/healthz`, which answers `{"status":"ok"}`.

## Using the image as CLI

The `ENTRYPOINT` is `dg-configurator`, so any sub-command can be run directly. The working directory is `/work`; bind-mount your files there:

```bash
docker run --rm -v "$PWD:/work" dg-configurator:latest validate config.json
docker run --rm -v "$PWD:/work" dg-configurator:latest pack config.json -o config.zip
```

The image never contains a configuration, key or certificate; everything is passed in at `docker run` time.
