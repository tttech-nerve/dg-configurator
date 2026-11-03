# Installation

## From source

Requires Python 3.14 or newer.

```bash
git clone <repository-url>
cd <repository>/tools/configurator   # or the repository root of the exported tool
pip install .
dg-configurator --version
```

From a checkout of the monorepo you can also run `pip install ./tools/configurator` from the repository root.

## Development setup

Requires `python3.14` and [poetry](https://python-poetry.org/).

```bash
cd tools/configurator
make setup PYTHON=$(which python3.14)
make check
```

`make setup` creates an in-project virtual environment (`.venv/`). See [development.md](development.md) for all Make targets.

## Docker

```bash
make dockerbuild
make dockerrun
```

`dockerrun` starts the image with a read-only root filesystem (`--read-only --tmpfs /tmp`) and publishes the port on `127.0.0.1` only. Details are in [docker.md](docker.md).
