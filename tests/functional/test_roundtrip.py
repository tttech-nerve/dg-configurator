# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Functional test of the full lifecycle: validate, package, sign, verify, re-import, re-pack."""

import json

from dg_configurator import packaging, project, signing
from dg_configurator.layout import auto_layout
from dg_configurator.model import UserConfig
from dg_configurator.validation import validate
from tests.conftest import FIXTURES_DIR


def _tls_config() -> bytes:
    document = json.loads((FIXTURES_DIR / "configs" / "valid" / "v1.1" / "minimal.json").read_text())
    document["endpoints"][0].update(
        url="mqtts://broker.local:8883",
        security={"tlsEnabled": True, "ca": "ca.pem", "certificate": "certs/client.pem", "key": "certs/client.key"},
    )
    return json.dumps(document).encode()


FILES = {"ca.pem": b"ca", "certs/client.pem": b"cert", "certs/client.key": b"key"}


def test_signed_package_round_trip_is_deterministic(keypair_a: signing.KeyPair):
    private_key = signing.load_private_key(keypair_a.private_pem)
    public_key = signing.load_public_key(keypair_a.public_b64der)
    config = UserConfig.model_validate_json(_tls_config())
    assert validate(_tls_config(), available_files=set(FILES)).valid is True

    config_json = packaging.dump_config(config)
    first = packaging.build_signed_zip(config_json, FILES, private_key)
    loaded = packaging.read_package(first, public_key)

    assert loaded.signature_status == "valid"
    assert loaded.files == FILES
    assert UserConfig.model_validate_json(loaded.config_json).model_dump() == config.model_dump()
    assert validate(loaded.config_json, available_files=set(loaded.files)).valid is True

    repacked = packaging.build_signed_zip(loaded.config_json, loaded.files, private_key)
    assert repacked == first


def test_project_round_trip_keeps_config_files_and_layout():
    config = UserConfig.model_validate_json(_tls_config())
    layout = auto_layout(config)

    archive = project.write_project(packaging.dump_config(config), FILES, layout)
    loaded = packaging.read_package(archive)

    assert loaded.kind == "project"
    assert loaded.layout == layout
    assert loaded.files == FILES
    assert project.write_project(loaded.config_json, loaded.files, loaded.layout or {}) == archive


def test_plain_package_survives_export_and_import():
    config = UserConfig.model_validate_json(_tls_config())
    plain = packaging.build_plain_zip(packaging.dump_config(config), FILES)

    loaded = packaging.read_package(plain)

    assert loaded.kind == "plain-zip"
    assert packaging.build_plain_zip(loaded.config_json, loaded.files) == plain
