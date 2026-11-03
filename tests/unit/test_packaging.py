# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for config package building and reading."""

import json
import tarfile
import zipfile
from io import BytesIO

import pytest

from dg_configurator import packaging, signing
from dg_configurator.errors import InvalidPackageError
from dg_configurator.model import UserConfig
from dg_configurator.safe_archive import read_tar, read_zip
from tests.conftest import FIXTURES_DIR

CONFIG = b'{"version": "1.0"}'
FILES = {"ca.pem": b"ca", "certs/key.pem": b"key"}


def _private(pair: signing.KeyPair):
    return signing.load_private_key(pair.private_pem)


def _public(pair: signing.KeyPair):
    return signing.load_public_key(pair.public_pem)


def test_builders_are_deterministic(keypair_a: signing.KeyPair):
    key = _private(keypair_a)

    assert packaging.build_plain_zip(CONFIG, FILES) == packaging.build_plain_zip(CONFIG, dict(reversed(FILES.items())))
    assert packaging.build_config_tar(CONFIG, FILES) == packaging.build_config_tar(
        CONFIG, dict(reversed(FILES.items()))
    )
    assert packaging.build_signed_zip(CONFIG, FILES, key) == packaging.build_signed_zip(CONFIG, FILES, key)


def test_plain_zip_round_trips():
    loaded = packaging.read_package(packaging.build_plain_zip(CONFIG, FILES))

    assert (loaded.kind, loaded.config_json, loaded.files) == ("plain-zip", CONFIG, FILES)
    assert loaded.signature_status is None


def test_signed_zip_contains_tar_and_signature_in_supervisor_layout(keypair_a: signing.KeyPair):
    data = packaging.build_signed_zip(CONFIG, FILES, _private(keypair_a))

    entries = read_zip(data)

    assert sorted(entries) == ["config.tar", "signature.sig"]
    assert read_tar(entries["config.tar"]) == {"config.json": CONFIG, **FILES}


def test_signed_zip_signature_status(keypair_a: signing.KeyPair, keypair_b: signing.KeyPair):
    data = packaging.build_signed_zip(CONFIG, FILES, _private(keypair_a))

    valid = packaging.read_package(data, _public(keypair_a))
    invalid = packaging.read_package(data, _public(keypair_b))
    unchecked = packaging.read_package(data)

    assert (valid.signature_status, invalid.signature_status, unchecked.signature_status) == (
        "valid",
        "invalid",
        "unchecked",
    )
    assert (valid.kind, valid.config_json, valid.files) == ("signed-zip", CONFIG, FILES)


def test_bare_json_is_accepted():
    loaded = packaging.read_package(CONFIG)

    assert (loaded.kind, loaded.config_json, loaded.files) == ("json", CONFIG, {})


def test_garbage_is_rejected():
    with pytest.raises(InvalidPackageError, match="neither a zip archive nor valid JSON"):
        packaging.read_package(b"not json, not zip")


def test_zip_without_known_layout_is_rejected():
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "hello")

    with pytest.raises(InvalidPackageError, match="recognised"):
        packaging.read_package(buffer.getvalue())


def test_signed_zip_whose_tar_lacks_config_json_is_rejected(keypair_a: signing.KeyPair):
    tar = packaging.build_config_tar(CONFIG, FILES)
    broken = BytesIO()
    with tarfile.open(fileobj=broken, mode="w") as archive:
        info = tarfile.TarInfo("other.txt")
        archive.addfile(info)
    zipped = packaging.deterministic_zip({"config.tar": broken.getvalue(), "signature.sig": b"sig"})

    assert tar
    with pytest.raises(InvalidPackageError, match="config.json"):
        packaging.read_package(zipped)


def test_tar_with_dot_prefixed_names_as_created_by_tar_dash_c_is_read(keypair_a: signing.KeyPair):
    tar_buffer = BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        directory = tarfile.TarInfo("./")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for name, data in {"./config.json": CONFIG, "./ca.pem": b"ca"}.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, BytesIO(data))
    tar_bytes = tar_buffer.getvalue()
    signature = signing.sign(tar_bytes, _private(keypair_a))
    zipped = packaging.deterministic_zip({"config.tar": tar_bytes, "signature.sig": signature})

    loaded = packaging.read_package(zipped, _public(keypair_a))

    assert loaded.config_json == CONFIG
    assert loaded.files == {"ca.pem": b"ca"}
    assert loaded.signature_status == "valid"


def test_dump_config_restores_schema_url_and_round_trips():
    raw = (FIXTURES_DIR / "configs" / "valid" / "v1.1" / "minimal.json").read_bytes()
    config = UserConfig.model_validate_json(raw)

    dumped = packaging.dump_config(config)
    document = json.loads(dumped)

    assert next(iter(document)) == "$schema"
    assert document["$schema"].endswith("config-schema-v1.1.json")
    assert "passwordPolicy" not in document
    assert UserConfig.model_validate_json(dumped).model_dump() == config.model_dump()
    assert packaging.dump_config(UserConfig.model_validate_json(dumped)) == dumped


def test_dump_config_keeps_an_explicit_password_policy():
    raw = (FIXTURES_DIR / "configs" / "valid" / "v1.1" / "password-policy.json").read_bytes()

    document = json.loads(packaging.dump_config(UserConfig.model_validate_json(raw)))

    assert document["passwordPolicy"]["minLength"] == 20


def test_dumped_v10_config_is_still_a_valid_v10_config():
    raw = (FIXTURES_DIR / "configs" / "valid" / "v1.0" / "minimal.json").read_bytes()

    dumped = packaging.dump_config(UserConfig.model_validate_json(raw))

    UserConfig.model_validate_json(dumped)
