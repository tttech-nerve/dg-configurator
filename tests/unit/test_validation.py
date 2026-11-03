# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for the validation entry point."""

import json
from pathlib import Path

import pytest

from dg_configurator.model import SCHEMA_URLS, ConfigVersion
from dg_configurator.validation import ValidationReport, validate
from tests.conftest import FIXTURES_DIR, INVALID_CONFIGS, VALID_CONFIGS


def _pairs(report: ValidationReport) -> set[tuple[str, tuple]]:
    return {(d.code, d.path) for d in report.diagnostics}


@pytest.mark.parametrize("path", INVALID_CONFIGS, ids=lambda p: p.stem)
def test_invalid_fixtures_produce_the_expected_diagnostics(path: Path):
    expected = json.loads(path.with_suffix(".expected.json").read_text())

    report = validate(path.read_bytes())

    assert report.valid is False
    assert {(item["code"], tuple(item["path"])) for item in expected} <= _pairs(report)


@pytest.mark.parametrize("path", VALID_CONFIGS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_valid_fixtures_have_no_errors(path: Path):
    report = validate(path.read_bytes())

    assert report.valid is True
    assert report.version == path.parent.name.removeprefix("v")


def test_malformed_json_reports_position():
    report = validate((FIXTURES_DIR / "configs" / "invalid" / "malformed_json.json").read_bytes())

    assert [d.code for d in report.diagnostics] == ["json_invalid"]
    assert report.diagnostics[0].line is not None
    assert report.diagnostics[0].column is not None
    assert report.version == "1.0" or report.version is None


def test_text_input_is_accepted(minimal_v11: bytes):
    assert validate(minimal_v11.decode()).valid is True


def test_report_version_is_known_for_invalid_documents():
    report = validate(json.dumps({"version": "1.0", "endpoints": "nope", "connections": []}))

    assert report.valid is False
    assert report.version == "1.0"
    assert report.diagnostics[0].code == "schema_invalid"


def test_non_object_document_has_no_version():
    assert validate("[]").version is None


def _tls_config(**security: object) -> bytes:
    document = json.loads((FIXTURES_DIR / "configs" / "valid" / "v1.0" / "minimal.json").read_text())
    document["endpoints"][0].update(url="mqtts://h", security={"tlsEnabled": True} | security)
    return json.dumps(document).encode()


def test_missing_and_unreferenced_files_are_reported():
    raw = _tls_config(ca="ca.pem")

    missing = validate(raw, available_files=set())
    present = validate(raw, available_files={"ca.pem"})
    extra = validate(raw, available_files={"ca.pem", "stray.pem"})

    assert ("file_missing", ()) in _pairs(missing)
    assert missing.valid is False
    assert not [d for d in present.diagnostics if d.code == "file_missing"]
    assert [d.code for d in extra.diagnostics] == ["file_unreferenced"]
    assert extra.valid is True


def test_file_checks_are_skipped_without_available_files():
    assert validate(_tls_config(ca="ca.pem")).diagnostics == []


def test_tls_insecure_and_plaintext_export_are_warnings_only():
    document = json.loads((FIXTURES_DIR / "configs" / "valid" / "v1.1" / "sql-bootstrap.json").read_text())
    document["endpoints"][1]["security"] = {"tlsInsecure": True}

    report = validate(json.dumps(document))

    assert report.valid is True
    assert {d.code for d in report.diagnostics} == {"tls_insecure", "plaintext_export"}
    assert {d.severity for d in report.diagnostics} == {"warning"}


def test_mismatching_schema_url_is_a_warning():
    document = json.loads((FIXTURES_DIR / "configs" / "valid" / "v1.1" / "minimal.json").read_text())
    document["$schema"] = "https://example.invalid/schema.json"

    report = validate(json.dumps(document))

    assert report.valid is True
    assert [(d.code, d.path) for d in report.diagnostics] == [("schema_url_mismatch", ("$schema",))]


def test_matching_schema_url_is_silent():
    document = json.loads((FIXTURES_DIR / "configs" / "valid" / "v1.1" / "minimal.json").read_text())
    document["$schema"] = SCHEMA_URLS[ConfigVersion.V1_1]

    assert validate(json.dumps(document)).diagnostics == []


@pytest.mark.parametrize("role", ["ca", "certificate", "key"])
def test_non_pem_file_names_are_warned_about(role: str):
    report = validate(_tls_config(**{role: f"certs/{role}.crt"}))

    assert report.valid is True
    assert [(d.severity, d.code, d.path) for d in report.diagnostics] == [
        ("warning", "file_not_pem", ("endpoints", 0, "security", role))
    ]


@pytest.mark.parametrize("name", ["certs/ca.pem", "certs/CA.PEM"])
def test_pem_file_names_are_not_warned_about(name: str):
    assert validate(_tls_config(ca=name)).diagnostics == []
