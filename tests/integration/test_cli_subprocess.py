# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Integration tests running the CLI as a real subprocess."""

import subprocess  # noqa: S404 - tests run the CLI as a subprocess
import sys
from pathlib import Path

from tests.conftest import FIXTURES_DIR


def _run(*args: str | Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "dg_configurator", *map(str, args)], capture_output=True, check=False, timeout=60
    )


def test_valid_fixture_exits_with_zero():
    result = _run("validate", FIXTURES_DIR / "configs" / "valid" / "v1.1" / "minimal.json")

    assert result.returncode == 0
    assert result.stdout.strip().endswith(b"valid")


def test_invalid_fixture_exits_with_one():
    result = _run("validate", FIXTURES_DIR / "configs" / "invalid" / "orphan_port.json")

    assert result.returncode == 1
    assert b"orphan_port" in result.stderr


def test_usage_error_exits_with_two():
    assert _run("pack").returncode == 2


def test_pki_full_runs_end_to_end(tmp_path: Path):
    result = _run(
        *("pki", "full", "--domain", "tls", "-o", tmp_path, "--key", "ec-p256", "--server-cn", "srv"),
        *("--server-dns", "srv.local", "--client-cn", "cli"),
    )

    assert result.returncode == 0, result.stderr
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "ca-key.pem",
        "ca.pem",
        "client-key.pem",
        "client.pem",
        "server-key.pem",
        "server.pem",
    ]
