# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for the PKI usage profiles."""

import dataclasses

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from dg_configurator.pki.keys import ALLOWED_KEYS, KeySpec
from dg_configurator.pki.profiles import (
    PROFILES,
    KeyUsageFlags,
    Usage,
    client_usage_for,
    get_profile,
    server_usage_for,
)

SERVER_AUTH = ExtendedKeyUsageOID.SERVER_AUTH
CLIENT_AUTH = ExtendedKeyUsageOID.CLIENT_AUTH


def _enabled(flags: KeyUsageFlags) -> set[str]:
    return {name for name, value in dataclasses.asdict(flags).items() if value}


def test_every_usage_has_a_profile():
    assert set(PROFILES) == set(Usage)
    assert len(Usage) == 8


def test_flags_match_the_x509_key_usage_arguments():
    assert x509.KeyUsage(**dataclasses.asdict(KeyUsageFlags(digital_signature=True))).digital_signature is True


def test_ca_profile():
    profile = get_profile(Usage.CA)

    assert profile.is_ca is True
    assert _enabled(profile.key_usage) == {"key_cert_sign", "crl_sign", "digital_signature"}
    assert profile.extended_key_usage == ()
    assert profile.requires_san is False
    assert profile.allowed_keys == ALLOWED_KEYS
    assert (profile.default_validity_days, profile.max_validity_days) == (3650, 7300)


@pytest.mark.parametrize("usage", [Usage.TLS_SERVER, Usage.MQTT_SERVER, Usage.SQL_SERVER])
def test_server_profiles(usage: Usage):
    profile = get_profile(usage)

    assert profile.is_ca is False
    assert _enabled(profile.key_usage) == {"digital_signature"}
    assert profile.rsa_key_usage_extra == ("key_encipherment",)
    assert profile.extended_key_usage == (SERVER_AUTH,)
    assert profile.requires_san is True
    assert profile.requires_application_uri is False
    assert profile.allowed_keys == ALLOWED_KEYS
    assert (profile.default_validity_days, profile.max_validity_days) == (825, 3650)


@pytest.mark.parametrize("usage", [Usage.TLS_CLIENT, Usage.MQTT_CLIENT, Usage.SQL_CLIENT])
def test_client_profiles(usage: Usage):
    profile = get_profile(usage)

    assert _enabled(profile.key_usage) == {"digital_signature"}
    assert profile.rsa_key_usage_extra == ("key_encipherment",)
    assert profile.extended_key_usage == (CLIENT_AUTH,)
    assert profile.requires_san is False
    assert profile.allowed_keys == ALLOWED_KEYS
    assert (profile.default_validity_days, profile.max_validity_days) == (825, 3650)


def test_opcua_profile():
    profile = get_profile(Usage.OPCUA_APPLICATION)

    assert _enabled(profile.key_usage) == {
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
    }
    assert set(profile.extended_key_usage) == {SERVER_AUTH, CLIENT_AUTH}
    assert profile.requires_san is True
    assert profile.requires_application_uri is True
    assert all(spec.algorithm == "rsa" for spec in profile.allowed_keys)
    assert KeySpec("ec", "P-256") not in profile.allowed_keys
    assert (profile.default_validity_days, profile.max_validity_days) == (1825, 3650)


def test_domain_mapping():
    assert (server_usage_for("opcua"), client_usage_for("opcua")) == (Usage.OPCUA_APPLICATION,) * 2
    assert (server_usage_for("mqtt"), client_usage_for("mqtt")) == (Usage.MQTT_SERVER, Usage.MQTT_CLIENT)
    assert (server_usage_for("sql"), client_usage_for("sql")) == (Usage.SQL_SERVER, Usage.SQL_CLIENT)
    assert (server_usage_for("tls"), client_usage_for("tls")) == (Usage.TLS_SERVER, Usage.TLS_CLIENT)
