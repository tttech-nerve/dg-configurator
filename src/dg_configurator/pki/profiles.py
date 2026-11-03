# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Usage profiles: the X.509 extension sets that make a certificate usable for a given Data Gateway role."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from cryptography.x509 import ObjectIdentifier
from cryptography.x509.oid import ExtendedKeyUsageOID

from .keys import ALLOWED_KEYS, KeySpec

type Domain = Literal["opcua", "mqtt", "sql", "tls"]


class Usage(StrEnum):
    """What a certificate is issued for."""

    CA = "ca"
    OPCUA_APPLICATION = "opcua-application"
    MQTT_SERVER = "mqtt-server"
    MQTT_CLIENT = "mqtt-client"
    SQL_SERVER = "sql-server"
    SQL_CLIENT = "sql-client"
    TLS_SERVER = "tls-server"
    TLS_CLIENT = "tls-client"


@dataclass(frozen=True)
class KeyUsageFlags:
    """The nine KeyUsage bits, named like the keyword arguments of ``x509.KeyUsage``."""

    digital_signature: bool = False
    content_commitment: bool = False
    key_encipherment: bool = False
    data_encipherment: bool = False
    key_agreement: bool = False
    key_cert_sign: bool = False
    crl_sign: bool = False
    encipher_only: bool = False
    decipher_only: bool = False


@dataclass(frozen=True)
class Profile:
    """Everything the builder and the UIs need to know about one certificate usage."""

    usage: Usage
    label: str
    is_ca: bool
    key_usage: KeyUsageFlags
    rsa_key_usage_extra: tuple[str, ...]
    extended_key_usage: tuple[ObjectIdentifier, ...]
    requires_san: bool
    requires_application_uri: bool
    allowed_keys: tuple[KeySpec, ...]
    default_validity_days: int
    max_validity_days: int
    common_name_hint: str
    notes: tuple[str, ...] = ()


_SERVER_AUTH = ExtendedKeyUsageOID.SERVER_AUTH
_CLIENT_AUTH = ExtendedKeyUsageOID.CLIENT_AUTH
_LEAF_KEY_USAGE = KeyUsageFlags(digital_signature=True)
_RSA_KEY_ENCIPHERMENT = ("key_encipherment",)
_RSA_ONLY = tuple(spec for spec in ALLOWED_KEYS if spec.algorithm == "rsa")

_SERVER_NOTES = ("At least one DNS name or IP address is required; clients check the host name against it.",)
_CLIENT_NOTES = ("DNS names, IP addresses, URIs and e-mail addresses are optional.",)
_OPCUA_NOTES = (
    "The application URI must be a valid absolute URI and equal the URI the peer expects; it is placed first in the "
    "subject alternative name, followed by at least one DNS name or IP address.",
    "RSA only: every security policy of the gateway uses RSA. RSA 2048 is the safe minimum and works with every "
    "policy; the legacy policies Basic128Rsa15 and Basic256 are deprecated. Certificates are signed with SHA-256.",
    "One certificate serves both the client and the server role (extended key usage serverAuth and clientAuth).",
    "A self-signed application certificate additionally carries the keyCertSign usage.",
)


def _tls_profile(
    usage: Usage, label: str, *, server: bool, common_name_hint: str, extra_notes: tuple[str, ...] = ()
) -> Profile:
    return Profile(
        usage=usage,
        label=label,
        is_ca=False,
        key_usage=_LEAF_KEY_USAGE,
        rsa_key_usage_extra=_RSA_KEY_ENCIPHERMENT,
        extended_key_usage=(_SERVER_AUTH if server else _CLIENT_AUTH,),
        requires_san=server,
        requires_application_uri=False,
        allowed_keys=ALLOWED_KEYS,
        default_validity_days=825,
        max_validity_days=3650,
        common_name_hint=common_name_hint,
        notes=(*(_SERVER_NOTES if server else _CLIENT_NOTES), *extra_notes),
    )


PROFILES: dict[Usage, Profile] = {
    Usage.CA: Profile(
        usage=Usage.CA,
        label="Certificate authority",
        is_ca=True,
        key_usage=KeyUsageFlags(digital_signature=True, key_cert_sign=True, crl_sign=True),
        rsa_key_usage_extra=(),
        extended_key_usage=(),
        requires_san=False,
        requires_application_uri=False,
        allowed_keys=ALLOWED_KEYS,
        default_validity_days=3650,
        max_validity_days=7300,
        common_name_hint="<organisation> Root CA",
        notes=("The CA may only issue end-entity certificates (path length 0).",),
    ),
    Usage.TLS_SERVER: _tls_profile(
        Usage.TLS_SERVER, "TLS server", server=True, common_name_hint="primary host name of the server"
    ),
    Usage.TLS_CLIENT: _tls_profile(
        Usage.TLS_CLIENT, "TLS client", server=False, common_name_hint="client or user identity"
    ),
    Usage.MQTT_SERVER: _tls_profile(Usage.MQTT_SERVER, "MQTT broker", server=True, common_name_hint="broker host name"),
    Usage.MQTT_CLIENT: _tls_profile(
        Usage.MQTT_CLIENT,
        "MQTT client",
        server=False,
        common_name_hint="MQTT client id or user name",
        extra_notes=(
            "Brokers that use the certificate identity (for example Mosquitto use_identity_as_username) take the "
            "common name as the user name.",
        ),
    ),
    Usage.SQL_SERVER: _tls_profile(
        Usage.SQL_SERVER, "SQL database server", server=True, common_name_hint="database host name"
    ),
    Usage.SQL_CLIENT: _tls_profile(
        Usage.SQL_CLIENT,
        "SQL client",
        server=False,
        common_name_hint="database user",
        extra_notes=("PostgreSQL-style clientcert=verify-full maps the common name to the database user.",),
    ),
    Usage.OPCUA_APPLICATION: Profile(
        usage=Usage.OPCUA_APPLICATION,
        label="OPC UA application instance",
        is_ca=False,
        key_usage=KeyUsageFlags(
            digital_signature=True, content_commitment=True, key_encipherment=True, data_encipherment=True
        ),
        rsa_key_usage_extra=(),
        extended_key_usage=(_SERVER_AUTH, _CLIENT_AUTH),
        requires_san=True,
        requires_application_uri=True,
        allowed_keys=_RSA_ONLY,
        default_validity_days=1825,
        max_validity_days=3650,
        common_name_hint="application name",
        notes=_OPCUA_NOTES,
    ),
}

_DOMAIN_USAGES: dict[str, tuple[Usage, Usage]] = {
    "opcua": (Usage.OPCUA_APPLICATION, Usage.OPCUA_APPLICATION),
    "mqtt": (Usage.MQTT_SERVER, Usage.MQTT_CLIENT),
    "sql": (Usage.SQL_SERVER, Usage.SQL_CLIENT),
    "tls": (Usage.TLS_SERVER, Usage.TLS_CLIENT),
}


def get_profile(usage: Usage) -> Profile:
    """Return the profile of a usage."""
    return PROFILES[usage]


def server_usage_for(domain: Domain) -> Usage:
    """Return the server-side usage of a domain (``opcua`` has one usage for both roles)."""
    return _DOMAIN_USAGES[domain][0]


def client_usage_for(domain: Domain) -> Usage:
    """Return the client-side usage of a domain (``opcua`` has one usage for both roles)."""
    return _DOMAIN_USAGES[domain][1]
