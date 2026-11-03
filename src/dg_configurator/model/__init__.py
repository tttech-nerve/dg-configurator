# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Pydantic v2 domain model for the Nerve Data Gateway user configuration (config.json)."""

from .common import LinkedFile, MessageEncoding
from .config import EndpointUnion, UserConfig
from .connection import Connection, ConnectionDestination, ConnectionSource
from .mqtt import MqttEndpoint, MqttPublisherOutput, MqttSubscriberInput
from .opcua import OpcuaEndpoint, OpcuaInput
from .password_policy import PasswordPolicy
from .sql import SqlBinaryWriterOutput, SqlColumnarWriterOutput, SqlEndpoint
from .version import LATEST, SCHEMA_URLS, ConfigVersion

__all__ = [
    "LATEST",
    "SCHEMA_URLS",
    "ConfigVersion",
    "Connection",
    "ConnectionDestination",
    "ConnectionSource",
    "EndpointUnion",
    "LinkedFile",
    "MessageEncoding",
    "MqttEndpoint",
    "MqttPublisherOutput",
    "MqttSubscriberInput",
    "OpcuaEndpoint",
    "OpcuaInput",
    "PasswordPolicy",
    "SqlBinaryWriterOutput",
    "SqlColumnarWriterOutput",
    "SqlEndpoint",
    "UserConfig",
]
