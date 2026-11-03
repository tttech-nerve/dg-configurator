# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Connection model — wires one input to one output."""

from .base import StrictModel, Uint32


class ConnectionSource(StrictModel):
    """Endpoint + input id pair identifying a connection's source."""

    endpoint: Uint32
    input: Uint32


class ConnectionDestination(StrictModel):
    """Endpoint + output id pair identifying a connection's destination."""

    endpoint: Uint32
    output: Uint32


class Connection(StrictModel):
    """Wires exactly one input on one endpoint to exactly one output on another."""

    id: Uint32
    name: str
    description: str = ""
    source: ConnectionSource
    destination: ConnectionDestination
