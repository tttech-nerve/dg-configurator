# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Deterministic auto-layout for configs that arrive without a saved graph layout."""

from .model import UserConfig

_COLUMN_WIDTH = 320
_ROW_BASE_HEIGHT = 160
_ROW_HEIGHT_PER_PORT = 28
_MARGIN_X = 40
_MARGIN_Y = 40


def auto_layout(config: UserConfig) -> dict[str, dict[str, dict[str, int]]]:
    """Place every endpoint on a grid.

    Endpoints with only inputs go to the left column, endpoints with only outputs to the right column and the
    remaining ones to the middle column. Within a column, rows are stacked in ascending endpoint-id order, each row
    tall enough for its ports.
    """
    columns: dict[int, list[tuple[int, int]]] = {0: [], 1: [], 2: []}
    for endpoint in sorted(config.endpoints, key=lambda e: e.id):
        has_inputs = bool(endpoint.inputs)
        has_outputs = bool(endpoint.outputs)
        if has_inputs and not has_outputs:
            column = 0
        elif has_outputs and not has_inputs:
            column = 2
        else:
            column = 1
        columns[column].append((endpoint.id, len(endpoint.inputs) + len(endpoint.outputs)))

    nodes: dict[str, dict[str, int]] = {}
    for column, endpoints in columns.items():
        y = _MARGIN_Y
        for endpoint_id, port_count in endpoints:
            nodes[str(endpoint_id)] = {"x": _MARGIN_X + column * _COLUMN_WIDTH, "y": y}
            y += _ROW_BASE_HEIGHT + port_count * _ROW_HEIGHT_PER_PORT + _MARGIN_Y
    return {"nodes": nodes}
