# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for the automatic graph layout."""

from dg_configurator.layout import _COLUMN_WIDTH, _MARGIN_X, _ROW_BASE_HEIGHT, auto_layout
from dg_configurator.model import MqttEndpoint, UserConfig


def _mqtt(endpoint_id: int, inputs: int = 0, outputs: int = 0) -> MqttEndpoint:
    return MqttEndpoint.model_validate(
        {
            "id": endpoint_id,
            "name": f"e{endpoint_id}",
            "endpointType": "mqtt-client",
            "url": "mqtt://h",
            "inputs": [
                {
                    "id": n,
                    "name": "i",
                    "inputType": "mqtt-subscriber",
                    "messageFormat": "json",
                    "topics": [{"topic": "t"}],
                }
                for n in range(inputs)
            ],
            "outputs": [
                {"id": n, "name": "o", "outputType": "mqtt-publisher", "messageFormat": "json", "topic": "t"}
                for n in range(outputs)
            ],
        }
    )


def _config(*endpoints: MqttEndpoint) -> UserConfig:
    # the layout does not depend on connections, so skip the cross-object validation
    return UserConfig.model_construct(version="1.1", endpoints=list(endpoints), connections=[])


def test_endpoints_are_placed_in_columns_by_port_direction():
    layout = auto_layout(_config(_mqtt(1, inputs=1), _mqtt(2, outputs=1), _mqtt(3, inputs=1, outputs=1)))

    xs = {endpoint_id: node["x"] for endpoint_id, node in layout["nodes"].items()}
    assert xs == {"1": _MARGIN_X, "3": _MARGIN_X + _COLUMN_WIDTH, "2": _MARGIN_X + 2 * _COLUMN_WIDTH}
    assert list(xs.values()).count(40) == 1


def test_endpoints_without_ports_go_to_the_middle_column():
    layout = auto_layout(_config(_mqtt(1)))

    assert layout["nodes"]["1"]["x"] == _MARGIN_X + _COLUMN_WIDTH


def test_layout_is_deterministic_and_independent_of_endpoint_order():
    endpoints = [_mqtt(1, inputs=2), _mqtt(2, inputs=1), _mqtt(3, outputs=1)]

    assert auto_layout(_config(*endpoints)) == auto_layout(_config(*reversed(endpoints)))


def test_endpoints_in_the_same_column_do_not_overlap():
    layout = auto_layout(_config(_mqtt(1, inputs=1), _mqtt(2, inputs=3)))

    first, second = layout["nodes"]["1"]["y"], layout["nodes"]["2"]["y"]
    assert second - first >= _ROW_BASE_HEIGHT
    assert second > first
