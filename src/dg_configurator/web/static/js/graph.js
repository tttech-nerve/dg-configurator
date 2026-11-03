// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TTTech Industrial Automation AG

/**
 * Node-graph editor built on the vendored Drawflow library.
 *
 * Mapping: one Drawflow node per endpoint. A Data Gateway *input* is a data source, so it becomes a Drawflow
 * OUTPUT port (right side); a Data Gateway *output* is a sink and becomes a Drawflow INPUT port (left side).
 * Drawflow port classes are positional ("output_1", "input_2", ...), so port N is the N-th input/output of
 * the endpoint in state.config.
 */

import Drawflow from "../vendor/drawflow/drawflow.js";
import { el, showMessage } from "./dom.js";
import * as state from "./state.js";

const NODE_WIDTH = 300;
const FAMILIES = { "mqtt-client": "mqtt", "opcua-client": "opcua", "sql-client": "sql" };

let editor = null;
let container = null;
let rendering = false;
let diagnostics = [];
const nodeOfEndpoint = new Map(); // endpoint id -> Drawflow node id (string)
const endpointOfNode = new Map(); // Drawflow node id (string) -> endpoint id

/** Format a data source emits, or undefined when unknown. OPC UA inputs always produce protobuf. */
function producedFormat(input) {
  if (input.inputType === "mqtt-subscriber") return input.messageFormat;
  if (typeof input.inputType === "string" && input.inputType.startsWith("opcua-")) return "protobuf";
  return undefined;
}

/** Formats a sink accepts, or undefined when unknown. */
function acceptedFormats(output) {
  switch (output.outputType) {
    case "sql-binary-writer":
      return ["binary"];
    case "sql-columnar-writer":
      return ["json", "protobuf"];
    case "mqtt-publisher":
      return ["json", "protobuf"];
    default:
      return undefined;
  }
}

/** Explain why `input` cannot feed `output`, or return null when they are compatible (or unknown). */
export function incompatibility(input, output) {
  const produced = producedFormat(input);
  const accepted = acceptedFormats(output);
  if (!produced || !accepted || accepted.includes(produced)) return null;
  return `Incompatible: "${output.name}" (${output.outputType}) accepts ${accepted.join(" or ")}, but "${input.name}" produces ${produced}.`;
}

function portIndex(portClass) {
  return Number.parseInt(portClass.split("_")[1], 10) - 1;
}

/** Drawflow ids/classes for a config connection, or null when it references a missing endpoint or port. */
function connectionPorts(connection) {
  const source = state.findEndpoint(connection.source?.endpoint);
  const destination = state.findEndpoint(connection.destination?.endpoint);
  const outIndex = source?.inputs?.findIndex((input) => input.id === connection.source.input) ?? -1;
  const inIndex = destination?.outputs?.findIndex((output) => output.id === connection.destination.output) ?? -1;
  if (outIndex < 0 || inIndex < 0) return null;
  return {
    outNode: nodeOfEndpoint.get(source.id),
    inNode: nodeOfEndpoint.get(destination.id),
    outClass: `output_${outIndex + 1}`,
    inClass: `input_${inIndex + 1}`,
  };
}

function edgeElement(connection) {
  const ports = connectionPorts(connection);
  if (!ports?.outNode || !ports.inNode) return null;
  const selector = `.connection.node_out_node-${ports.outNode}.node_in_node-${ports.inNode}.${ports.outClass}.${ports.inClass}`;
  return container.querySelector(selector);
}

export function initGraph(element) {
  container = element;
  editor = new Drawflow(element);
  editor.reroute = false;
  editor.start();

  editor.on("connectionCreated", onConnectionCreated);
  editor.on("connectionRemoved", onConnectionRemoved);
  editor.on("connectionSelected", onConnectionSelected);
  editor.on("connectionUnselected", () => state.select(null));
  editor.on("nodeMoved", onNodeMoved);
  editor.on("nodeRemoved", onNodeRemoved);
  editor.on("nodeSelected", (id) => state.select({ kind: "endpoint", endpointId: endpointOfNode.get(String(id)) }));
  editor.on("nodeUnselected", () => state.select(null));

  state.subscribe((current, kind, info) => {
    if (kind === "structure" && !info.fromGraph) render();
    else if (kind === "config") refreshLabels();
    else if (kind === "selection") syncSelection();
  });
  render();
}

function linkFromEvent({ output_id: outputId, input_id: inputId, output_class: outClass, input_class: inClass }) {
  const sourceEndpoint = state.findEndpoint(endpointOfNode.get(String(outputId)));
  const destinationEndpoint = state.findEndpoint(endpointOfNode.get(String(inputId)));
  const input = sourceEndpoint?.inputs?.[portIndex(outClass)];
  const output = destinationEndpoint?.outputs?.[portIndex(inClass)];
  if (!input || !output) return null;
  return { sourceEndpoint, destinationEndpoint, input, output };
}

function findConnectionFor(link) {
  return state.getState().config.connections.find(
    (c) =>
      c.source?.endpoint === link.sourceEndpoint.id &&
      c.source?.input === link.input.id &&
      c.destination?.endpoint === link.destinationEndpoint.id &&
      c.destination?.output === link.output.id,
  );
}

function onConnectionCreated(event) {
  if (rendering) return;
  const link = linkFromEvent(event);
  const problem = link ? incompatibility(link.input, link.output) : "Cannot connect: unknown port.";
  if (problem || !link) {
    editor.removeSingleConnection(event.output_id, event.input_id, event.output_class, event.input_class);
    showMessage(problem, "error");
    return;
  }
  state.addConnection(
    {
      id: state.nextId(state.getState().config.connections),
      name: `${link.input.name} → ${link.output.name}`,
      source: { endpoint: link.sourceEndpoint.id, input: link.input.id },
      destination: { endpoint: link.destinationEndpoint.id, output: link.output.id },
    },
    { fromGraph: true },
  );
}

function onConnectionRemoved(event) {
  if (rendering) return;
  const link = linkFromEvent(event);
  const connection = link && findConnectionFor(link);
  if (connection) state.removeConnection(connection.id, { fromGraph: true });
}

function onConnectionSelected(event) {
  const link = linkFromEvent(event);
  const connection = link && findConnectionFor(link);
  if (connection) state.select({ kind: "connection", id: connection.id });
}

function onNodeMoved(id) {
  const endpointId = endpointOfNode.get(String(id));
  const node = editor.getNodeFromId(id);
  if (endpointId !== undefined) state.setNodePosition(endpointId, node.pos_x, node.pos_y);
}

function onNodeRemoved(id) {
  const endpointId = endpointOfNode.get(String(id));
  endpointOfNode.delete(String(id));
  nodeOfEndpoint.delete(endpointId);
  if (endpointId !== undefined) state.removeEndpoint(endpointId, { fromGraph: true });
}

function portColumn(title, ports, kind, endpoint) {
  const rows = (ports || []).map((port) =>
    el(
      "div",
      {
        class: "dg-port-row",
        title: `${port.name} (${port.inputType ?? port.outputType})`,
        "data-kind": kind,
        "data-endpoint-id": endpoint.id,
        "data-port-id": port.id,
        onclick: () => state.select({ kind, endpointId: endpoint.id, portId: port.id }),
      },
      port.name,
    ),
  );
  return el("div", { class: `dg-col dg-col-${kind}` }, el("div", { class: "dg-col-title" }, title), rows);
}

/** (Re)build the content of an endpoint node: header plus the two port label columns. */
function fillNode(nodeId, endpoint) {
  const content = container.querySelector(`#node-${nodeId} .drawflow_content_node`);
  content.replaceChildren(
    el(
      "div",
      { class: "dg-node-head" },
      el("span", { class: "dg-node-name" }, endpoint.name ?? ""),
      el("span", { class: "dg-node-type" }, endpoint.endpointType ?? "?"),
    ),
    el(
      "div",
      { class: "dg-node-cols" },
      portColumn("Outputs (sinks)", endpoint.outputs, "output", endpoint),
      portColumn("Inputs (sources)", endpoint.inputs, "input", endpoint),
    ),
  );
}

function render() {
  const { config, layout } = state.getState();
  rendering = true;
  try {
    editor.clear();
    editor.nodeId = 1;
    editor.node_selected = null;
    editor.connection_selected = null;
    nodeOfEndpoint.clear();
    endpointOfNode.clear();

    config.endpoints.forEach((endpoint, index) => {
      if (!endpoint || typeof endpoint !== "object") return;
      const position = layout.nodes[endpoint.id] || state.gridPosition(index);
      const inputs = Array.isArray(endpoint.inputs) ? endpoint.inputs : [];
      const outputs = Array.isArray(endpoint.outputs) ? endpoint.outputs : [];
      const family = FAMILIES[endpoint.endpointType] ?? "unknown";
      // Drawflow "inputs" are Data Gateway outputs and vice versa
      const id = String(
        editor.addNode(String(endpoint.endpointType), outputs.length, inputs.length, position.x, position.y,
          `dg-node dg-${family}`, { endpointId: endpoint.id }, ""),
      );
      nodeOfEndpoint.set(endpoint.id, id);
      endpointOfNode.set(id, endpoint.id);
      fillNode(id, endpoint);
    });

    for (const connection of config.connections) {
      const ports = connectionPorts(connection);
      if (ports?.outNode && ports.inNode) editor.addConnection(ports.outNode, ports.inNode, ports.outClass, ports.inClass);
    }
  } finally {
    rendering = false;
  }
  applyDiagnostics();
  syncSelection();
}

function refreshLabels() {
  for (const endpoint of state.getState().config.endpoints) {
    const nodeId = nodeOfEndpoint.get(endpoint?.id);
    if (nodeId) fillNode(nodeId, endpoint);
  }
  applyDiagnostics();
  syncSelection();
}

/** Mirror state.selection onto the Drawflow selection and the port label rows. */
function syncSelection() {
  const selection = state.getState().selection;
  if (editor.node_selected) editor.node_selected.classList.remove("selected");
  if (editor.connection_selected) editor.connection_selected.classList.remove("selected");
  editor.node_selected = null;
  editor.connection_selected = null;

  if (selection?.endpointId !== undefined) {
    const nodeElement = container.querySelector(`#node-${nodeOfEndpoint.get(selection.endpointId)}`);
    if (nodeElement) {
      nodeElement.classList.add("selected");
      editor.node_selected = nodeElement;
    }
  } else if (selection?.kind === "connection") {
    const connection = state.findConnection(selection.id);
    const path = connection && edgeElement(connection)?.querySelector(".main-path");
    if (path) {
      path.classList.add("selected");
      editor.connection_selected = path;
    }
  }
  container.querySelectorAll(".dg-port-row").forEach((row) => {
    const selected =
      selection &&
      row.dataset.kind === selection.kind &&
      Number(row.dataset.endpointId) === selection.endpointId &&
      Number(row.dataset.portId) === selection.portId;
    row.classList.toggle("dg-port-selected", Boolean(selected));
  });
}

/** DOM elements a diagnostics path refers to, plus the Drawflow node id to bring into view. */
function targetsForPath(path) {
  const { config } = state.getState();
  const [section, index, sub, subIndex] = path;
  if (section === "endpoints" && Number.isInteger(index)) {
    const endpoint = config.endpoints[index];
    const nodeId = endpoint && nodeOfEndpoint.get(endpoint.id);
    if (!nodeId) return { elements: [], nodeId: null };
    const elements = [container.querySelector(`#node-${nodeId}`)];
    const port = (sub === "inputs" || sub === "outputs") && Number.isInteger(subIndex) ? endpoint[sub]?.[subIndex] : null;
    if (port) {
      const kind = sub === "inputs" ? "input" : "output";
      elements.push(container.querySelector(`.dg-port-row[data-kind="${kind}"][data-endpoint-id="${endpoint.id}"][data-port-id="${port.id}"]`));
    }
    return { elements: elements.filter(Boolean), nodeId };
  }
  if (section === "connections" && Number.isInteger(index)) {
    const connection = config.connections[index];
    const edge = connection && edgeElement(connection);
    return { elements: edge ? [edge] : [], nodeId: connection ? nodeOfEndpoint.get(connection.source?.endpoint) : null };
  }
  return { elements: [], nodeId: null };
}

/** Persistently mark the nodes, ports and edges that have diagnostics. */
export function setDiagnostics(list) {
  diagnostics = list;
  if (container) applyDiagnostics();
}

function applyDiagnostics() {
  container.querySelectorAll(".dg-error, .dg-warning").forEach((element) => {
    element.classList.remove("dg-error", "dg-warning");
  });
  for (const diagnostic of diagnostics) {
    const cls = diagnostic.severity === "error" ? "dg-error" : "dg-warning";
    for (const element of targetsForPath(diagnostic.path).elements) {
      if (cls === "dg-error") element.classList.remove("dg-warning");
      if (cls === "dg-error" || !element.classList.contains("dg-error")) element.classList.add(cls);
    }
  }
}

/** Emphasise the node/port/edge for a diagnostics path and pan the canvas so it is visible. */
export function highlightPath(path) {
  clearHighlights();
  const { elements, nodeId } = targetsForPath(path);
  elements.forEach((element) => element.classList.add("dg-focus"));
  if (!nodeId) return;
  const node = editor.getNodeFromId(nodeId);
  const area = container.getBoundingClientRect();
  editor.canvas_x = area.width / 2 - (node.pos_x + NODE_WIDTH / 2) * editor.zoom;
  editor.canvas_y = area.height / 2 - (node.pos_y + 60) * editor.zoom;
  editor.precanvas.style.transform = `translate(${editor.canvas_x}px, ${editor.canvas_y}px) scale(${editor.zoom})`;
}

export function clearHighlights() {
  container?.querySelectorAll(".dg-focus").forEach((element) => element.classList.remove("dg-focus"));
}
