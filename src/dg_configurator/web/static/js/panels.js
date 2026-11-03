// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TTTech Industrial Automation AG

/**
 * The two side panels: the palette (add endpoints, and inputs/outputs of the selected endpoint) and the
 * properties panel (schema-driven form for the selected endpoint, port, connection or the document itself).
 */

import { getDiagnostics } from "./diagnostics.js";
import { el } from "./dom.js";
import { buildDefault, markFieldErrors, pickVariant, renderForm, resolveRef } from "./forms.js";
import * as state from "./state.js";

const FAMILIES = { "mqtt-client": "mqtt", "opcua-client": "opcua", "sql-client": "sql" };

// Values for fields the user would otherwise have to fill in before the object validates.
const ENDPOINT_DEFAULTS = {
  "mqtt-client": { url: "mqtt://localhost:1883" },
  "opcua-client": { url: "opc.tcp://localhost:4840" },
  "sql-client": { dbType: "postgresql", host: "localhost" },
};
const PORT_DEFAULTS = {
  "mqtt-subscriber": { messageFormat: "json", topics: [{ topic: "data/example" }] },
  "mqtt-publisher": { messageFormat: "json", topic: "data/example" },
  "opcua-polling": { pollingIntervalMS: 1000, nodes: [{ node: "ns=2;s=Example" }] },
  "opcua-subscriber": {
    samplingIntervalMS: 500,
    publishingIntervalMS: 1000,
    nodes: [{ node: "ns=2;s=Example" }],
  },
  "sql-columnar-writer": { table: "readings" },
  "sql-binary-writer": { table: "frames" },
};
// OPC UA inputs share one schema; show only the interval fields that belong to the input type.
const HIDDEN_PORT_FIELDS = {
  "opcua-polling": ["samplingIntervalMS", "publishingIntervalMS"],
  "opcua-subscriber": ["pollingIntervalMS"],
};

let meta = null;
let schemas = {};
let paletteElement = null;
let propertiesElement = null;

export function initPanels(options) {
  ({ meta, schemas, palette: paletteElement, properties: propertiesElement } = options);
  state.subscribe((current, kind) => {
    if (kind === "selection" || kind === "structure" || kind === "version") {
      renderPalette();
      renderProperties();
    }
  });
  renderPalette();
  renderProperties();
}

function currentSchema() {
  const { version } = state.getState();
  return schemas[version] ?? Object.values(schemas)[0];
}

function versionAtLeast(version, minimum) {
  const a = version.split(".").map(Number);
  const b = minimum.split(".").map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0);
  }
  return true;
}

function fillRequired(object, schema, node) {
  const resolved = resolveRef(schema, node);
  for (const key of resolved.required ?? []) {
    if (!(key in object)) object[key] = buildDefault(schema, resolved.properties[key]);
  }
  return object;
}

function endpointSchema(schema, endpointType) {
  return pickVariant(schema, schema.properties.endpoints.items, endpointType);
}

function portSchema(schema, endpointType, kind, portType) {
  const endpointNode = resolveRef(schema, endpointSchema(schema, endpointType));
  const items = endpointNode.properties?.[kind]?.items;
  return pickVariant(schema, items, portType) ?? items;
}

function createEndpoint(type) {
  const { config } = state.getState();
  const schema = currentSchema();
  const endpoint = {
    id: state.nextId(config.endpoints),
    name: state.uniqueName(type, config.endpoints.map((e) => e.name)),
    endpointType: type,
    ...structuredClone(ENDPOINT_DEFAULTS[type] ?? {}),
    inputs: [],
    outputs: [],
  };
  fillRequired(endpoint, schema, endpointSchema(schema, type));
  state.addEndpoint(endpoint);
  state.select({ kind: "endpoint", endpointId: endpoint.id });
}

function createPort(endpoint, kind, type) {
  const schema = currentSchema();
  const typeKey = kind === "inputs" ? "inputType" : "outputType";
  const ports = endpoint[kind] || [];
  const port = {
    id: state.nextId(ports),
    name: state.uniqueName(type, ports.map((p) => p.name)),
    [typeKey]: type,
    ...structuredClone(PORT_DEFAULTS[type] ?? {}),
  };
  fillRequired(port, schema, portSchema(schema, endpoint.endpointType, kind, type));
  (kind === "inputs" ? state.addInput : state.addOutput)(endpoint.id, port);
  state.select({ kind: kind === "inputs" ? "input" : "output", endpointId: endpoint.id, portId: port.id });
}

function renderPalette() {
  const { version, config, selection } = state.getState();
  const limits = meta.limits;
  const types = meta.endpointTypes;

  const addEndpointButtons = types
    .filter((type) => versionAtLeast(version, type.minVersion))
    .map((type) =>
      el(
        "button",
        {
          type: "button",
          class: `palette-item dg-${FAMILIES[type.endpointType] ?? "unknown"}`,
          disabled: config.endpoints.length >= limits.maxEndpoints,
          onclick: () => createEndpoint(type.endpointType),
        },
        `+ ${type.endpointType}`,
      ),
    );
  const hidden = types.filter((type) => !versionAtLeast(version, type.minVersion)).map((type) => type.endpointType);

  const sections = [
    el("h2", {}, "Endpoints"),
    addEndpointButtons,
    hidden.length ? el("p", { class: "hint" }, `Needs a newer config version: ${hidden.join(", ")}`) : null,
  ];

  const selected = selection?.endpointId !== undefined ? state.findEndpoint(selection.endpointId) : null;
  const typeInfo = selected && types.find((type) => type.endpointType === selected.endpointType);
  sections.push(el("h2", {}, "Selected endpoint"));
  if (!typeInfo) {
    sections.push(el("p", { class: "hint" }, "Select an endpoint to add inputs (sources) or outputs (sinks)."));
  } else {
    sections.push(el("p", { class: "hint" }, selected.name));
    for (const [kind, label, typeList, max] of [
      ["inputs", "Input", typeInfo.inputTypes, limits.maxInputsPerEndpoint],
      ["outputs", "Output", typeInfo.outputTypes, limits.maxOutputsPerEndpoint],
    ]) {
      for (const portType of typeList) {
        sections.push(
          el(
            "button",
            {
              type: "button",
              class: "palette-item",
              disabled: (selected[kind] || []).length >= max,
              title: kind === "inputs" ? "Adds a data source" : "Adds a data sink",
              onclick: () => createPort(selected, kind, portType),
            },
            `+ ${label}: ${portType}`,
          ),
        );
      }
    }
    if (!typeInfo.inputTypes.length && !typeInfo.outputTypes.length) {
      sections.push(el("p", { class: "hint" }, "This endpoint type has no inputs or outputs."));
    }
  }
  paletteElement.replaceChildren(...sections.flat().filter(Boolean));
}

function describeConnectionEnd(endpointId, portKind, portId) {
  const endpoint = state.findEndpoint(endpointId);
  const port = endpoint?.[portKind]?.find((candidate) => candidate.id === portId);
  return `${endpoint?.name ?? `endpoint ${endpointId}`} / ${port?.name ?? `port ${portId}`}`;
}

function deleteButton(label, onclick) {
  return el("button", { type: "button", class: "danger", onclick }, label);
}

function renderProperties() {
  const schema = currentSchema();
  const panel = propertiesElement;
  panel.replaceChildren();
  if (!schema) return;

  const form = el("div", { class: "properties-form" });
  const onRedraw = () => markFieldErrors(panel, getDiagnostics());
  const { config, selection } = state.getState();
  const endpoint = selection?.endpointId !== undefined ? state.findEndpoint(selection.endpointId) : null;
  const connection = selection?.kind === "connection" ? state.findConnection(selection.id) : null;
  const portKind = { input: "inputs", output: "outputs" }[selection?.kind];
  const port = endpoint && portKind ? endpoint[portKind]?.find((candidate) => candidate.id === selection.portId) : null;

  if (endpoint && selection.kind === "endpoint") {
    const path = ["endpoints", config.endpoints.indexOf(endpoint)];
    panel.append(
      el("h2", {}, "Endpoint"),
      el("p", { class: "hint" }, `${endpoint.endpointType} · id ${endpoint.id}`),
      form,
      deleteButton("Delete endpoint", () => {
        const hasPorts = (endpoint.inputs?.length ?? 0) + (endpoint.outputs?.length ?? 0) > 0;
        if (!hasPorts || window.confirm(`Delete endpoint "${endpoint.name}" and its connections?`)) {
          state.removeEndpoint(endpoint.id);
        }
      }),
    );
    renderForm(form, schema, endpointSchema(schema, endpoint.endpointType), endpoint, path, {
      hidden: new Set(["id", "endpointType", "inputs", "outputs"]),
      onRedraw,
    });
  } else if (port) {
    const typeKey = selection.kind === "input" ? "inputType" : "outputType";
    const portType = port[typeKey];
    const path = ["endpoints", config.endpoints.indexOf(endpoint), portKind, endpoint[portKind].indexOf(port)];
    panel.append(
      el("h2", {}, selection.kind === "input" ? "Input (source)" : "Output (sink)"),
      el("p", { class: "hint" }, `${portType} on ${endpoint.name} · id ${port.id}`),
      form,
      deleteButton(`Delete ${selection.kind}`, () => state.removePort(endpoint.id, portKind, port.id)),
    );
    renderForm(form, schema, portSchema(schema, endpoint.endpointType, portKind, portType), port, path, {
      hidden: new Set(["id", typeKey, ...(HIDDEN_PORT_FIELDS[portType] ?? [])]),
      onRedraw,
    });
  } else if (connection) {
    const { source, destination } = connection;
    const from = describeConnectionEnd(source?.endpoint, "inputs", source?.input);
    const to = describeConnectionEnd(destination?.endpoint, "outputs", destination?.output);
    panel.append(
      el("h2", {}, "Connection"),
      el("p", { class: "hint" }, `${from} → ${to}`),
      form,
      deleteButton("Delete connection", () => state.removeConnection(connection.id)),
    );
    const path = ["connections", config.connections.indexOf(connection)];
    renderForm(form, schema, { $ref: "#/$defs/Connection" }, connection, path, {
      hidden: new Set(["id", "source", "destination"]),
      onRedraw,
    });
  } else {
    panel.append(
      el("h2", {}, "Document settings"),
      el("p", { class: "hint" }, "Select an endpoint, port or connection to edit it; Delete removes the selected node or connection."),
      form,
    );
    renderForm(form, schema, schema, config, [], {
      hidden: new Set(["version", "endpoints", "connections"]),
      onRedraw,
    });
  }
}
