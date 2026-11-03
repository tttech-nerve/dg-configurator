// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TTTech Industrial Automation AG

/**
 * Single mutable store for the document being edited: the config object (exactly what gets saved/packaged),
 * UI-only layout and selection, and the supporting files (name -> base64).
 *
 * Every mutator ends in notify(kind). Listeners receive (state, kind, {fromGraph}); kinds are:
 *   "structure"  endpoints/ports/connections added or removed, or the whole document replaced
 *   "config"     a property value changed
 *   "files"      supporting files changed
 *   "version"    config version changed
 *   "selection"  selection changed (no document change)
 * `fromGraph` marks structure changes the graph has already drawn itself, so it must not re-render.
 */

const DEFAULT_VERSION = "1.1";

function emptyConfig(version) {
  return { version, endpoints: [], connections: [] };
}

const state = {
  version: DEFAULT_VERSION,
  config: emptyConfig(DEFAULT_VERSION),
  layout: { nodes: {} },
  files: {},
  // {kind: "endpoint"|"input"|"output"|"connection", endpointId?, portId?, id?} or null
  selection: null,
};

const listeners = new Set();

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function notify(kind, fromGraph = false) {
  for (const fn of listeners) fn(state, kind, { fromGraph });
}

export function getState() {
  return state;
}

/** Position of the n-th node when no layout is known. */
export function gridPosition(index) {
  return { x: 60 + (index % 2) * 360, y: 40 + Math.floor(index / 2) * 260 };
}

/** Smallest unused id above the current maximum in `items` (objects with a numeric `id`). */
export function nextId(items) {
  return items.reduce((max, item) => Math.max(max, Number.isInteger(item?.id) ? item.id : 0), 0) + 1;
}

/** `base-N` with the lowest N >= 1 not present in `taken`. */
export function uniqueName(base, taken) {
  const used = new Set(taken);
  let n = 1;
  while (used.has(`${base}-${n}`)) n++;
  return `${base}-${n}`;
}

export function findEndpoint(endpointId) {
  return state.config.endpoints.find((endpoint) => endpoint.id === endpointId);
}

export function findConnection(connectionId) {
  return state.config.connections.find((connection) => connection.id === connectionId);
}

export function addEndpoint(endpoint, position) {
  state.config.endpoints.push(endpoint);
  state.layout.nodes[endpoint.id] = position || gridPosition(state.config.endpoints.length - 1);
  notify("structure");
}

export function addInput(endpointId, input) {
  const endpoint = findEndpoint(endpointId);
  (endpoint.inputs ||= []).push(input);
  notify("structure");
}

export function addOutput(endpointId, output) {
  const endpoint = findEndpoint(endpointId);
  (endpoint.outputs ||= []).push(output);
  notify("structure");
}

export function addConnection(connection, { fromGraph = false } = {}) {
  state.config.connections.push(connection);
  notify("structure", fromGraph);
}

export function removeConnection(connectionId, { fromGraph = false } = {}) {
  const index = state.config.connections.findIndex((connection) => connection.id === connectionId);
  if (index < 0) return;
  state.config.connections.splice(index, 1);
  if (state.selection?.kind === "connection" && state.selection.id === connectionId) state.selection = null;
  notify("structure", fromGraph);
}

export function removeEndpoint(endpointId, { fromGraph = false } = {}) {
  const config = state.config;
  config.endpoints = config.endpoints.filter((endpoint) => endpoint.id !== endpointId);
  config.connections = config.connections.filter(
    (c) => c.source?.endpoint !== endpointId && c.destination?.endpoint !== endpointId,
  );
  delete state.layout.nodes[endpointId];
  if (state.selection?.endpointId === endpointId) state.selection = null;
  notify("structure", fromGraph);
}

/** Remove an input (`kind` "inputs") or output ("outputs") and every connection attached to it. */
export function removePort(endpointId, kind, portId) {
  const endpoint = findEndpoint(endpointId);
  if (!endpoint) return;
  endpoint[kind] = (endpoint[kind] || []).filter((port) => port.id !== portId);
  const [side, key] = kind === "inputs" ? ["source", "input"] : ["destination", "output"];
  state.config.connections = state.config.connections.filter(
    (c) => !(c[side]?.endpoint === endpointId && c[side]?.[key] === portId),
  );
  if (state.selection?.endpointId === endpointId && state.selection.portId === portId) {
    state.selection = { kind: "endpoint", endpointId };
  }
  notify("structure");
}

/**
 * Set (or, for `undefined`, delete) the value at `path`, which addresses state.config exactly like a
 * diagnostics path. Missing parents are created; deleting an array element splices it out.
 */
export function updateProperties(path, value) {
  if (path.length === 0) return;
  let target = state.config;
  for (let i = 0; i < path.length - 1; i++) {
    const key = path[i];
    if (target[key] === undefined || target[key] === null || typeof target[key] !== "object") {
      target[key] = typeof path[i + 1] === "number" ? [] : {};
    }
    target = target[key];
  }
  const last = path[path.length - 1];
  if (value === undefined) {
    if (Array.isArray(target)) target.splice(last, 1);
    else delete target[last];
  } else {
    target[last] = value;
  }
  notify("config");
}

export function setFile(name, base64) {
  state.files[name] = base64;
  notify("files");
}

export function setNodePosition(endpointId, x, y) {
  state.layout.nodes[endpointId] = { x, y };
}

export function setVersion(version) {
  state.version = version;
  state.config.version = version;
  notify("version");
}

export function select(selection) {
  state.selection = selection;
  notify("selection");
}

/** Replace the document with imported data; endpoints without a known position are placed on a grid. */
export function loadImported(config, layout, files) {
  const doc = config && typeof config === "object" ? config : {};
  if (!Array.isArray(doc.endpoints)) doc.endpoints = [];
  if (!Array.isArray(doc.connections)) doc.connections = [];
  state.config = doc;
  if (typeof doc.version === "string") state.version = doc.version;
  else state.config.version = state.version;

  const known = layout && layout.nodes ? layout.nodes : {};
  state.layout = { nodes: {} };
  doc.endpoints.forEach((endpoint, index) => {
    state.layout.nodes[endpoint?.id] = known[endpoint?.id] || gridPosition(index);
  });
  state.files = {};
  for (const file of files || []) state.files[file.name] = file.contentBase64;
  state.selection = null;
  notify("structure");
}

export function reset() {
  state.config = emptyConfig(state.version);
  state.layout = { nodes: {} };
  state.files = {};
  state.selection = null;
  notify("structure");
}
