// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TTTech Industrial Automation AG

/**
 * Diagnostics panel: lists the validation report and links each entry to the graph and the properties form.
 * Diagnostic paths address the config document (["endpoints", 0, "inputs", 1, "topics", 0, "topic"]).
 */

import { el } from "./dom.js";
import { markFieldErrors, scrollToField } from "./forms.js";
import * as graph from "./graph.js";
import * as state from "./state.js";

let current = [];

export function getDiagnostics() {
  return current;
}

function pathText(path) {
  if (!path.length) return "document";
  return path.map((segment) => (typeof segment === "number" ? `#${segment + 1}` : segment)).join(" → ");
}

/** The selection that shows the object a diagnostics path belongs to (null = document settings). */
function selectionFor(path) {
  const { config } = state.getState();
  if (path[0] === "endpoints" && Number.isInteger(path[1])) {
    const endpoint = config.endpoints[path[1]];
    if (!endpoint) return null;
    if ((path[2] === "inputs" || path[2] === "outputs") && Number.isInteger(path[3])) {
      const port = endpoint[path[2]]?.[path[3]];
      if (port) return { kind: path[2] === "inputs" ? "input" : "output", endpointId: endpoint.id, portId: port.id };
    }
    return { kind: "endpoint", endpointId: endpoint.id };
  }
  if (path[0] === "connections" && Number.isInteger(path[1])) {
    const connection = config.connections[path[1]];
    return connection ? { kind: "connection", id: connection.id } : null;
  }
  return null;
}

function focusDiagnostic(diagnostic) {
  state.select(selectionFor(diagnostic.path));
  graph.highlightPath(diagnostic.path);
  scrollToField(diagnostic.path);
}

/** Replace the contents of `container` with the report and mark the affected nodes, edges and fields. */
export function renderDiagnostics(container, report) {
  current = report.diagnostics ?? [];
  const errors = current.filter((d) => d.severity === "error").length;
  const warnings = current.length - errors;
  const summary = current.length
    ? `${errors} error${errors === 1 ? "" : "s"}, ${warnings} warning${warnings === 1 ? "" : "s"}`
    : "No problems found";

  const items = current.map((diagnostic) =>
    el(
      "li",
      {
        class: `diag diag-${diagnostic.severity}`,
        tabindex: 0,
        onclick: () => focusDiagnostic(diagnostic),
        onkeydown: (event) => {
          if (event.key === "Enter") focusDiagnostic(diagnostic);
        },
      },
      el("span", { class: "diag-code" }, `[${diagnostic.code}]`),
      " ",
      diagnostic.message,
      el("span", { class: "diag-path" }, pathText(diagnostic.path)),
    ),
  );
  container.replaceChildren(
    el("div", { id: "diagnostics-summary", class: errors ? "has-errors" : "" }, summary),
    el("ul", { id: "diagnostics-list" }, items),
  );

  graph.setDiagnostics(current);
  const panel = document.getElementById("properties-panel");
  if (panel) markFieldErrors(panel, current);
}
