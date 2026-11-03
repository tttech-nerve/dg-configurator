// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TTTech Industrial Automation AG

/**
 * Generic form renderer driven by the backend's JSON Schema (Pydantic style: `$ref` into `$defs`,
 * Optional fields as `anyOf: [X, {type: null}]`, discriminated unions as `oneOf` + `discriminator`).
 * Every edit calls state.updateProperties(path, value) with the field's config path, which is the same
 * addressing scheme as diagnostics paths (so errors can be shown on the matching field).
 */

import { el } from "./dom.js";
import { PEM_ACCEPT, readBase64, requirePem } from "./files.js";
import * as state from "./state.js";

// Supporting-file fields inside the *Security objects: a stored file name plus a file picker.
const FILE_FIELDS = new Set(["ca", "certificate", "key"]);
const SECRET_FIELDS = new Set(["password", "keyPassword"]);

/** Follow `$ref` chains into `$defs`; sibling keywords of the `$ref` win over the definition's. */
export function resolveRef(root, node) {
  let current = node || {};
  for (let depth = 0; current.$ref && depth < 20; depth++) {
    const { $ref, ...siblings } = current;
    current = { ...root.$defs[$ref.split("/").pop()], ...siblings };
  }
  return current;
}

/**
 * Classify a schema node. Returns {kind, node, nullable, defaultValue} where kind is one of
 * object | oneOf | const | select | boolean | integer | number | string | array | json (raw JSON fallback).
 */
export function analyze(root, rawNode) {
  let node = resolveRef(root, rawNode);
  let nullable = false;
  let defaultValue = node.default;
  while (node.anyOf) {
    const options = node.anyOf.filter((option) => option.type !== "null");
    if (options.length !== node.anyOf.length) nullable = true;
    if (options.length !== 1) return { kind: "json", node, nullable, defaultValue };
    const inner = resolveRef(root, options[0]);
    defaultValue = defaultValue ?? inner.default;
    node = { ...inner, description: node.description ?? inner.description };
  }
  const result = (kind) => ({ kind, node, nullable, defaultValue });
  if (node.oneOf) return node.discriminator?.mapping ? result("oneOf") : result("json");
  if ("const" in node) return result("const");
  if (node.enum) return result("select");
  if (node.type === "object") return node.properties ? result("object") : result("json");
  if (["boolean", "integer", "number", "string", "array"].includes(node.type)) return result(node.type);
  return result("json");
}

/** Variants of a discriminated union: [{value, node}]. */
export function variantsOf(unionNode) {
  return Object.entries(unionNode.discriminator.mapping).map(([value, ref]) => ({ value, node: { $ref: ref } }));
}

/** Schema node of the union variant for a discriminator value, or null. */
export function pickVariant(root, rawNode, value) {
  const analysis = analyze(root, rawNode);
  if (analysis.kind !== "oneOf") return null;
  return variantsOf(analysis.node).find((variant) => variant.value === value)?.node ?? null;
}

/** A value for `rawNode` with all required fields filled with neutral defaults. */
export function buildDefault(root, rawNode) {
  const { kind, node, defaultValue } = analyze(root, rawNode);
  switch (kind) {
    case "object": {
      const result = {};
      for (const key of node.required ?? []) result[key] = buildDefault(root, node.properties[key]);
      return result;
    }
    case "oneOf":
      return buildDefault(root, variantsOf(node)[0].node);
    case "const":
      return node.const;
    case "select":
      return defaultValue ?? node.enum[0];
    case "boolean":
      return defaultValue ?? false;
    case "integer":
    case "number":
      return defaultValue ?? node.minimum ?? 0;
    case "string":
      return defaultValue ?? "";
    case "array":
      return Array.from({ length: node.minItems ?? 0 }, () => buildDefault(root, node.items));
    default:
      return null;
  }
}

/**
 * Render the properties of the object described by `node` into `container`.
 * `value` is the live object inside state.config at `basePath`; `opts.hidden` lists property names
 * managed elsewhere (ids, type discriminators, ports); `opts.onRedraw` runs after every (re)draw.
 */
export function renderForm(container, schema, node, value, basePath, opts = {}) {
  const ctx = { root: schema, redraw };
  function redraw() {
    const { node: objectNode } = analyze(schema, node);
    container.replaceChildren(renderProperties(ctx, objectNode, value, basePath, opts.hidden));
    if (opts.onRedraw) opts.onRedraw();
  }
  redraw();
}

function commit(path, value) {
  state.updateProperties(path, value);
}

function renderProperties(ctx, objectNode, value, path, hidden) {
  const body = el("div", { class: "form-body" });
  const required = new Set(objectNode.required ?? []);
  for (const [key, raw] of Object.entries(objectNode.properties)) {
    if (key === "$schema" || (hidden && hidden.has(key))) continue;
    const fieldPath = [...path, key];
    const isFile = objectNode.title?.endsWith("Security") && FILE_FIELDS.has(key);
    body.append(
      isFile
        ? fileField(key, value?.[key], fieldPath)
        : renderField(ctx, key, raw, value?.[key], fieldPath, { required: required.has(key) }),
    );
  }
  return body;
}

function requiredMark(required) {
  return required ? el("span", { class: "req", title: "required" }, "*") : null;
}

// Array entries are always present, so they carry no required marker (`extra` is their remove button).
function isRequired(opts) {
  return opts.required && !opts.extra;
}

function renderField(ctx, key, raw, value, path, opts) {
  const analysis = analyze(ctx.root, raw);
  switch (analysis.kind) {
    case "object":
      return objectField(ctx, key, analysis, value, path, opts);
    case "oneOf":
      return unionField(ctx, key, analysis, value, path, opts);
    case "array":
      return arrayField(ctx, key, analysis, value, path, opts);
    default:
      return primitiveField(key, analysis, value, path, opts);
  }
}

function objectField(ctx, key, analysis, value, path, opts) {
  const present = value !== undefined && value !== null;
  const legend = el("legend", {}, key, requiredMark(isRequired(opts)));
  const box = el("fieldset", { class: "group", "data-path": JSON.stringify(path) }, legend);
  if (analysis.nullable) {
    const toggle = el("input", {
      type: "checkbox",
      checked: present,
      title: "Include this section",
      onchange: () => {
        commit(path, toggle.checked ? buildDefault(ctx.root, analysis.node) : undefined);
        ctx.redraw();
      },
    });
    legend.prepend(toggle);
  }
  if (opts.extra) legend.append(opts.extra);
  if (present || !analysis.nullable) box.append(renderProperties(ctx, analysis.node, present ? value : {}, path));
  return box;
}

function unionField(ctx, key, analysis, value, path, opts) {
  const discriminator = analysis.node.discriminator.propertyName;
  const variants = variantsOf(analysis.node);
  const current = value?.[discriminator];
  const select = el(
    "select",
    {
      onchange: () => {
        const variant = variants[select.selectedIndex - 1];
        commit(path, variant ? buildDefault(ctx.root, variant.node) : undefined);
        ctx.redraw();
      },
    },
    el("option", {}, ""),
    variants.map((variant) => el("option", { selected: variant.value === current }, variant.value)),
  );
  const legend = el("legend", {}, key, requiredMark(isRequired(opts)), opts.extra);
  const box = el("fieldset", { class: "group", "data-path": JSON.stringify(path) }, legend, select);
  const chosen = variants.find((variant) => variant.value === current);
  if (chosen) {
    box.append(renderProperties(ctx, resolveRef(ctx.root, chosen.node), value, path, new Set([discriminator])));
  }
  return box;
}

function arrayField(ctx, key, analysis, value, path, opts) {
  const { node } = analysis;
  const items = Array.isArray(value) ? value : [];
  const legend = el("legend", {}, key, requiredMark(isRequired(opts)), opts.extra);
  const box = el("fieldset", { class: "group array", "data-path": JSON.stringify(path) }, legend);
  const min = node.minItems ?? 0;
  items.forEach((item, index) => {
    const remove = el(
      "button",
      {
        type: "button",
        class: "small",
        title: "Remove this entry",
        disabled: items.length <= min,
        onclick: () => {
          commit([...path, index], undefined);
          ctx.redraw();
        },
      },
      "×",
    );
    box.append(renderField(ctx, `#${index + 1}`, node.items, item, [...path, index], { required: true, extra: remove }));
  });
  box.append(
    el(
      "button",
      {
        type: "button",
        class: "small",
        disabled: node.maxItems !== undefined && items.length >= node.maxItems,
        onclick: () => {
          commit([...path, items.length], buildDefault(ctx.root, node.items));
          ctx.redraw();
        },
      },
      "+ Add",
    ),
  );
  return box;
}

function primitiveField(key, analysis, value, path, opts) {
  const { kind, node } = analysis;
  const placeholder = analysis.defaultValue ?? undefined;
  const label = el("label", {}, key, requiredMark(isRequired(opts)));
  let control;
  if (kind === "boolean") {
    control = el("input", {
      type: "checkbox",
      checked: (value ?? analysis.defaultValue ?? false) === true,
      onchange: (event) => commit(path, event.target.checked),
    });
  } else if (kind === "const" || kind === "select") {
    control = selectControl(analysis, value, path);
  } else if (kind === "integer" || kind === "number") {
    control = el("input", {
      type: "number",
      value: value ?? undefined,
      min: node.minimum,
      max: node.maximum,
      step: kind === "integer" ? 1 : "any",
      placeholder,
      oninput: (event) => {
        const number = event.target.value === "" ? NaN : Number(event.target.value);
        commit(path, Number.isNaN(number) ? undefined : number);
      },
    });
  } else if (kind === "string") {
    control = el("input", {
      type: SECRET_FIELDS.has(key) ? "password" : "text",
      value: value ?? undefined,
      placeholder,
      autocomplete: "off",
      oninput: (event) => commit(path, event.target.value === "" && !opts.required ? undefined : event.target.value),
    });
  } else {
    control = jsonControl(value, path);
    label.append(" ", el("span", { class: "hint" }, "(JSON)"));
  }
  return el(
    "div",
    { class: `field field-${kind}`, "data-path": JSON.stringify(path), title: node.description },
    label,
    el("div", { class: "control" }, control, opts.extra),
  );
}

function selectControl(analysis, value, path) {
  const { kind, node } = analysis;
  const options = kind === "const" ? [node.const] : node.enum;
  const selected = value ?? analysis.defaultValue ?? (kind === "const" ? node.const : undefined);
  const hasBlank = selected === undefined || selected === null;
  return el(
    "select",
    {
      disabled: kind === "const",
      onchange: (event) => {
        const index = event.target.selectedIndex - (hasBlank ? 1 : 0);
        commit(path, index < 0 ? undefined : options[index]);
      },
    },
    hasBlank ? el("option", {}, "") : null,
    options.map((option) => el("option", { selected: option === selected }, String(option))),
  );
}

function jsonControl(value, path) {
  const area = el("textarea", {
    rows: 4,
    spellcheck: "false",
    placeholder: "JSON",
    oninput: () => {
      if (area.value.trim() === "") {
        area.classList.remove("invalid");
        commit(path, undefined);
        return;
      }
      try {
        commit(path, JSON.parse(area.value));
        area.classList.remove("invalid");
      } catch {
        area.classList.add("invalid");
      }
    },
  });
  area.value = value === undefined || value === null ? "" : JSON.stringify(value, null, 2);
  return area;
}

function fileField(key, value, path) {
  const status = el("span", { class: "file-status" });
  function updateStatus() {
    const name = text.value;
    const stored = name && Object.hasOwn(state.getState().files, name);
    status.textContent = !name ? "" : stored ? "file stored" : "no file stored under this name";
    status.className = `file-status ${stored ? "ok" : "missing"}`;
  }
  const text = el("input", {
    type: "text",
    value: value ?? undefined,
    placeholder: "stored file name, e.g. certs/ca.pem",
    oninput: () => {
      commit(path, text.value === "" ? undefined : text.value);
      updateStatus();
    },
  });
  const picker = el("input", {
    type: "file",
    accept: PEM_ACCEPT,
    title: "Choose a .pem file to store under the name on the left",
    onchange: async () => {
      const file = picker.files[0];
      if (!file) return;
      if (!requirePem(file)) {
        picker.value = "";
        return;
      }
      const name = text.value || `certs/${file.name}`;
      text.value = name;
      commit(path, name);
      state.setFile(name, await readBase64(file));
      picker.value = "";
      updateStatus();
    },
  });
  updateStatus();
  return el(
    "div",
    { class: "field field-file", "data-path": JSON.stringify(path) },
    el("label", {}, key),
    el("div", { class: "control" }, text, picker, status),
  );
}

/** Find the field element for a path, falling back to the nearest enclosing field present in `container`. */
export function findField(container, path) {
  const fields = new Map();
  container.querySelectorAll("[data-path]").forEach((element) => fields.set(element.dataset.path, element));
  for (let length = path.length; length > 0; length--) {
    const field = fields.get(JSON.stringify(path.slice(0, length)));
    if (field) return field;
  }
  return null;
}

/** Mark the fields in `container` that have diagnostics (errors win over warnings). */
export function markFieldErrors(container, diagnostics) {
  container.querySelectorAll(".dg-error, .dg-warning").forEach((element) => {
    element.classList.remove("dg-error", "dg-warning");
  });
  for (const diagnostic of diagnostics) {
    const field = findField(container, diagnostic.path);
    if (!field) continue;
    if (diagnostic.severity === "error") {
      field.classList.remove("dg-warning");
      field.classList.add("dg-error");
    } else if (!field.classList.contains("dg-error")) {
      field.classList.add("dg-warning");
    }
  }
}

/** Scroll the properties panel to the field for `path` and flash it; returns false if there is none. */
export function scrollToField(path) {
  const panel = document.getElementById("properties-panel");
  const field = panel && findField(panel, path);
  if (!field) return false;
  field.scrollIntoView({ block: "center", behavior: "smooth" });
  field.classList.add("dg-flash");
  setTimeout(() => field.classList.remove("dg-flash"), 1600);
  return true;
}
