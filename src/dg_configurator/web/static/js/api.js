// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TTTech Industrial Automation AG

/**
 * Thin fetch wrappers around the dg-configurator backend API.
 * Non-2xx responses throw an ApiError carrying the response `detail`; a 422 with a validation report
 * additionally exposes it as `error.report` so callers can render the diagnostics panel.
 */

export class ApiError extends Error {
  constructor(message, status, report = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.report = report;
  }
}

function describeDetail(detail) {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    // FastAPI request-validation errors: [{loc, msg, ...}]
    return detail.map((item) => `${(item.loc || []).join(".")}: ${item.msg}`).join("; ");
  }
  return JSON.stringify(detail);
}

async function toApiError(response) {
  const text = await response.text();
  let message = `${response.status} ${response.statusText}`.trim();
  let report = null;
  try {
    const body = JSON.parse(text);
    if (body && body.detail !== undefined) {
      const detail = body.detail;
      if (detail && typeof detail === "object" && Array.isArray(detail.diagnostics)) {
        report = detail;
        const errors = detail.diagnostics.filter((d) => d.severity === "error").length;
        message = `The configuration is invalid (${errors} error${errors === 1 ? "" : "s"})`;
      } else {
        message = describeDetail(detail);
      }
    }
  } catch {
    if (text) message = text.slice(0, 500);
  }
  return new ApiError(message, response.status, report);
}

async function request(url, options) {
  let response;
  try {
    response = await fetch(url, options);
  } catch (cause) {
    throw new ApiError(`Cannot reach the server: ${cause.message}`, 0);
  }
  if (!response.ok) throw await toApiError(response);
  return response;
}

async function getJson(url) {
  return (await request(url)).json();
}

export function base64ToBlob(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new Blob([bytes]);
}

// The config goes in as a file part: Starlette limits plain text form parts to 1 MiB.
function configForm(config, files) {
  const form = new FormData();
  form.append("config", new Blob([JSON.stringify(config)], { type: "application/json" }), "config.json");
  for (const [name, base64] of Object.entries(files || {})) {
    form.append("files", base64ToBlob(base64), name);
  }
  return form;
}

/** GET /api/meta */
export function getMeta() {
  return getJson("/api/meta");
}

/** GET /api/schema/{version} */
export function getSchema(version) {
  return getJson(`/api/schema/${encodeURIComponent(version)}`);
}

/** POST /api/validate; `files` is the list of available supporting-file names. */
export async function postValidate(config, files) {
  const response = await request("/api/validate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ config, files }),
  });
  return response.json();
}

/** POST /api/import (multipart `file` and optional `publicKey`). */
export async function postImport(file, publicKey) {
  const form = new FormData();
  form.append("file", file, file.name);
  if (publicKey) form.append("publicKey", publicKey);
  const response = await request("/api/import", { method: "POST", body: form });
  return response.json();
}

/** POST /api/package -> zip Blob. `files` maps name -> base64; `signingKey` is an optional File/Blob. */
export async function postPackage(config, files, signingKey, keyPassword) {
  const form = configForm(config, files);
  if (signingKey) {
    form.append("signingKey", signingKey, signingKey.name || "signing-key.pem");
    if (keyPassword) form.append("keyPassword", keyPassword);
  }
  const response = await request("/api/package", { method: "POST", body: form });
  return response.blob();
}

/** POST /api/project -> .dgproj zip Blob. */
export async function postProject(config, layout, files) {
  const form = configForm(config, files);
  form.append("layout", JSON.stringify(layout));
  const response = await request("/api/project", { method: "POST", body: form });
  return response.blob();
}

async function postJson(url, body) {
  const response = await request(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return response.json();
}

/** POST /api/keypair -> {files, publicKeyBase64Der, warnings}; generated in memory, nothing is stored. */
export function postKeypair(bits, passphrase) {
  return postJson("/api/keypair", { bits, passphrase: passphrase || null });
}

/** POST /api/pki/generate -> {files, certificates, warnings}. */
export function postPkiGenerate(requestBody) {
  return postJson("/api/pki/generate", requestBody);
}

/** POST /api/pki/archive -> zip Blob of the given generated files ({name, contentBase64}). */
export async function postPkiArchive(files) {
  const form = new FormData();
  for (const file of files) form.append("files", base64ToBlob(file.contentBase64), file.name);
  const response = await request("/api/pki/archive", { method: "POST", body: form });
  return response.blob();
}

/** POST /api/pki/convert (multipart) -> {files, warnings, detected}. */
export async function postConvert(file, password, outputPassphrase, basename) {
  const form = new FormData();
  form.append("file", file, file.name);
  if (password) form.append("password", password);
  if (outputPassphrase) form.append("outputPassphrase", outputPassphrase);
  if (basename) form.append("basename", basename);
  const response = await request("/api/pki/convert", { method: "POST", body: form });
  return response.json();
}
