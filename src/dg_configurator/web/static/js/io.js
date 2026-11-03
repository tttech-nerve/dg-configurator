// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TTTech Industrial Automation AG

/** Import, project save, config export and package download handlers behind the toolbar buttons. */

import * as api from "./api.js";
import { renderDiagnostics } from "./diagnostics.js";
import { download, showMessage } from "./dom.js";
import { requirePem } from "./files.js";
import * as state from "./state.js";

let publicKey = null;

function diagnosticsPanel() {
  return document.getElementById("diagnostics-panel");
}

/** Remember an optional PEM public key that is sent with imports to verify signed packages. */
export async function handlePublicKeyFile(fileInput) {
  const file = fileInput.files[0];
  if (file && !requirePem(file)) {
    fileInput.value = "";
    return;
  }
  publicKey = file ? await file.text() : null;
  const status = document.getElementById("public-key-status");
  if (status) status.textContent = file ? file.name : "none";
  fileInput.value = "";
}

/** Import a config.json, deploy package (plain or signed) or .dgproj project chosen in `fileInput`. */
export async function handleImportFile(fileInput) {
  const file = fileInput.files[0];
  if (!file) return;
  try {
    const result = await api.postImport(file, publicKey);
    state.loadImported(result.config, result.layout, result.files);
    renderDiagnostics(diagnosticsPanel(), result.report);

    let text = `Imported ${file.name} (${result.packageKind})`;
    if (result.signature) text += `, signature ${result.signature}`;
    if (!result.report.valid) text += "; the configuration has problems, see the diagnostics panel";
    showMessage(text, result.signature === "invalid" || !result.report.valid ? "error" : "ok", 8000);
  } catch (error) {
    showMessage(`Import failed: ${error.message}`, "error", 10000);
  } finally {
    fileInput.value = "";
  }
}

export async function handleSaveProject() {
  const { config, layout, files } = state.getState();
  try {
    download(await api.postProject(config, layout, files), "project.dgproj");
  } catch (error) {
    if (error.report) renderDiagnostics(diagnosticsPanel(), error.report);
    showMessage(`Saving the project failed: ${error.message}`, "error", 10000);
  }
}

export function handleExportConfig() {
  const text = `${JSON.stringify(state.getState().config, null, 2)}\n`;
  download(new Blob([text], { type: "application/json" }), "config.json");
}

/** Build config.zip on the server, optionally signed; on validation errors show the diagnostics instead. */
export async function handlePackage(sign, keyFile, keyPassword) {
  if (sign && !keyFile) {
    showMessage("Choose a private key file to sign the package.", "error");
    return;
  }
  if (sign && !requirePem(keyFile)) return;
  const { config, files } = state.getState();
  try {
    const blob = await api.postPackage(config, files, sign ? keyFile : null, sign ? keyPassword : null);
    download(blob, "config.zip");
    showMessage("Package created.", "ok");
  } catch (error) {
    if (error.report) renderDiagnostics(diagnosticsPanel(), error.report);
    showMessage(`Package not created: ${error.message}`, "error", 10000);
  }
}
