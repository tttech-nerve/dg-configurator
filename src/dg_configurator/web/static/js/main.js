// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TTTech Industrial Automation AG

/** Entry point: loads meta and schemas, builds the panels and graph, wires the toolbar and debounced validation. */

import * as api from "./api.js";
import { renderDiagnostics } from "./diagnostics.js";
import { showMessage } from "./dom.js";
import * as graph from "./graph.js";
import * as io from "./io.js";
import { initKeysDialog } from "./keys.js";
import { initPanels } from "./panels.js";
import * as state from "./state.js";

const VALIDATION_DELAY_MS = 400;

function byId(id) {
  return document.getElementById(id);
}

let validationTimer = null;
let validationRun = 0;

function scheduleValidation() {
  clearTimeout(validationTimer);
  validationTimer = setTimeout(runValidation, VALIDATION_DELAY_MS);
}

async function runValidation() {
  const run = ++validationRun;
  const { config, files } = state.getState();
  try {
    const report = await api.postValidate(config, Object.keys(files));
    if (run === validationRun) renderDiagnostics(byId("diagnostics-panel"), report);
  } catch (error) {
    if (run === validationRun) showMessage(`Validation failed: ${error.message}`, "error");
  }
}

function setupToolbar(meta) {
  const versionSelect = byId("version-select");
  versionSelect.replaceChildren(
    ...meta.configVersions.map((version) => {
      const option = document.createElement("option");
      option.value = version;
      option.textContent = version;
      return option;
    }),
  );
  const syncVersion = () => {
    versionSelect.value = state.getState().version;
  };
  syncVersion();
  // Only the version number changes: nothing is removed, the next validation reports what is too new.
  versionSelect.addEventListener("change", () => state.setVersion(versionSelect.value));
  state.subscribe((current, kind) => {
    if (kind === "structure" || kind === "version") syncVersion();
  });

  byId("btn-new").addEventListener("click", () => {
    const { config } = state.getState();
    if (config.endpoints.length === 0 || window.confirm("Discard the current configuration and start a new one?")) {
      state.reset();
    }
  });

  const importInput = byId("import-input");
  byId("btn-import").addEventListener("click", () => importInput.click());
  importInput.addEventListener("change", () => io.handleImportFile(importInput));

  const keyInput = byId("public-key-input");
  byId("btn-public-key").addEventListener("click", () => keyInput.click());
  keyInput.addEventListener("change", () => io.handlePublicKeyFile(keyInput));

  byId("btn-save-project").addEventListener("click", () => io.handleSaveProject());
  byId("btn-export").addEventListener("click", () => io.handleExportConfig());

  const dialog = byId("package-dialog");
  const sign = byId("package-sign");
  const keyFile = byId("package-key-file");
  const keyPassword = byId("package-key-password");
  const syncSigning = () => {
    keyFile.disabled = !sign.checked;
    keyPassword.disabled = !sign.checked;
  };
  sign.addEventListener("change", syncSigning);
  syncSigning();
  byId("btn-package").addEventListener("click", () => dialog.showModal());
  byId("package-cancel").addEventListener("click", () => dialog.close());
  byId("package-form").addEventListener("submit", (event) => {
    event.preventDefault();
    dialog.close();
    io.handlePackage(sign.checked, keyFile.files[0] ?? null, keyPassword.value);
    keyPassword.value = "";
  });

  initKeysDialog(meta);
}

async function main() {
  let meta;
  let schemas;
  try {
    meta = await api.getMeta();
    const loaded = await Promise.all(meta.configVersions.map((version) => api.getSchema(version)));
    schemas = Object.fromEntries(meta.configVersions.map((version, index) => [version, loaded[index]]));
  } catch (error) {
    showMessage(`Cannot load the editor data from the server: ${error.message}`, "error", 60000);
    return;
  }
  byId("tool-version").textContent = `v${meta.toolVersion}`;

  graph.initGraph(byId("drawflow"));
  initPanels({ meta, schemas, palette: byId("palette"), properties: byId("properties-panel") });
  setupToolbar(meta);

  state.subscribe((current, kind) => {
    if (kind !== "selection") scheduleValidation();
  });
  runValidation();
}

main();
