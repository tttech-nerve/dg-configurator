// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TTTech Industrial Automation AG

/**
 * The "Keys & certificates" dialog: signing keypair generator, PKI generator and PEM converter.
 * Generated key material only lives in the DOM of the result areas; they are emptied when the dialog closes.
 */

import * as api from "./api.js";
import { download, el } from "./dom.js";
import { readBase64 } from "./files.js";
import * as state from "./state.js";

const TABS = ["keypair", "pki", "convert"];
const DOMAIN_LABELS = { opcua: "OPC UA", mqtt: "MQTT", sql: "SQL", tls: "Generic TLS" };
const MODES = [
  ["full", "Full PKI (CA + server + client)"],
  ["ca", "CA only"],
  ["server", "Server certificate only"],
  ["client", "Client certificate only"],
];
const ISSUERS = [
  ["new-ca", "Create a new CA"],
  ["existing-ca", "Use an existing CA"],
  ["self-signed", "Self-signed (no CA)"],
];
const DEFAULT_KEY = "rsa-4096";

function byId(id) {
  return document.getElementById(id);
}

function setStatus(text, kind = "info") {
  const box = byId("keys-status");
  box.textContent = text;
  box.className = `message-${kind}`;
  box.hidden = !text;
}

function splitList(text) {
  return text
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter((item) => item !== "");
}

function labeled(text, control) {
  return el("label", { class: "column" }, text, control);
}

function textInput(placeholder = "") {
  return el("input", { type: "text", autocomplete: "off", placeholder });
}

function passwordInput() {
  return el("input", { type: "password", autocomplete: "off" });
}

function downloadList(files) {
  return el(
    "ul",
    { class: "keys-files" },
    files.map((file) =>
      el(
        "li",
        {},
        el(
          "button",
          { type: "button", onclick: () => download(api.base64ToBlob(file.contentBase64), file.name) },
          `Download ${file.name}`,
        ),
        file.secret ? " (private key)" : "",
      ),
    ),
  );
}

function warningList(warnings) {
  if (!warnings || warnings.length === 0) return null;
  return el("ul", { class: "keys-warnings" }, warnings.map((warning) => el("li", {}, warning)));
}

/** Store the files under certs/<name> in the project, asking before overwriting. */
function addToProject(files) {
  const names = files.map((file) => `certs/${file.name}`);
  const existing = names.filter((name) => Object.hasOwn(state.getState().files, name));
  if (existing.length > 0 && !window.confirm(`Overwrite the stored file(s) ${existing.join(", ")}?`)) return;
  files.forEach((file, index) => state.setFile(names[index], file.contentBase64));
  setStatus(
    `Stored ${names.join(", ")}. Enter the passphrase of an encrypted private key in the endpoint's keyPassword field.`,
    "ok",
  );
}

async function downloadArchive(files) {
  try {
    download(await api.postPkiArchive(files), "pki.zip");
  } catch (error) {
    setStatus(`Archive not created: ${error.message}`, "error");
  }
}

/** Append warnings, per-file download buttons and the zip / add-to-project actions to `container`. */
function renderGeneratedFiles(container, files, warnings) {
  container.append(
    warningList(warnings),
    downloadList(files),
    el(
      "div",
      { class: "dialog-buttons" },
      el("button", { type: "button", onclick: () => downloadArchive(files) }, "Download all (zip)"),
      el("button", { type: "button", onclick: () => addToProject(files) }, "Add to project files"),
    ),
  );
}

// ---- signing keypair -------------------------------------------------------------------------------------------

function renderKeypairResult(container, result) {
  const value = el("textarea", { readonly: true, rows: 3, class: "keys-public-value" });
  value.value = result.publicKeyBase64Der;
  const copy = el(
    "button",
    {
      type: "button",
      onclick: async () => {
        try {
          await navigator.clipboard.writeText(value.value);
          setStatus("Copied to the clipboard.", "ok");
        } catch {
          value.select();
          setStatus("Copying is not available here; the value is selected, copy it manually.", "error");
        }
      },
    },
    "Copy",
  );
  container.replaceChildren(
    el("label", { class: "column" }, "Value for CONFIG_VERIFICATION_KEY", value),
    el("div", { class: "dialog-buttons" }, copy),
    warningList(result.warnings),
    downloadList(result.files),
  );
}

async function generateKeypair() {
  const passphraseInput = byId("keypair-passphrase");
  const bits = Number(byId("keypair-bits").value);
  const passphrase = passphraseInput.value;
  passphraseInput.value = "";
  setStatus("Generating…");
  try {
    renderKeypairResult(byId("keypair-result"), await api.postKeypair(bits, passphrase));
    setStatus("");
  } catch (error) {
    byId("keypair-result").replaceChildren();
    setStatus(`Key pair not generated: ${error.message}`, "error");
  }
}

// ---- PKI generator ---------------------------------------------------------------------------------------------

/** One certificate form (CA, server or client); `update` adapts it to the usage chosen. */
function certificateFieldset(role, title, basename) {
  const fields = {
    commonName: textInput(),
    organization: textInput(),
    organizationalUnit: textInput(),
    country: el("input", { type: "text", autocomplete: "off", maxlength: 2, placeholder: "AT" }),
    state: textInput(),
    locality: textInput(),
    dns: el("textarea", { rows: 2, placeholder: "one per line or comma separated" }),
    ip: el("textarea", { rows: 2, placeholder: "one per line or comma separated" }),
    uri: el("textarea", { rows: 2 }),
    email: el("textarea", { rows: 2 }),
    key: el("select"),
    validity: el("input", { type: "number", min: 1, step: 1 }),
    passphrase: passwordInput(),
    confirm: passwordInput(),
    basename: textInput(),
  };
  fields.basename.value = basename;
  const sanFields = el(
    "div",
    { class: "san-fields" },
    labeled("DNS names", fields.dns),
    labeled("IP addresses", fields.ip),
    labeled("URIs", fields.uri),
    labeled("E-mail addresses", fields.email),
  );
  const uriLabel = sanFields.children[2];
  const hint = el("p", { class: "hint" });
  const notes = el("ul", { class: "hint" });
  const root = el(
    "fieldset",
    { class: "pki-cert", "data-role": role },
    el("legend", {}, title),
    hint,
    notes,
    labeled("Common name (CN)", fields.commonName),
    el(
      "div",
      { class: "pki-grid" },
      labeled("Organisation (O)", fields.organization),
      labeled("Organisational unit (OU)", fields.organizationalUnit),
      labeled("Country (C)", fields.country),
      labeled("State (ST)", fields.state),
      labeled("Locality (L)", fields.locality),
    ),
    sanFields,
    el(
      "div",
      { class: "pki-grid" },
      labeled("Key type", fields.key),
      labeled("Validity (days)", fields.validity),
      labeled("File name (without .pem)", fields.basename),
    ),
    el(
      "div",
      { class: "pki-grid" },
      labeled("Passphrase for the private key (optional)", fields.passphrase),
      labeled("Repeat passphrase", fields.confirm),
    ),
  );

  return {
    root,
    fields,
    /** Adapt hints, key choices, validity bounds and the SAN fields to the selected usage profile. */
    update(profile) {
      const isCa = profile.role === "ca";
      fields.commonName.placeholder = isCa ? "default: <organisation> Root CA" : profile.commonNameHint;
      hint.textContent = `Common name: ${profile.commonNameHint}`;
      notes.replaceChildren(...profile.notes.map((note) => el("li", {}, note)));
      sanFields.hidden = isCa;
      uriLabel.firstChild.textContent = profile.requiresApplicationUri ? "Application URI (first line)" : "URIs";
      const previous = fields.key.value;
      fields.key.replaceChildren(...profile.allowedKeys.map((key) => el("option", { value: key }, key)));
      fields.key.value = profile.allowedKeys.includes(previous)
        ? previous
        : profile.allowedKeys.includes(DEFAULT_KEY)
          ? DEFAULT_KEY
          : profile.allowedKeys[0];
      fields.validity.max = profile.maxValidityDays;
      fields.validity.placeholder = `default ${profile.defaultValidityDays}`;
    },
    /** The subject, key, validity, passphrase and file name as the request fields; throws on a passphrase mismatch. */
    read() {
      if (fields.passphrase.value !== fields.confirm.value) {
        throw new Error(`${title}: the passphrases do not match.`);
      }
      return {
        subject: {
          commonName: fields.commonName.value.trim(),
          organization: fields.organization.value.trim() || null,
          organizationalUnit: fields.organizationalUnit.value.trim() || null,
          country: fields.country.value.trim() || null,
          state: fields.state.value.trim() || null,
          locality: fields.locality.value.trim() || null,
        },
        key: fields.key.value,
        validityDays: fields.validity.value === "" ? null : Number(fields.validity.value),
        passphrase: fields.passphrase.value || null,
        basename: fields.basename.value.trim() || basename,
      };
    },
    san() {
      return {
        dns: splitList(fields.dns.value),
        ip: splitList(fields.ip.value),
        uri: splitList(fields.uri.value),
        email: splitList(fields.email.value),
      };
    },
    clearPassphrases() {
      fields.passphrase.value = "";
      fields.confirm.value = "";
    },
  };
}

function radioGroup(name, options, onChange) {
  const inputs = options.map(([value, label], index) =>
    el("input", { type: "radio", name, value, checked: index === 0, onchange: onChange }),
  );
  const root = el("div", { class: "radio-group" }, options.map(([, label], index) => el("label", { class: "row" }, inputs[index], label)));
  return { root, value: () => inputs.find((input) => input.checked).value };
}

function usageProfile(meta, usage) {
  return meta.pki.usages.find((item) => item.usage === usage);
}

function certificateTable(certificates) {
  const header = el("tr", {}, ["File", "Subject", "Expires", "SHA-256 fingerprint"].map((text) => el("th", {}, text)));
  const rows = certificates.map((item) =>
    el(
      "tr",
      {},
      el("td", {}, item.file),
      el("td", {}, item.subject),
      el("td", {}, item.notAfter.slice(0, 10)),
      el("td", { class: "fingerprint" }, item.sha256Fingerprint),
    ),
  );
  return el("table", { class: "keys-table" }, el("thead", {}, header), el("tbody", {}, rows));
}

function initPkiPanel(meta) {
  const panel = byId("keys-panel-pki");
  const result = el("div", { id: "pki-result" });
  const mode = radioGroup("pki-mode", MODES, refresh);
  const domain = el(
    "select",
    { onchange: refresh },
    Object.keys(meta.pki.domains).map((key) => el("option", { value: key }, DOMAIN_LABELS[key] ?? key)),
  );
  const issuer = radioGroup("pki-issuer", ISSUERS, refresh);
  const caCert = el("input", { type: "file", accept: ".pem" });
  const caKey = el("input", { type: "file", accept: ".pem" });
  const caPassphrase = passwordInput();
  const existingCa = el(
    "fieldset",
    { class: "pki-cert" },
    el("legend", {}, "Existing CA"),
    labeled("CA certificate (PEM)", caCert),
    labeled("CA private key (PEM)", caKey),
    labeled("Passphrase of the CA key (if encrypted)", caPassphrase),
  );
  const issuerBox = el("div", {}, el("strong", {}, "Issuer"), issuer.root, existingCa);
  const ca = certificateFieldset("ca", "Certificate authority", "ca");
  const server = certificateFieldset("server", "Server certificate", "server");
  const client = certificateFieldset("client", "Client certificate", "client");

  function refresh() {
    const single = mode.value() === "server" || mode.value() === "client";
    const issuerKind = issuer.value();
    const usages = meta.pki.domains[domain.value];
    issuerBox.hidden = !single;
    existingCa.hidden = !(single && issuerKind === "existing-ca");
    ca.root.hidden = !(mode.value() === "full" || mode.value() === "ca" || (single && issuerKind === "new-ca"));
    server.root.hidden = !(mode.value() === "full" || mode.value() === "server");
    client.root.hidden = !(mode.value() === "full" || mode.value() === "client");
    domain.disabled = mode.value() === "ca";
    ca.update(usageProfile(meta, "ca"));
    server.update(usageProfile(meta, usages.server));
    client.update(usageProfile(meta, usages.client));
  }

  async function buildRequest() {
    const selectedMode = mode.value();
    const usages = meta.pki.domains[domain.value];
    const single = selectedMode === "server" || selectedMode === "client";
    const issuerKind = single ? issuer.value() : selectedMode === "ca" ? "ca-only" : "new-ca";
    const body = { issuer: issuerKind, leaves: [] };
    if (!ca.root.hidden) {
      body.ca = ca.read();
      body.ca.subject.commonName ||= `${body.ca.subject.organization || "Data Gateway"} Root CA`;
    }
    if (issuerKind === "existing-ca") {
      if (!caCert.files[0] || !caKey.files[0]) throw new Error("Choose the CA certificate and the CA key (.pem).");
      body.existingCa = {
        certificateBase64: await readBase64(caCert.files[0]),
        privateKeyBase64: await readBase64(caKey.files[0]),
        passphrase: caPassphrase.value || null,
      };
    }
    for (const [form, usage] of [
      [server, usages.server],
      [client, usages.client],
    ]) {
      if (form.root.hidden) continue;
      body.leaves.push({ usage, ...form.read(), san: form.san() });
    }
    return body;
  }

  function clearPassphrases() {
    for (const form of [ca, server, client]) form.clearPassphrases();
    caPassphrase.value = "";
  }

  async function generate() {
    let body;
    try {
      body = await buildRequest();
    } catch (error) {
      setStatus(error.message, "error");
      return;
    }
    setStatus("Generating… (4096-bit RSA keys can take a few seconds)");
    try {
      const response = await api.postPkiGenerate(body);
      result.replaceChildren(certificateTable(response.certificates));
      renderGeneratedFiles(result, response.files, response.warnings);
      setStatus("");
    } catch (error) {
      result.replaceChildren();
      setStatus(`Not generated: ${error.message}`, "error");
    } finally {
      clearPassphrases();
    }
  }

  panel.replaceChildren(
    el("p", { class: "hint" }, "Generates certificates and keys as .pem files in memory. Nothing is stored on the server."),
    el("strong", {}, "What do you want to create?"),
    mode.root,
    labeled("Usage / domain", domain),
    issuerBox,
    ca.root,
    server.root,
    client.root,
    el("div", { class: "dialog-buttons" }, el("button", { type: "button", onclick: generate }, "Generate")),
    result,
  );
  refresh();
  return () => {
    result.replaceChildren();
    clearPassphrases();
    caCert.value = "";
    caKey.value = "";
  };
}

// ---- converter -------------------------------------------------------------------------------------------------

async function convertFile() {
  const fileInput = byId("convert-file");
  const passwordInput = byId("convert-password");
  const outputInput = byId("convert-output-passphrase");
  const file = fileInput.files[0];
  if (!file) {
    setStatus("Choose a file to convert.", "error");
    return;
  }
  const password = passwordInput.value;
  const outputPassphrase = outputInput.value;
  const result = byId("convert-result");
  setStatus("Converting…");
  try {
    const response = await api.postConvert(file, password, outputPassphrase, byId("convert-basename").value.trim());
    result.replaceChildren(el("p", {}, `Detected: ${response.detected.join("; ")}`));
    renderGeneratedFiles(result, response.files, response.warnings);
    setStatus("");
  } catch (error) {
    result.replaceChildren();
    setStatus(`Not converted: ${error.message}`, "error");
  } finally {
    passwordInput.value = "";
    outputInput.value = "";
  }
}

// ---- dialog ----------------------------------------------------------------------------------------------------

function selectTab(name) {
  for (const tab of TABS) {
    byId(`keys-tab-${tab}`).setAttribute("aria-selected", String(tab === name));
    byId(`keys-panel-${tab}`).hidden = tab !== name;
  }
  setStatus("");
}

/** Wire the "Keys & certificates…" toolbar button, the tabs and the three panels; `meta` is the /api/meta response. */
export function initKeysDialog(meta) {
  const dialog = byId("keys-dialog");
  const resetPki = initPkiPanel(meta);

  for (const tab of TABS) byId(`keys-tab-${tab}`).addEventListener("click", () => selectTab(tab));
  byId("btn-keys").addEventListener("click", () => {
    selectTab("keypair");
    dialog.showModal();
  });
  byId("keys-close").addEventListener("click", () => dialog.close());
  byId("keypair-generate").addEventListener("click", generateKeypair);
  byId("convert-run").addEventListener("click", convertFile);

  dialog.addEventListener("close", () => {
    byId("keypair-result").replaceChildren();
    byId("convert-result").replaceChildren();
    for (const id of ["keypair-passphrase", "convert-password", "convert-output-passphrase"]) byId(id).value = "";
    byId("convert-file").value = "";
    resetPki();
    setStatus("");
  });
}
