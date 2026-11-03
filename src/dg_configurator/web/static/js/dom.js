// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TTTech Industrial Automation AG

/**
 * Tiny DOM helpers shared by the UI modules: an element factory and the transient status message.
 * All text is inserted as text nodes, never as HTML.
 */

/** Create an element. `on*` attributes are event listeners, `true` sets a boolean attribute, null/false skips. */
export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

let messageTimer = null;

/** Offer `blob` as a download named `filename` through a temporary link. */
export function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/** Show a transient message in the #message element; `kind` is "info" | "error" | "ok". */
export function showMessage(text, kind = "info", timeoutMs = 5000) {
  const box = document.getElementById("message");
  if (!box) return;
  box.textContent = text;
  box.className = `message-${kind}`;
  box.hidden = false;
  clearTimeout(messageTimer);
  messageTimer = setTimeout(() => {
    box.hidden = true;
  }, timeoutMs);
}
