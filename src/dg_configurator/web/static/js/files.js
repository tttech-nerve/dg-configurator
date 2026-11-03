// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TTTech Industrial Automation AG

/** File helpers shared by the UI modules: extension checks for the .pem-only pickers and base64 reading. */

import { showMessage } from "./dom.js";

export const PEM_ACCEPT = ".pem";

/** Case-insensitive suffix check of `file.name` against a list of extensions such as [".pem"]. */
export function hasExtension(file, extensions) {
  const name = file.name.toLowerCase();
  return extensions.some((extension) => name.endsWith(extension.toLowerCase()));
}

/** True for .pem files; otherwise shows an error message and returns false. */
export function requirePem(file) {
  if (hasExtension(file, [PEM_ACCEPT])) return true;
  showMessage(`${file.name} is not a .pem file. Use the Convert dialog to convert other formats.`, "error", 8000);
  return false;
}

/** Read a Blob/File and resolve with its content as base64 (without data-URL prefix). */
export function readBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",", 2)[1] ?? "");
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}
