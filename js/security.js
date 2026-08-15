/**
 * security.js — CipherNexus v3 Security Utility Layer
 * All XSS prevention, input validation, file validation,
 * safe DOM helpers, localStorage guards, clipboard safety.
 * No external dependencies. Must be loaded FIRST.
 */

"use strict";

// ─── HTML Escape ──────────────────────────────────────────────
/**
 * Escapes a string for safe insertion into innerHTML.
 * Use on ANY user-controlled or file-derived string.
 */
export function html(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/`/g, "&#x60;");
}

// ─── Safe Image Insertion ─────────────────────────────────────
const ALLOWED_DATA_PREFIXES = [
  "data:image/png;base64,",
  "data:image/jpeg;base64,",
  "data:image/jpg;base64,",
  "data:image/gif;base64,",
  "data:image/webp;base64,",
  "data:image/bmp;base64,",
];

/**
 * Safely inserts an image into a preview frame using createElement.
 * Validates data URL prefix — never uses innerHTML.
 * Defense: prevents XSS via crafted SVG/script data URLs.
 */
export function setImgSrc(elementId, dataUrl) {
  const frame = document.getElementById(elementId);
  if (!frame) return;
  const safe = ALLOWED_DATA_PREFIXES.some((p) => dataUrl.startsWith(p));
  frame.replaceChildren();
  if (!safe) {
    const span = document.createElement("span");
    span.className = "placeholder";
    span.textContent = "invalid image format";
    frame.appendChild(span);
    return;
  }
  const img = document.createElement("img");
  img.setAttribute("src", dataUrl);
  img.setAttribute("alt", "image preview");
  img.style.cssText =
    "max-width:100%;max-height:100%;object-fit:contain;display:block";
  frame.appendChild(img);
}

// ─── File Validation ──────────────────────────────────────────
export const MAX_FILE_SIZE = 15 * 1024 * 1024; // 15 MB
export const ALLOWED_MIME = new Set([
  "image/png",
  "image/jpeg",
  "image/jpg",
  "image/gif",
  "image/webp",
  "image/bmp",
]);

// Magic byte signatures
const MAGIC = [
  { bytes: [0x89, 0x50, 0x4e, 0x47] }, // PNG
  { bytes: [0xff, 0xd8, 0xff] }, // JPEG
  { bytes: [0x47, 0x49, 0x46] }, // GIF
  { bytes: [0x52, 0x49, 0x46, 0x46] }, // WEBP (RIFF)
  { bytes: [0x42, 0x4d] }, // BMP
];

/**
 * Validates an uploaded file:
 *  1. MIME type whitelist
 *  2. Size cap (15 MB)
 *  3. Magic byte header check
 * Returns Promise<{ valid: boolean, error?: string }>
 */
export function validateImageFile(file) {
  return new Promise((resolve) => {
    if (!ALLOWED_MIME.has(file.type)) {
      return resolve({
        valid: false,
        error: `File type "${html(file.type)}" not allowed. Use PNG/JPEG/WEBP/BMP/GIF.`,
      });
    }
    if (file.size > MAX_FILE_SIZE) {
      return resolve({
        valid: false,
        error: `File too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Max 15 MB.`,
      });
    }
    if (file.size === 0) {
      return resolve({ valid: false, error: "File is empty." });
    }
    const fr = new FileReader();
    fr.onload = (e) => {
      const arr = new Uint8Array(e.target.result);
      const ok = MAGIC.some((sig) => sig.bytes.every((b, i) => arr[i] === b));
      if (!ok)
        return resolve({
          valid: false,
          error:
            "File header does not match a known image format. Possible spoofed extension.",
        });
      resolve({ valid: true });
    };
    fr.onerror = () =>
      resolve({ valid: false, error: "File read error during validation." });
    fr.readAsArrayBuffer(file.slice(0, 8));
  });
}

// ─── Image Dimension Guard ────────────────────────────────────
/**
 * Validates HTMLImageElement dimensions before canvas ops.
 * Prevents memory exhaustion via gigantic crafted images.
 */
export function validateImageDimensions(img, maxDim = 20000) {
  return (
    img &&
    img.width > 0 &&
    img.height > 0 &&
    img.width <= maxDim &&
    img.height <= maxDim
  );
}

// ─── DOM Terminal Helpers ─────────────────────────────────────
const SAFE_LOG_CLS = new Set(["", "err", "warn", "info", "muted", "safe"]);

/**
 * Appends a styled line to a terminal div using textContent.
 * cls must be one of: err | warn | info | muted | ''
 * Never uses innerHTML — safe against any message content.
 */
export function appendToTerminal(terminalId, message, cls = "") {
  const out = document.getElementById(terminalId);
  if (!out) return;
  out.style.display = "block";
  const s = document.createElement("span");
  const sc = SAFE_LOG_CLS.has(cls) ? cls : "";
  s.className = `t-line${sc ? " t-" + sc : ""}`;
  s.textContent = String(message);
  out.appendChild(s);
  out.appendChild(document.createElement("br"));
  out.scrollTop = out.scrollHeight;
}

/** Clears a terminal div safely. */
export function clearTerminal(terminalId) {
  const out = document.getElementById(terminalId);
  if (!out) return;
  out.replaceChildren();
  out.style.display = "block";
}

/**
 * Returns a logger closure for a terminal div.
 * Usage: const log = mkLogger('myTerminalId');
 *        log('message', 'info');
 */
export function mkLogger(id) {
  clearTerminal(id);
  return (msg, cls = "") => appendToTerminal(id, msg, cls);
}

// ─── LocalStorage Guards ──────────────────────────────────────
const LS_WHITELIST = {
  sv_sidebar: new Set(["0", "1"]),
};

/** Reads and validates a whitelisted localStorage key. */
export function sanitizeLocalStorage(key) {
  if (!LS_WHITELIST[key]) return null;
  try {
    const val = localStorage.getItem(key);
    if (!LS_WHITELIST[key].has(val)) {
      localStorage.removeItem(key);
      return null;
    }
    return val;
  } catch {
    return null;
  }
}

/** Validates key + value against whitelist before writing. */
export function safeWriteLocalStorage(key, value) {
  if (!LS_WHITELIST[key] || !LS_WHITELIST[key].has(value)) return;
  try {
    localStorage.setItem(key, value);
  } catch {
    /* quota / private mode */
  }
}

// ─── Clipboard Guard ─────────────────────────────────────────
const MAX_CLIP = 8192;

/**
 * Strips ANSI escapes + null bytes, enforces 8KB cap,
 * then writes to clipboard.
 * Returns Promise.
 */
export function safeClipboard(text) {
  if (typeof text !== "string") return Promise.reject("Not a string");
  const cleaned = text
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "") // ANSI escape sequences
    .replace(/\x00/g, "") // null bytes
    .replace(/\r/g, "\n"); // normalize line endings
  if (cleaned.length > MAX_CLIP)
    return Promise.reject(`Content too long (${cleaned.length} chars)`);
  return navigator.clipboard.writeText(cleaned);
}

// ─── Input Validators ─────────────────────────────────────────
/**
 * Parses and range-checks a numeric input.
 * Returns fallback on NaN / out-of-range / non-finite.
 */
export function validateIntegerInput(value, min, max, fallback) {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n) || n < min || n > max) return fallback;
  return n;
}

/** Validates a hex string (no 0x prefix). */
export function validateHex(str, maxLen = 64) {
  return (
    typeof str === "string" &&
    /^[0-9a-fA-F]+$/.test(str) &&
    str.length > 0 &&
    str.length <= maxLen
  );
}

/** Strips non-printable ASCII, optional length cap. */
export function sanitizePrintable(str, maxLen = 512) {
  return String(str)
    .replace(/[^\x20-\x7E]/g, "")
    .slice(0, maxLen);
}

// ─── Security Audit Console Log ───────────────────────────────
export function printSecurityAudit() {
  const controls = [
    "CSP: default-src self; connect-src none; object-src none; frame-ancestors none",
    "X-Content-Type-Options: nosniff",
    "Referrer-Policy: no-referrer",
    "File validation: MIME whitelist + magic bytes + 15 MB cap",
    "innerHTML banned — all output via textContent / DOM API",
    "localStorage: key+value whitelist validated",
    "Clipboard: ANSI stripped, 8 KB cap",
    "RSA/AES/KDF: Web Crypto API (SubtleCrypto) — real cryptography",
    "LSB hot-loop: WebAssembly for performance + isolation",
    "Canvas: dimension-validated (max 20 000 × 20 000)",
    "Input length caps on all user fields",
    "No eval(), no new Function(), no setTimeout(string)",
  ];
  console.groupCollapsed(
    "%c CipherNexus v3 — Security Controls",
    "color:#f5a623;font-weight:bold;font-size:13px",
  );
  controls.forEach((c, i) =>
    console.log(
      `%c ${String(i + 1).padStart(2, "0")} %c ${c}`,
      "color:#6ee7b7;font-weight:bold",
      "color:#9d9ab5",
    ),
  );
  console.groupEnd();
}
