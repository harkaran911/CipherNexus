/**
 * hash.js — StegoVault v3 Hashing & Integrity Lab
 * Real-time multi-algorithm hashing, avalanche effect demo,
 * file integrity verification, HMAC authentication.
 * All cryptography via Web Crypto API (SubtleCrypto).
 * All DOM output via textContent / createElement — no innerHTML.
 */

"use strict";

import { mkLogger, validateImageFile, sanitizePrintable } from "./security.js";
import {
  sha256Hex,
  sha512Hex,
  sha1Hex,
  hashBuffer,
  hmacSHA256,
  hmacVerify,
  bytesToHex,
} from "./crypto.js";

const subtle = crypto.subtle;

// ─── Helper: SHA-384 ──────────────────────────────────────────
async function sha384Hex(str) {
  const buf = await subtle.digest("SHA-384", new TextEncoder().encode(str));
  return bytesToHex(buf);
}

// ─── 1. Multi-Algorithm Real-Time Hasher ──────────────────────

let _hashDebounce = null;

export async function hashRealtime() {
  clearTimeout(_hashDebounce);
  _hashDebounce = setTimeout(async () => {
    const input = document.getElementById("hashInput")?.value || "";
    const container = document.getElementById("hashResults");
    if (!container) return;
    container.replaceChildren();

    if (!input) {
      const empty = document.createElement("div");
      empty.className = "hash-empty";
      empty.textContent = "Start typing to see live hashes…";
      container.appendChild(empty);
      return;
    }

    const algorithms = [
      {
        name: "SHA-1",
        fn: sha1Hex,
        bits: 160,
        color: "rose",
        deprecated: true,
        status: "⚠ DEPRECATED",
      },
      {
        name: "SHA-256",
        fn: sha256Hex,
        bits: 256,
        color: "sage",
        deprecated: false,
        status: "✓ CURRENT",
      },
      {
        name: "SHA-384",
        fn: sha384Hex,
        bits: 384,
        color: "cyan",
        deprecated: false,
        status: "✓ CURRENT",
      },
      {
        name: "SHA-512",
        fn: sha512Hex,
        bits: 512,
        color: "amber",
        deprecated: false,
        status: "✓ CURRENT",
      },
    ];

    for (const algo of algorithms) {
      try {
        const hash = await algo.fn(input);
        const row = document.createElement("div");
        row.className = `hash-result-row${algo.deprecated ? " deprecated" : ""}`;

        const header = document.createElement("div");
        header.className = "hash-result-header";

        const name = document.createElement("span");
        name.className = `hash-algo-name hash-color-${algo.color}`;
        name.textContent = algo.name;

        const meta = document.createElement("span");
        meta.className = "hash-algo-meta";
        meta.textContent = `${algo.bits}-bit · ${hash.length} hex chars · ${algo.status}`;

        header.append(name, meta);

        const hashLine = document.createElement("div");
        hashLine.className = "hash-digest-line";

        const digestEl = document.createElement("code");
        digestEl.className = "hash-digest";
        digestEl.textContent = hash;

        const copyBtn = document.createElement("button");
        copyBtn.className = "hash-copy-btn";
        copyBtn.textContent = "Copy";
        copyBtn.addEventListener("click", () => {
          navigator.clipboard
            .writeText(hash)
            .then(() => {
              copyBtn.textContent = "✓";
              copyBtn.style.color = "var(--sage)";
              setTimeout(() => {
                copyBtn.textContent = "Copy";
                copyBtn.style.color = "";
              }, 1500);
            })
            .catch(() => {
              copyBtn.textContent = "✗";
              setTimeout(() => {
                copyBtn.textContent = "Copy";
              }, 1500);
            });
        });

        hashLine.append(digestEl, copyBtn);
        row.append(header, hashLine);
        container.appendChild(row);
      } catch (err) {
        console.warn(`Hash ${algo.name} failed:`, err);
      }
    }

    // Update stats
    const statsEl = document.getElementById("hashStats");
    if (statsEl) {
      const bytes = new TextEncoder().encode(input).length;
      statsEl.textContent = `Input: ${input.length} chars · ${bytes} bytes · UTF-8 encoded`;
    }
  }, 80);
}

// ─── 2. Avalanche Effect Demonstrator ─────────────────────────

let _avalDebounce = null;

export async function avalancheDemo() {
  clearTimeout(_avalDebounce);
  _avalDebounce = setTimeout(async () => {
    const input1 = document.getElementById("avalInput1")?.value || "";
    const input2 = document.getElementById("avalInput2")?.value || "";
    const hash1El = document.getElementById("avalHash1");
    const diffEl = document.getElementById("avalDiff");
    const statsEl = document.getElementById("avalStats");
    const bitsEl = document.getElementById("avalBitDiff");

    if (!hash1El || !diffEl) return;

    const hash1 = input1 ? await sha256Hex(input1) : "";
    const hash2 = input2 ? await sha256Hex(input2) : "";

    hash1El.textContent = hash1 || "—";

    // Build visual diff
    diffEl.replaceChildren();

    if (hash1 && hash2) {
      // Character-level diff
      let charDiffs = 0;
      for (let i = 0; i < Math.max(hash1.length, hash2.length); i++) {
        const span = document.createElement("span");
        const c1 = hash1[i] || "";
        const c2 = hash2[i] || "";
        const same = c1 === c2;
        if (!same) charDiffs++;
        span.textContent = c2;
        span.className = same ? "aval-char-same" : "aval-char-diff";
        diffEl.appendChild(span);
      }

      // Bit-level diff
      let bitDiffs = 0;
      const totalBits = 256;
      for (let i = 0; i < hash1.length; i++) {
        const b1 = parseInt(hash1[i], 16);
        const b2 = parseInt(hash2[i], 16);
        const xor = b1 ^ b2;
        bitDiffs += popcount4(xor);
      }

      const bitPct = ((bitDiffs / totalBits) * 100).toFixed(1);
      const charPct = ((charDiffs / 64) * 100).toFixed(1);

      if (statsEl) {
        statsEl.textContent = `Characters changed: ${charDiffs}/64 (${charPct}%) · Bits flipped: ${bitDiffs}/256 (${bitPct}%)`;
      }

      // Animated bit-diff bar
      if (bitsEl) {
        bitsEl.replaceChildren();
        const barWrap = document.createElement("div");
        barWrap.className = "aval-bit-bar-wrap";

        const barFill = document.createElement("div");
        barFill.className = "aval-bit-bar-fill";
        barFill.style.width = bitPct + "%";
        barFill.style.background =
          bitDiffs > 100
            ? "var(--sage)"
            : bitDiffs > 50
              ? "var(--amber)"
              : "var(--rose)";

        const label = document.createElement("span");
        label.className = "aval-bit-label";
        label.textContent = `${bitPct}% bits differ`;
        label.style.color =
          bitDiffs > 100
            ? "var(--sage)"
            : bitDiffs > 50
              ? "var(--amber)"
              : "var(--rose)";

        barWrap.appendChild(barFill);
        bitsEl.append(barWrap, label);

        // Ideal indicator
        const ideal = document.createElement("div");
        ideal.className = "aval-ideal";
        ideal.textContent =
          input1 !== input2
            ? bitDiffs > 100
              ? "✓ Good avalanche — ~50% bits changed (ideal)"
              : "⚠ Weak avalanche — fewer bits changed than expected"
            : "— Identical inputs produce identical hashes";
        bitsEl.appendChild(ideal);
      }
    } else {
      if (statsEl)
        statsEl.textContent = "Enter text in both fields to compare hashes";
      if (bitsEl) bitsEl.replaceChildren();
    }
  }, 100);
}

/** Count set bits in a 4-bit nibble */
function popcount4(n) {
  let c = 0;
  while (n) {
    c += n & 1;
    n >>= 1;
  }
  return c;
}

// ─── 3. File Integrity Checker ────────────────────────────────

let _integrityFile1 = null;
let _integrityFile2 = null;
let _integrityHash1 = "";
let _integrityHash2 = "";

export function handleIntegrityFile1(input) {
  const f = input.files[0];
  if (!f) return;
  _integrityFile1 = f;
  _processIntegrityFile(f, "integrityFile1Name", "integrityFile1Hash", 1);
}

export function handleIntegrityFile2(input) {
  const f = input.files[0];
  if (!f) return;
  _integrityFile2 = f;
  _processIntegrityFile(f, "integrityFile2Name", "integrityFile2Hash", 2);
}

async function _processIntegrityFile(file, nameId, hashId, fileNum) {
  const nameEl = document.getElementById(nameId);
  const hashEl = document.getElementById(hashId);
  if (nameEl)
    nameEl.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  if (hashEl) hashEl.textContent = "Computing SHA-256…";

  try {
    const buffer = await file.arrayBuffer();
    const hash = await hashBuffer(buffer, "SHA-256");
    if (hashEl) hashEl.textContent = hash;
    if (fileNum === 1) _integrityHash1 = hash;
    else _integrityHash2 = hash;

    // Auto-compare if both loaded
    if (_integrityHash1 && _integrityHash2) {
      _compareIntegrity();
    }
  } catch (err) {
    if (hashEl) hashEl.textContent = `Error: ${err.message}`;
  }
}

function _compareIntegrity() {
  const resultEl = document.getElementById("integrityResult");
  if (!resultEl) return;
  resultEl.replaceChildren();

  const match = _integrityHash1 === _integrityHash2;

  const verdict = document.createElement("div");
  verdict.className = `integrity-verdict ${match ? "match" : "mismatch"}`;

  const icon = document.createElement("span");
  icon.className = "integrity-icon";
  icon.textContent = match ? "✓" : "✗";

  const text = document.createElement("span");
  text.textContent = match
    ? "MATCH — Files are identical (SHA-256 hashes match)"
    : "MISMATCH — Files differ! Possible corruption or tampering.";

  verdict.append(icon, text);
  resultEl.appendChild(verdict);

  // Show character-level diff
  if (!match) {
    const diffRow = document.createElement("div");
    diffRow.className = "integrity-diff-row";
    let diffCount = 0;
    for (let i = 0; i < 64; i++) {
      const span = document.createElement("span");
      const same = _integrityHash1[i] === _integrityHash2[i];
      if (!same) diffCount++;
      span.textContent = _integrityHash2[i] || "?";
      span.className = same ? "aval-char-same" : "aval-char-diff";
      diffRow.appendChild(span);
    }
    const diffLabel = document.createElement("div");
    diffLabel.className = "integrity-diff-label";
    diffLabel.textContent = `${diffCount}/64 hex characters differ`;
    resultEl.append(diffRow, diffLabel);
  }
}

export function verifyChecksum() {
  const log = mkLogger("checksumOutput");
  const knownHash = (document.getElementById("checksumInput")?.value || "")
    .trim()
    .toLowerCase();
  const fileInput = document.getElementById("checksumFile");

  if (!knownHash) {
    log("[ERROR] Paste a known SHA-256 hash first.", "err");
    return;
  }
  if (!/^[0-9a-f]{64}$/.test(knownHash)) {
    log("[ERROR] Invalid SHA-256 hash (must be 64 hex chars).", "err");
    return;
  }
  if (!fileInput?.files?.[0]) {
    log("[ERROR] Upload a file to verify.", "err");
    return;
  }

  const file = fileInput.files[0];
  log(
    `[*] Computing SHA-256 of "${sanitizePrintable(file.name, 80)}" (${(file.size / 1024).toFixed(1)} KB)…`,
    "info",
  );

  file
    .arrayBuffer()
    .then(async (buffer) => {
      const computed = await hashBuffer(buffer, "SHA-256");
      const match = computed === knownHash;

      log(`[*] Known hash:    ${knownHash}`, "muted");
      log(`[*] Computed hash: ${computed}`, "muted");
      log(
        match
          ? "[✓] INTEGRITY VERIFIED — hash matches!"
          : "[✗] INTEGRITY FAILED — hash does NOT match! File may be corrupted or tampered.",
        match ? "info" : "err",
      );
    })
    .catch((err) => {
      log(`[ERROR] ${err.message}`, "err");
    });
}

// ─── 4. HMAC Authentication ──────────────────────────────────

export async function hmacGenerate() {
  const log = mkLogger("hmacOutput");
  const message = (document.getElementById("hmacMessage")?.value || "").slice(
    0,
    1024,
  );
  const key = (document.getElementById("hmacKey")?.value || "").slice(0, 256);

  if (!message) {
    log("[ERROR] Enter a message.", "err");
    return;
  }
  if (!key) {
    log("[ERROR] Enter a secret key.", "err");
    return;
  }

  log("[*] Algorithm: HMAC-SHA-256 (Web Crypto API)", "info");
  log(
    `[*] Message: "${sanitizePrintable(message).substring(0, 60)}…"`,
    "muted",
  );
  log(
    `[*] Key: ${"●".repeat(Math.min(key.length, 32))} (${key.length} chars)`,
    "muted",
  );

  try {
    const tag = await hmacSHA256(message, key);
    log(`[✓] HMAC Tag: ${tag}`, "info");
    log(`[*] Tag length: 256 bits (64 hex chars)`, "muted");

    // Store for verification
    const tagEl = document.getElementById("hmacTagVerify");
    if (tagEl) tagEl.value = tag;
  } catch (err) {
    log(`[ERROR] HMAC failed: ${err.message}`, "err");
  }
}

export async function hmacVerifyTag() {
  const log = mkLogger("hmacVerifyOutput");
  const message = (
    document.getElementById("hmacVerifyMessage")?.value || ""
  ).slice(0, 1024);
  const key = (document.getElementById("hmacVerifyKey")?.value || "").slice(
    0,
    256,
  );
  const tag = (document.getElementById("hmacTagVerify")?.value || "")
    .trim()
    .toLowerCase();

  if (!message) {
    log("[ERROR] Enter the message to verify.", "err");
    return;
  }
  if (!key) {
    log("[ERROR] Enter the secret key.", "err");
    return;
  }
  if (!/^[0-9a-f]{64}$/.test(tag)) {
    log("[ERROR] Invalid HMAC tag (must be 64 hex chars).", "err");
    return;
  }

  log("[*] Verifying HMAC-SHA-256 tag…", "info");

  try {
    const valid = await hmacVerify(message, key, tag);
    log(`[*] Tag: ${tag.substring(0, 32)}…`, "muted");
    log(
      valid
        ? "[✓] TAG VALID — message is authentic and untampered"
        : "[✗] TAG INVALID — message or key does not match!",
      valid ? "info" : "err",
    );
  } catch (err) {
    log(`[ERROR] Verification failed: ${err.message}`, "err");
  }
}

// ─── Init ─────────────────────────────────────────────────────
export function initHashLab() {
  // Trigger initial hash display
  hashRealtime();
  // Set up avalanche with default values
  const a1 = document.getElementById("avalInput1");
  const a2 = document.getElementById("avalInput2");
  if (a1 && !a1.value) a1.value = "CipherNexus";
  if (a2 && !a2.value) a2.value = "CipherNexuS";
  avalancheDemo();
}
