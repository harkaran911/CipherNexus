/**
 * app.js — CipherNexus v3 Application Entry Point
 * Imports all modules, wires DOM events, initialises UI,
 * handles RSA panel, entropy visualizer, password analyzer.
 * This is the ONLY file that touches window / global scope.
 */

"use strict";

import {
  printSecurityAudit,
  mkLogger,
  sanitizePrintable,
  validateIntegerInput,
  validateHex,
} from "./security.js";
import {
  initCursor,
  initSidebar,
  toggleSidebar,
  switchTab,
  animateBlocks,
  runECBDemo,
  buildPrimeGrid,
  buildChecklist,
  copyCmd,
} from "./ui.js";
import {
  runAESPanel,
  runKDFPanel,
  calcPassEntropy,
  shannonEntropy,
  generateRSAKeys,
  rsaEncryptWC,
  rsaDecryptWC,
  rsaSignWC,
  rsaVerifyWC,
  modPow,
  gcd,
  modInverse,
  isPrime,
  bytesToHex,
} from "./crypto.js";
import {
  handleEncodeUpload,
  handleDecodeUpload,
  handleCompareUpload,
  encodeMessage,
  decodeMessage,
  renderBitPlanes,
  showBitPlaneDemo,
  runChiSquare,
  updateCapacity,
  setLsbDepth,
  setLsbDecodeDepth,
  runRSAnalysis,
  runHistogramAnalysis,
  setHistogramChannel,
  runSPAAnalysis,
} from "./steg.js";
import {
  handleAudioUpload,
  encodeAudioMessage,
  decodeAudioMessage,
  playAndVisualize,
  exportWAV,
  stopAudio,
  analyzeWAVMetadata,
  drawLSBBitmap,
  analyzeStereoChannels,
} from "./audio_steg.js";
import {
  hashRealtime,
  avalancheDemo,
  handleIntegrityFile1,
  handleIntegrityFile2,
  verifyChecksum,
  hmacGenerate,
  hmacVerifyTag,
  initHashLab,
} from "./hash.js";
import { handleEncodingSync } from "./encoding.js";
import { initCrackLab, handleWordlistUpload, startCracker, stopCracker } from "./cracker.js";
import { initScene } from "./scene.js";
import {
  runHexDump, runStringsExtract, runPNGChunks,
  runFileCarver, runMetadataExtract,
} from "./forensics.js";
import {
  identifyHash,
  runXORAnalyze, runXORWithKey,
  runCaesar, runCaesarBrute,
  runVigenere, runAtbash,
  runRailFence, runFrequencyAnalysis, runROT13,
} from "./ctf_tools.js";

// ─── RSA Panel State ──────────────────────────────────────────
const RSA_MIN = 2,
  RSA_MAX = 9999;
let _rsaP = 61,
  _rsaQ = 53,
  _rsaE = 17;
let _lastSig = null;

async function rsaDerive() {
  _rsaP = validateIntegerInput(
    document.getElementById("rsaP")?.value,
    RSA_MIN,
    RSA_MAX,
    61,
  );
  _rsaQ = validateIntegerInput(
    document.getElementById("rsaQ")?.value,
    RSA_MIN,
    RSA_MAX,
    53,
  );
  _rsaE = validateIntegerInput(
    document.getElementById("rsaE")?.value,
    2,
    65537,
    17,
  );
  await generateRSAKeys(_rsaP, _rsaQ, _rsaE);
  rsaAutoEncrypt();
}

function rsaGenRandom() {
  const primes = [
    11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
    89, 97, 101, 103, 107, 109, 113,
  ];
  const shuffle = (arr) => [...arr].sort(() => Math.random() - 0.5);
  const [p, q] = shuffle(primes);
  const phi = (p - 1) * (q - 1);
  const eOpts = [17, 19, 23, 29, 31, 37, 41];
  const e = eOpts.find((c) => c < phi && gcd(c, phi) === 1) || 3;
  document.getElementById("rsaP").value = p;
  document.getElementById("rsaQ").value = q;
  document.getElementById("rsaE").value = e;
  rsaDerive();
}

function rsaCheckPrimes() {
  const p = validateIntegerInput(
    document.getElementById("rsaP")?.value,
    RSA_MIN,
    RSA_MAX,
    0,
  );
  const q = validateIntegerInput(
    document.getElementById("rsaQ")?.value,
    RSA_MIN,
    RSA_MAX,
    0,
  );
  alert(
    `p=${p}: ${isPrime(p) ? "✓ Prime" : "✗ Not prime"}\nq=${q}: ${isPrime(q) ? "✓ Prime" : "✗ Not prime"}`,
  );
}

async function rsaAutoEncrypt() {
  const rawText = document.getElementById("rsaPlainEnc")?.value || "Hi";
  const text = rawText.slice(0, 32);

  // Show textbook blocks (small prime demo)
  const blocks = document.getElementById("rsaCipherBlocks");
  const outEl = document.getElementById("rsaEncOutput");
  if (!blocks || !outEl) return;

  const n = _rsaP * _rsaQ,
    e = _rsaE;
  if (n < 2) return;

  const bytes = [...text].map((c) => c.charCodeAt(0));
  const ciphered = bytes.map((m) => modPow(m, e, n));

  blocks.replaceChildren();
  ciphered.forEach((c) => {
    const d = document.createElement("div");
    d.className = "block-cell cipher";
    d.textContent = String(c);
    d.title = `C = ${c}`;
    blocks.appendChild(d);
  });
  outEl.textContent = ciphered.join(", ");

  // Also attempt real Web Crypto RSA-OAEP for display
  try {
    const realCtHex = await rsaEncryptWC(text);
    document.getElementById("rsaCipherIn").value = realCtHex;
  } catch {
    document.getElementById("rsaCipherIn").value = ciphered.join(", ");
  }
}

async function rsaDecrypt() {
  const log = mkLogger("rsaDecOutput");
  const raw = document.getElementById("rsaCipherIn")?.value || "";

  // Try real Web Crypto first
  if (/^[0-9a-f]{64,}$/.test(raw.trim())) {
    try {
      const pt = await rsaDecryptWC(raw.trim());
      log("[✓] Decrypted (real RSA-OAEP 2048-bit):", "info");
      log(`[✓] Plaintext: "${sanitizePrintable(pt)}"`, "info");
      return;
    } catch {
      /* fall through to textbook mode */
    }
  }

  // Textbook mode (small prime demo)
  if (raw.length > 200 || !/^[0-9,\s]+$/.test(raw)) {
    log("[SECURITY] Invalid ciphertext format.", "err");
    return;
  }
  const n = _rsaP * _rsaQ,
    d = modInverse(_rsaE, (_rsaP - 1) * (_rsaQ - 1));
  const ciphered = raw
    .split(",")
    .map((s) => parseInt(s.trim(), 10))
    .filter((x) => Number.isFinite(x) && x >= 0 && x < n);
  const decrypted = ciphered.map((c) => modPow(c, d, n));
  const text = decrypted.map((b) => String.fromCharCode(b)).join("");
  log(`[✓] Decrypted bytes: ${decrypted.join(", ")}`, "info");
  log(`[✓] Plaintext: "${sanitizePrintable(text)}"`, "info");
  log(`[*] Using d=${d}, n=${n} (textbook small-prime demo)`, "muted");
}

async function rsaSign() {
  const el = document.getElementById("rsaSignMsg");
  const out = document.getElementById("rsaSigOutput");
  if (!el || !out) return;
  const msg = el.value.slice(0, 256);
  try {
    const sigHex = await rsaSignWC(msg);
    _lastSig = { sigHex, msg };
    out.textContent = `Signature (RSASSA-PKCS1-v1_5, SHA-256):\n${sigHex.slice(0, 64)}…\n[real Web Crypto signature]`;
    document.getElementById("rsaVerifyMsg").value = msg;
  } catch (err) {
    out.textContent = `[ERROR] ${err.message} — generate a keypair first.`;
  }
}

async function rsaVerify() {
  const log = mkLogger("rsaVerifyOutput");
  if (!_lastSig) {
    log("[ERROR] Sign a message first.", "err");
    return;
  }
  const msg = (document.getElementById("rsaVerifyMsg")?.value || "").slice(
    0,
    256,
  );
  try {
    const valid = await rsaVerifyWC(msg, _lastSig.sigHex);
    log(`[*] Verifying RSASSA-PKCS1-v1_5 signature…`, "info");
    log(`[*] Message matches original: ${msg === _lastSig.msg}`, "muted");
    log(
      valid
        ? "[✓] SIGNATURE VALID — message is authentic (Web Crypto verified)"
        : "[✗] SIGNATURE INVALID — message was tampered!",
      valid ? "info" : "err",
    );
  } catch (err) {
    log(`[ERROR] Verify failed: ${err.message}`, "err");
  }
}

// ─── AES Panel State ──────────────────────────────────────────
let currentAESMode = "ECB";

function setAESMode(mode, btn) {
  currentAESMode = mode;
  document
    .querySelectorAll(".mode-tab")
    .forEach((b) => b.classList.remove("active"));
  btn.classList.add("active");
  const ivField = document.getElementById("ivField");
  if (ivField) ivField.classList.toggle("show", mode !== "ECB");
  animateBlocks(
    mode,
    document.getElementById("aesPlain")?.value || "PLAINTEXT",
  );
}

function handleAES(op) {
  const mode = currentAESMode;
  const pass = (document.getElementById("aesPass")?.value || "").slice(0, 128);
  const plain = (document.getElementById("aesPlain")?.value || "").slice(
    0,
    512,
  );
  const ivHex = document.getElementById("aesIV")?.value || "";
  runAESPanel(op, mode, pass, plain, ivHex);
  if (op === "encrypt") animateBlocks(mode, plain);
}

// ─── KDF Panel ────────────────────────────────────────────────
async function handleKDF() {
  const pass = document.getElementById("kdfPass")?.value || "";
  const salt = document.getElementById("kdfSalt")?.value || "deadbeefdeadbeef";
  const iter = validateIntegerInput(
    document.getElementById("kdfIter")?.value,
    1000,
    1_000_000,
    1000,
  );
  const entropy = await runKDFPanel(pass, salt, iter);
  updateEntropyBars(entropy);
}

function updateEntropyBars(entropy) {
  const ePct = Math.min(100, (entropy / 128) * 100);
  const cPct = Math.min(100, (entropy / 70) * 100);
  const eb = document.getElementById("entropyBar");
  const cb = document.getElementById("crackBar");
  if (eb) {
    eb.style.width = ePct + "%";
    eb.className = `progress-fill${ePct < 40 ? " danger" : ePct > 70 ? " safe" : ""}`;
  }
  if (cb) {
    cb.style.width = cPct + "%";
    cb.className = `progress-fill${cPct < 50 ? " danger" : " safe"}`;
  }
  const ep = document.getElementById("entropyPct");
  if (ep) ep.textContent = entropy.toFixed(1) + " bits";
  const cp = document.getElementById("crackPct");
  if (cp)
    cp.textContent =
      entropy > 70
        ? "Practically uncrackable"
        : entropy > 40
          ? "Millions of years"
          : "Years";
}

// ─── Entropy Visualizer ───────────────────────────────────────
function calcEntropyViz(type) {
  const canvas = document.getElementById("entropyCanvas");
  const ctx = canvas?.getContext("2d");
  const input = document.getElementById("entropyInput")?.value || "Hello World";
  const out = document.getElementById("entropyStats");
  if (!ctx || !out) return;

  out.replaceChildren();
  const log = (msg, cls) => {
    const s = document.createElement("span");
    const SAFE = new Set(["", "err", "warn", "info", "muted"]);
    s.className = "t-line" + (SAFE.has(cls) ? " t-" + cls : "");
    s.textContent = String(msg);
    out.appendChild(s);
    out.appendChild(document.createElement("br"));
  };

  const raw = new TextEncoder().encode(input);
  const data =
    type === "encrypted"
      ? raw.map((b, i) => (b * 167 + i * 53 + 127) & 0xff)
      : raw;

  const freq = new Array(256).fill(0);
  data.forEach((b) => freq[b]++);
  const entropy = shannonEntropy(new Uint8Array(data));

  log(
    `[*] Mode: ${type === "encrypted" ? "Simulated encrypted" : "Raw plaintext"}`,
    "info",
  );
  log(
    `[*] Bytes: ${data.length} · Unique values: ${freq.filter((x) => x > 0).length}`,
    "muted",
  );
  log(`[✓] Shannon Entropy: ${entropy.toFixed(4)} bits/byte`, "info");
  log(
    `[*] ${entropy > 7.5 ? "⚠ HIGH — consistent with encryption" : "✓ LOW — natural/unencrypted data"}`,
    entropy > 7.5 ? "warn" : "",
  );

  // Draw histogram
  const W = 480,
    H = 180;
  ctx.clearRect(0, 0, W, H);
  const max = Math.max(...freq, 1);
  const bw = W / 256;
  freq.forEach((count, i) => {
    const h = (count / max) * 140;
    ctx.fillStyle =
      type === "encrypted"
        ? `hsla(${260 + i * 0.4}, 75%, 65%, 0.8)`
        : `hsla(${145 + i * 0.3}, 60%, 55%, 0.8)`;
    ctx.fillRect(i * bw, H - 20 - h, Math.max(1, bw - 0.5), h);
  });
  ctx.fillStyle = "rgba(255,255,255,0.15)";
  ctx.fillRect(0, H - 20, W, 1);
  ctx.fillStyle = "rgba(255,255,255,0.2)";
  ctx.font = "10px DM Mono, monospace";
  ctx.fillText("0", 4, H - 5);
  ctx.fillText("255", W - 22, H - 5);
  ctx.fillText(`H = ${entropy.toFixed(3)} bits/byte`, W / 2 - 55, 16);
}

// ─── Passphrase Analyzer ──────────────────────────────────────
function analyzePW() {
  const pw = document.getElementById("pwTest")?.value || "";
  const div = document.getElementById("pwResult");
  if (!div) return;
  if (!pw) {
    div.replaceChildren();
    return;
  }

  const hasL = /[a-z]/.test(pw),
    hasU = /[A-Z]/.test(pw);
  const hasN = /[0-9]/.test(pw),
    hasS = /[^a-zA-Z0-9]/.test(pw);
  const cs =
    (hasL ? 26 : 0) + (hasU ? 26 : 0) + (hasN ? 10 : 0) + (hasS ? 32 : 0);
  const comb = Math.pow(cs, pw.length);
  const secs = comb / 1e11;

  let timeStr;
  if (secs < 1) timeStr = "Instant";
  else if (secs < 60) timeStr = `${secs.toFixed(1)}s`;
  else if (secs < 3600) timeStr = `${(secs / 60).toFixed(1)} min`;
  else if (secs < 86400) timeStr = `${(secs / 3600).toFixed(1)} hrs`;
  else if (secs < 31536000) timeStr = `${(secs / 86400).toFixed(0)} days`;
  else if (secs < 3.15e10) timeStr = `${(secs / 31536000).toFixed(0)} years`;
  else timeStr = "Centuries+";

  const entropy = calcPassEntropy(pw);
  const pct = Math.min(100, (entropy / 100) * 100);
  const [label, cls] =
    entropy < 28
      ? ["Weak", "danger"]
      : entropy < 50
        ? ["Moderate", ""]
        : entropy < 80
          ? ["Strong", "safe"]
          : ["Very Strong", "safe"];

  div.replaceChildren();
  const term = document.createElement("div");
  term.className = "terminal";
  term.style.marginBottom = "14px";
  [
    [`[*] Length: ${pw.length} · Charset: ${cs}`, "muted"],
    [`[*] Entropy: ${entropy.toFixed(1)} bits`, "info"],
    [`[*] GPU crack time (100B/s): ${timeStr}`, entropy < 50 ? "err" : "info"],
    [`[*] Verdict: ${label.toUpperCase()}`, entropy < 50 ? "err" : "info"],
  ].forEach(([msg, c]) => {
    const s = document.createElement("span");
    s.className = `t-line t-${c}`;
    s.textContent = msg;
    term.appendChild(s);
    term.appendChild(document.createElement("br"));
  });
  div.appendChild(term);

  const pf = document.createElement("div");
  pf.className = "progress-field";
  const pl = document.createElement("div");
  pl.className = "progress-labels";
  const pll = document.createElement("span");
  pll.textContent = "Strength";
  const plv = document.createElement("span");
  plv.textContent = label;
  pl.append(pll, plv);
  const pt = document.createElement("div");
  pt.className = "progress-track";
  const fill = document.createElement("div");
  fill.className = `progress-fill ${cls}`;
  fill.style.width = pct + "%";
  pt.appendChild(fill);
  pf.append(pl, pt);
  div.appendChild(pf);
}

// ─── Expose Globals (called from HTML onclick) ────────────────
// ES modules don't expose to global scope automatically.
// We selectively expose only the functions needed by inline HTML handlers.
Object.assign(window, {
  // sidebar / tabs
  toggleSidebar,
  switchTab,
  copyCmd,

  // steg
  handleEncodeUpload,
  handleDecodeUpload,
  handleCompareUpload,
  encodeMessage,
  decodeMessage,
  renderBitPlanes,
  showBitPlaneDemo,
  runChiSquare,
  updateCapacity,
  setLsbDepth: (n, btn) => setLsbDepth(n, btn, "lsbDepthCtrl"),
  setLsbDecodeDepth: (n, btn) => setLsbDecodeDepth(n, btn, "lsbDecodeCtrl"),

  // steganalysis — new
  runRSAnalysis,
  runHistogramAnalysis,
  setHistogramChannel,
  runSPAAnalysis,

  // audio steg
  handleAudioUpload,
  encodeAudioMessage,
  decodeAudioMessage,
  playAndVisualize,
  exportWAV,
  stopAudio,
  analyzeWAVMetadata,
  drawLSBBitmap,
  analyzeStereoChannels,

  // forensics
  runHexDump,
  runStringsExtract,
  runPNGChunks,
  runFileCarver,
  runMetadataExtract,

  // ctf tools
  identifyHash,
  runXORAnalyze,
  runXORWithKey,
  runCaesar, runCaesarBrute,
  runVigenere, runAtbash,
  runRailFence,
  runFrequencyAnalysis,
  runROT13,

  // crypto / AES
  setAESMode,
  runAES: (op) => handleAES(op),
  runKDF: () => handleKDF(),
  animateBlocks: () =>
    animateBlocks(
      currentAESMode,
      document.getElementById("aesPlain")?.value || "",
    ),
  runECBDemo: () =>
    runECBDemo(document.getElementById("ecbDemoPlain")?.value || ""),

  // RSA
  rsaDerive,
  rsaGenRandom,
  rsaCheckPrimes,
  rsaAutoEncrypt,
  rsaDecrypt,
  rsaSign,
  rsaVerify,

  // hashing lab
  hashRealtime,
  avalancheDemo,
  handleIntegrityFile1,
  handleIntegrityFile2,
  verifyChecksum,
  hmacGenerate,
  hmacVerifyTag,

  // entropy / password
  calcEntropy: calcEntropyViz,
  analyzePW,

  // encoding
  handleSyncEncoding: (id) => handleEncodingSync(id),

  // cracker
  handleWordlistUpload,
  startCracker,
  stopCracker,

  // landing
  enterApp
});

// ─── Landing Page Boot Sequence ───────────────────────────────
function runBootSequence() {
  const terminalOut = document.getElementById("bootTerminalOutput");
  if (!terminalOut) return;

  const lines = [
    { text: "INIT kernel secure-enclave...", class: "ok", delay: 200 },
    { text: "Loading cryptographic modules (AES-GCM, RSA, PBKDF2)...", class: "ok", delay: 600 },
    { text: "Mounting Web Workers pool for HashLab...", class: "ok", delay: 500 },
    { text: "WARNING: Unauthorized access is strictly prohibited.", class: "warn", delay: 700 },
    { text: "Establishing SECURE context bounds...", class: "ok", delay: 1000 },
    { text: "SYSTEM NOMINAL. AWAITING INITIALIZATION.", class: "ok", delay: 1400 }
  ];

  let cumulativeDelay = 0;
  lines.forEach((line) => {
    cumulativeDelay += line.delay;
    setTimeout(() => {
      const el = document.createElement("div");
      el.className = "term-line " + line.class;
      el.textContent = "> " + line.text;
      terminalOut.appendChild(el);
      terminalOut.scrollTop = terminalOut.scrollHeight;
    }, cumulativeDelay);
  });
}

function enterApp() {
  const landing = document.getElementById("landing-page");
  const mainApp = document.getElementById("mainAppWrap");

  if (landing) {
    landing.classList.add("landing-exit");
  }
  if (mainApp) {
    mainApp.classList.remove("app-hidden");
    mainApp.classList.add("app-visible");
  }
}

// ─── Init ─────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  try {
    printSecurityAudit();
    initScene();
    initCursor();
    initSidebar();
    buildChecklist();
    buildPrimeGrid();
    rsaDerive();
    handleKDF();
    calcEntropyViz("plain");
    animateBlocks("ECB", "PLAINTEXT");
    runECBDemo("ATTACKATDAWNATTACKATDAWN");
    initHashLab();
    initCrackLab();

    // Landing page sequence
    runBootSequence();
  } catch (err) {
    console.error("BOOT ERROR:", err);
  }
});
