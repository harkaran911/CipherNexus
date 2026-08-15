/**
 * ui.js — StegoVault v3 UI Layer
 * Cursor, sidebar toggle, tab switching,
 * AES block animations, prime grid rendering.
 * Imports security utilities for all DOM operations.
 */

"use strict";

import {
  sanitizeLocalStorage,
  safeWriteLocalStorage,
  safeClipboard,
  sanitizePrintable,
} from "./security.js";
import { onTabSwitch } from "./scene.js";

// ─── Custom Cursor ────────────────────────────────────────────
let mouseX = 0,
  mouseY = 0,
  ringX = 0,
  ringY = 0;
let cursorDot, cursorRing;

export function initCursor() {
  // Skip custom cursor on touch devices
  if (window.matchMedia("(pointer: coarse)").matches) return;

  cursorDot = document.getElementById("cursorDot");
  cursorRing = document.getElementById("cursorRing");

  document.addEventListener(
    "mousemove",
    (e) => {
      mouseX = e.clientX;
      mouseY = e.clientY;
      if (cursorDot) {
        cursorDot.style.left = mouseX + "px";
        cursorDot.style.top = mouseY + "px";
      }
    },
    { passive: true },
  );

  requestAnimationFrame(animCursor);
}

function animCursor() {
  ringX += (mouseX - ringX) * 0.12;
  ringY += (mouseY - ringY) * 0.12;
  if (cursorRing) {
    cursorRing.style.left = ringX + "px";
    cursorRing.style.top = ringY + "px";
  }
  requestAnimationFrame(animCursor);
}

// ─── Sidebar ──────────────────────────────────────────────────
export function initSidebar() {
  const saved = sanitizeLocalStorage("sv_sidebar");
  if (saved === "0") {
    document.getElementById("sidebar")?.classList.add("collapsed");
    document.getElementById("sidebarToggle")?.classList.add("collapsed");
  }
}

export function toggleSidebar() {
  const sb = document.getElementById("sidebar");
  const btn = document.getElementById("sidebarToggle");
  if (!sb || !btn) return;
  const collapsed = sb.classList.toggle("collapsed");
  btn.classList.toggle("collapsed", collapsed);
  safeWriteLocalStorage("sv_sidebar", collapsed ? "0" : "1");
}

// ─── Mobile Sidebar Drawer ────────────────────────────────────
export function toggleMobileSidebar() {
  const sb = document.getElementById("sidebar");
  const backdrop = document.getElementById("sidebarBackdrop");
  if (!sb || !backdrop) return;
  const isOpen = sb.classList.toggle("mobile-open");
  backdrop.classList.toggle("show", isOpen);
  document.body.style.overflow = isOpen ? "hidden" : "";
}

function closeMobileSidebar() {
  const sb = document.getElementById("sidebar");
  const backdrop = document.getElementById("sidebarBackdrop");
  if (!sb || !backdrop) return;
  sb.classList.remove("mobile-open");
  backdrop.classList.remove("show");
  document.body.style.overflow = "";
}

// ─── Tab Switching ────────────────────────────────────────────
export function switchTab(id, el) {
  document
    .querySelectorAll(".tab-panel")
    .forEach((p) => p.classList.remove("active"));
  document
    .querySelectorAll(".nav-item")
    .forEach((n) => n.classList.remove("active"));
  const panel = document.getElementById("tab-" + id);
  if (panel) panel.classList.add("active");
  if (el) el.classList.add("active");
  // Close mobile drawer after navigation
  closeMobileSidebar();
  // Fire Three.js transition effect
  onTabSwitch(id);
}

// ─── AES Block Visualizer ─────────────────────────────────────
const ALLOWED_CELL_CLS = new Set([
  "plain",
  "cipher",
  "iv",
  "xored",
  "ecb-repeat",
  "block-arrow",
]);

function makeBlockCell(text, cls, delay = 0) {
  const div = document.createElement("div");
  const safeCls = cls
    .split(" ")
    .filter((c) => ALLOWED_CELL_CLS.has(c))
    .join(" ");
  div.className = `block-cell ${safeCls}`;
  div.textContent = sanitizePrintable(String(text)).substring(0, 6);
  div.style.animationDelay = delay + "ms";
  div.title = sanitizePrintable(String(text)).substring(0, 80);
  return div;
}

const ARROW = () => {
  const d = document.createElement("div");
  d.className = "block-cell block-arrow";
  d.textContent = "→";
  return d;
};

export function animateBlocks(mode, plaintext) {
  const viz = document.getElementById("blockViz");
  if (!viz) return;
  const plain = sanitizePrintable(plaintext || "PLAINTEXT").slice(0, 128);
  const blockStrs = [];
  for (let i = 0; i < plain.length && blockStrs.length < 6; i += 8)
    blockStrs.push(plain.slice(i, i + 8).padEnd(8, "·"));

  viz.replaceChildren();

  if (mode === "ECB") {
    blockStrs.forEach((b, i) => {
      viz.appendChild(makeBlockCell(b, "plain", i * 60));
      viz.appendChild(ARROW());
      const isRepeat = blockStrs.indexOf(b) < i;
      viz.appendChild(
        makeBlockCell(
          "C" + (i + 1) + "···",
          isRepeat ? "cipher ecb-repeat" : "cipher",
          i * 60 + 120,
        ),
      );
    });
  } else if (mode === "CBC") {
    viz.appendChild(makeBlockCell("IV", "iv"));
    blockStrs.forEach((b, i) => {
      viz.appendChild(makeBlockCell("⊕", "block-arrow"));
      viz.appendChild(makeBlockCell(b, "xored", i * 80));
      viz.appendChild(ARROW());
      viz.appendChild(makeBlockCell("AES", "plain", i * 80 + 80));
      viz.appendChild(ARROW());
      viz.appendChild(makeBlockCell("C" + (i + 1), "cipher", i * 80 + 160));
    });
  } else if (mode === "CTR") {
    [
      ["Nonce+0", "iv"],
      ["→", "block-arrow"],
      ["AES", "plain"],
      ["⊕", "block-arrow"],
      ["P1", "xored"],
      ["=", "block-arrow"],
      ["C1", "cipher"],
      ["  ", "block-arrow"],
      ["Nonce+1", "iv"],
      ["→", "block-arrow"],
      ["AES", "plain"],
      ["⊕", "block-arrow"],
      ["P2", "xored"],
      ["=", "block-arrow"],
      ["C2", "cipher"],
    ].forEach(([t, c], i) => viz.appendChild(makeBlockCell(t, c, i * 40)));
  } else {
    // GCM
    [
      ["Nonce", "iv"],
      ["→", "block-arrow"],
      ["AES", "plain"],
      ["⊕", "block-arrow"],
      ["P1·P2", "xored"],
      ["=", "block-arrow"],
      ["C", "cipher"],
      ["+", "block-arrow"],
      ["AuthTag", "iv"],
    ].forEach(([t, c], i) => viz.appendChild(makeBlockCell(t, c, i * 50)));
  }

  // Stagger reveal animation
  let delay = 0;
  viz.querySelectorAll(".block-cell").forEach((cell) => {
    cell.style.opacity = "0";
    cell.style.transform = "scale(0.7)";
    setTimeout(() => {
      cell.style.opacity = "1";
      cell.style.transform = "scale(1)";
      cell.style.transition = "all 0.35s cubic-bezier(0.34,1.56,0.64,1)";
    }, delay);
    delay += 60;
  });
}

// ─── ECB Pattern Demo ─────────────────────────────────────────
export function runECBDemo(plaintext) {
  const plain = sanitizePrintable(plaintext || "AABBCCAABBCC").slice(0, 64);
  const ecb = document.getElementById("ecbBlocks");
  const cbc = document.getElementById("cbcBlocks");
  if (!ecb || !cbc) return;
  ecb.replaceChildren();
  cbc.replaceChildren();

  const makeB = (text, cls) => {
    const d = document.createElement("div");
    d.className = `block-cell ${cls}`;
    d.textContent = sanitizePrintable(String(text)).substring(0, 5);
    return d;
  };

  for (let i = 0; i < plain.length; i += 4) {
    const chunk = plain.slice(i, i + 4);
    const seen = plain.slice(0, i).includes(chunk) && chunk.length === 4;
    ecb.appendChild(makeB(chunk, seen ? "ecb-repeat" : "cipher"));
  }

  let prev = 42;
  for (let i = 0; i < plain.length; i += 4) {
    const chunk = plain.slice(i, i + 4);
    const hash =
      (chunk.split("").reduce((a, c) => a + c.charCodeAt(0), 0) ^
        prev ^
        (i * 7)) %
      256;
    prev = hash;
    const d = document.createElement("div");
    d.className = "block-cell cipher";
    d.textContent = hash.toString(16).padStart(2, "0") + "··";
    cbc.appendChild(d);
  }
}

// ─── Prime Grid ───────────────────────────────────────────────
function isPrime(n) {
  if (n < 2) return false;
  if (n < 4) return true;
  if (n % 2 === 0 || n % 3 === 0) return false;
  for (let i = 5; i * i <= n; i += 6)
    if (n % i === 0 || n % (i + 2) === 0) return false;
  return true;
}

export function buildPrimeGrid() {
  const grid = document.getElementById("primeGrid");
  if (!grid) return;
  grid.replaceChildren();
  for (let i = 2; i <= 100; i++) {
    const b = document.createElement("div");
    b.className = "rsa-prime-badge";
    if (!isPrime(i)) {
      b.style.opacity = "0.2";
      b.style.filter = "grayscale(1)";
    }
    b.textContent = i;
    grid.appendChild(b);
  }
}

// ─── Copy Command ─────────────────────────────────────────────
export function copyCmd(btn) {
  const cmdEl = btn.previousElementSibling;
  if (!cmdEl) return;
  safeClipboard(cmdEl.textContent)
    .then(() => {
      const orig = btn.textContent;
      btn.textContent = "Copied!";
      btn.style.color = "var(--sage)";
      setTimeout(() => {
        btn.textContent = orig;
        btn.style.color = "";
      }, 1500);
    })
    .catch((err) => {
      btn.textContent = "Error";
      btn.style.color = "var(--danger)";
      setTimeout(() => {
        btn.textContent = "Copy";
        btn.style.color = "";
      }, 2000);
      console.warn("Clipboard blocked:", err);
    });
}

// ─── Checklist Builder ────────────────────────────────────────
const CHECKLIST = [
  {
    tool: "strings / xxd",
    action: "Check for readable text at EOF or in headers",
    badge: "badge-sage",
    label: "Quick Win",
  },
  {
    tool: "exiftool",
    action: "Dump all EXIF metadata — Comment, UserComment fields",
    badge: "badge-sage",
    label: "Quick Win",
  },
  {
    tool: "file + binwalk",
    action: "Identify file type, scan for embedded signatures",
    badge: "badge-sage",
    label: "Quick Win",
  },
  {
    tool: "pngcheck -v",
    action:
      "Validate PNG structure — inspect auxiliary chunks (tEXt, iTXt, zTXt)",
    badge: "badge-sage",
    label: "Quick Win",
  },
  {
    tool: "binwalk -e",
    action: "Extract all embedded files from signature scan",
    badge: "badge-cyan",
    label: "Extract",
  },
  {
    tool: "foremost -i",
    action: "Carve embedded files by header/footer signatures",
    badge: "badge-cyan",
    label: "Extract",
  },
  {
    tool: "steghide extract",
    action: "Try blank passphrase extraction on JPEG/BMP",
    badge: "badge-cyan",
    label: "Extract",
  },
  {
    tool: "stegseek",
    action: "Wordlist attack against steghide-protected images",
    badge: "badge-rose",
    label: "Attack",
  },
  {
    tool: "jsteg reveal",
    action: "Extract data hidden in JPEG DCT coefficients",
    badge: "badge-cyan",
    label: "Extract",
  },
  {
    tool: "outguess -r",
    action: "Extract OutGuess-embedded data from JPEG",
    badge: "badge-cyan",
    label: "Extract",
  },
  {
    tool: "zsteg -a",
    action: "Automated LSB analysis across all channels and planes",
    badge: "badge-amber",
    label: "Analyze",
  },
  {
    tool: "Chi-Square test",
    action: "Statistical analysis — equalized pairs = LSB steg",
    badge: "badge-amber",
    label: "Analyze",
  },
  {
    tool: "RS Analysis",
    action: "Regular-Singular group analysis — detects LSB modification rate",
    badge: "badge-amber",
    label: "Analyze",
  },
  {
    tool: "Sonic Visualiser",
    action: "Spectrogram analysis for audio steganography (WAV/MP3)",
    badge: "badge-lilac",
    label: "Audio",
  },
  {
    tool: "stegoveritas",
    action: "All-in-one steganalysis framework — runs everything",
    badge: "badge-muted",
    label: "Auto",
  },
];

export function buildChecklist() {
  const container = document.getElementById("checklist");
  if (!container) return;
  container.replaceChildren();
  CHECKLIST.forEach((item, i) => {
    const row = document.createElement("div");
    row.className = "checklist-item";
    const num = document.createElement("span");
    num.className = "cl-num";
    num.textContent = String(i + 1).padStart(2, "0");
    const tool = document.createElement("span");
    tool.className = "cl-tool";
    tool.textContent = item.tool;
    const action = document.createElement("span");
    action.className = "cl-action";
    action.textContent = item.action;
    const badge = document.createElement("span");
    badge.className = `badge ${item.badge}`;
    badge.textContent = item.label;
    row.append(num, tool, action, badge);
    container.appendChild(row);
  });
}
