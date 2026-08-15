/**
 * ctf_tools.js — CipherNexus v3 CTF Toolkit
 * XOR Analyzer, Hash Identifier, Classical Ciphers,
 * Frequency Analysis, Rail Fence, Vigenere, Atbash.
 */

"use strict";

import { mkLogger } from "./security.js";

// ─── Hash Identifier ──────────────────────────────────────────
const HASH_DEFS = [
    { name: "CRC-32",         len: 8,   pat: /^[0-9a-f]{8}$/i },
    { name: "MD5 / NTLM / MD4", len: 32, pat: /^[0-9a-f]{32}$/i },
    { name: "SHA-1 / RIPEMD-160", len: 40, pat: /^[0-9a-f]{40}$/i },
    { name: "MySQL 4.1+",     len: 41,  pat: /^\*[0-9A-F]{40}$/ },
    { name: "SHA-224 / SHA3-224", len: 56, pat: /^[0-9a-f]{56}$/i },
    { name: "SHA-256 / SHA3-256", len: 64, pat: /^[0-9a-f]{64}$/i },
    { name: "SHA-384 / SHA3-384", len: 96, pat: /^[0-9a-f]{96}$/i },
    { name: "SHA-512 / SHA3-512 / Whirlpool", len: 128, pat: /^[0-9a-f]{128}$/i },
    { name: "bcrypt",          len: 0,   pat: /^\$2[ayb]\$\d{2}\$.{53}$/ },
    { name: "MD5-crypt (Unix $1$)", len: 0, pat: /^\$1\$/ },
    { name: "SHA-256-crypt (Unix $5$)", len: 0, pat: /^\$5\$/ },
    { name: "SHA-512-crypt (Unix $6$)", len: 0, pat: /^\$6\$/ },
    { name: "Argon2",          len: 0,   pat: /^\$argon2/ },
    { name: "PBKDF2",          len: 0,   pat: /^pbkdf2/i },
    { name: "scrypt",          len: 0,   pat: /^\$s0\$/ },
    { name: "Django PBKDF2",   len: 0,   pat: /^pbkdf2_sha/ },
    { name: "Base64 (possible hash)", len: 0, pat: /^[A-Za-z0-9+/]{24,}={0,2}$/ },
];

export function identifyHash() {
    const input = (document.getElementById("hashIdInput")?.value || "").trim();
    const log = mkLogger("hashIdOutput");

    if (!input) { log("[ERROR] Enter a hash string.", "err"); return; }

    log(`[*] Input length: ${input.length} chars`, "muted");
    log(`[*] Character set: ${/^[0-9a-f]+$/i.test(input) ? "hex" : /^[A-Za-z0-9+/=]+$/.test(input) ? "base64-alphabet" : "mixed"}`, "muted");
    log("─".repeat(50), "muted");

    const hits = HASH_DEFS.filter(d => {
        if (d.len && input.length !== d.len) return false;
        return d.pat.test(input);
    });

    if (!hits.length) {
        log("[✗] No known format matched.", "warn");
        log(`[*] Length ${input.length} is not a standard hash length.`, "muted");
        log("[*] Might be: custom hash, salted, or encoded data.", "muted");
    } else {
        log(`[✓] ${hits.length} candidate(s):`, "safe");
        hits.forEach(h => log(`  → ${h.name}`, "safe"));
        if (hits.length > 1) {
            log("", "");
            log("[*] Multiple matches are normal for same-length algos (e.g. MD5 = NTLM = 32 hex).", "muted");
            log("[*] Context clues (source, format, surrounding data) narrow it down.", "muted");
        }
    }

    // Extra checks
    try {
        if (/^[A-Za-z0-9+/]+=*$/.test(input) && input.length % 4 === 0) {
            const dec = atob(input);
            log("", "");
            log(`[*] Valid Base64 → ${dec.length} raw bytes when decoded`, "info");
        }
    } catch {}

    if (/^\d+$/.test(input)) log("[*] All digits — could be decimal-encoded integer or timestamp.", "info");
}

// ─── XOR Analyzer ─────────────────────────────────────────────
function scoreEnglish(bytes) {
    let score = 0;
    for (const b of bytes) {
        if (b === 32) score += 6;
        else if ((b >= 65 && b <= 90) || (b >= 97 && b <= 122)) score += 3;
        else if (b >= 48 && b <= 57) score += 1;
        else if (b >= 33 && b <= 126) score += 0;
        else score -= 8;
    }
    return score;
}

function parseXORInput() {
    const raw = (document.getElementById("xorInput")?.value || "").trim();
    const fmt = document.getElementById("xorInputFormat")?.value || "hex";
    if (!raw) return null;

    try {
        if (fmt === "hex") {
            const clean = raw.replace(/\s+/g, "");
            if (!/^[0-9a-fA-F]+$/.test(clean) || clean.length % 2) return null;
            const b = new Uint8Array(clean.length / 2);
            for (let i = 0; i < clean.length; i += 2) b[i/2] = parseInt(clean.substring(i, i+2), 16);
            return b;
        } else if (fmt === "base64") {
            const bin = atob(raw);
            const b = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
            return b;
        } else {
            return new TextEncoder().encode(raw);
        }
    } catch { return null; }
}

export function runXORAnalyze() {
    const log = mkLogger("xorOutput");
    const bytes = parseXORInput();
    if (!bytes) { log("[ERROR] Invalid or empty input.", "err"); return; }

    log(`[*] ${bytes.length} bytes — brute-forcing single-byte XOR (0x00–0xFF)…`, "info");

    const results = [];
    for (let key = 0; key < 256; key++) {
        const dec = new Uint8Array(bytes.length);
        for (let i = 0; i < bytes.length; i++) dec[i] = bytes[i] ^ key;
        results.push({ key, score: scoreEnglish(dec), dec });
    }
    results.sort((a, b) => b.score - a.score);

    log("[✓] Top 5 single-byte XOR candidates:", "safe");
    results.slice(0, 5).forEach(({ key, dec }, i) => {
        const preview = Array.from(dec).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : "·").join("").slice(0, 70);
        log(`  #${i+1}  key=0x${key.toString(16).padStart(2,"0")} (${String(key).padStart(3)})  ${preview}`, i === 0 ? "safe" : "info");
    });

    if (bytes.length < 8) return;

    // Multi-byte key length detection via Hamming distance
    log("", "");
    log("[*] Testing multi-byte key lengths 2–16 (Kasiski / IC method)…", "muted");

    const kls = [];
    for (let kl = 2; kl <= Math.min(16, Math.floor(bytes.length / 4)); kl++) {
        let dist = 0, pairs = 0;
        for (let i = 0; i + kl * 2 <= bytes.length && pairs < 8; i += kl, pairs++) {
            for (let j = 0; j < kl; j++) {
                let x = bytes[i+j] ^ bytes[i+kl+j];
                while (x) { dist += x & 1; x >>= 1; }
            }
        }
        if (pairs) kls.push({ kl, norm: dist / (pairs * kl) });
    }
    kls.sort((a, b) => a.norm - b.norm);

    kls.slice(0, 4).forEach(({ kl, norm }) => {
        log(`  Key length ${kl}  normalized Hamming = ${norm.toFixed(3)}`, "muted");
    });

    if (kls.length && bytes.length >= kls[0].kl * 4) {
        const bestKL = kls[0].kl;
        log("", "");
        log(`[*] Recovering key bytes for length ${bestKL}…`, "info");
        const keyBytes = [];
        for (let pos = 0; pos < bestKL; pos++) {
            const col = [];
            for (let i = pos; i < bytes.length; i += bestKL) col.push(bytes[i]);
            const colU8 = new Uint8Array(col);
            let best = { k: 0, s: -Infinity };
            for (let k = 0; k < 256; k++) {
                const dec = colU8.map(b => b ^ k);
                const s = scoreEnglish(dec);
                if (s > best.s) best = { k, s };
            }
            keyBytes.push(best.k);
        }
        const hex = keyBytes.map(b => b.toString(16).padStart(2,"0")).join(" ");
        const str = keyBytes.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2,"0")}`).join("");
        log(`  Probable key (hex): ${hex}`, "safe");
        log(`  Probable key (str): ${str}`, "safe");
        const dec = new Uint8Array(bytes.length);
        for (let i = 0; i < bytes.length; i++) dec[i] = bytes[i] ^ keyBytes[i % bestKL];
        const preview = Array.from(dec).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : "·").join("").slice(0, 100);
        log(`  Preview: ${preview}`, "info");
    }
}

export function runXORWithKey() {
    const log = mkLogger("xorOutput");
    const bytes = parseXORInput();
    const keyRaw = (document.getElementById("xorKey")?.value || "").trim();
    if (!bytes) { log("[ERROR] Invalid or empty input.", "err"); return; }
    if (!keyRaw) { log("[ERROR] Enter a key.", "err"); return; }

    let keyBytes;
    const hexClean = keyRaw.replace(/\s+/g, "");
    if (/^[0-9a-fA-F]+$/.test(hexClean) && hexClean.length % 2 === 0 && keyRaw.includes(" ") || hexClean.length === 2) {
        keyBytes = new Uint8Array(hexClean.length/2);
        for (let i = 0; i < hexClean.length; i+=2) keyBytes[i/2] = parseInt(hexClean.substring(i,i+2), 16);
        log(`[*] Key (hex): ${hexClean}`, "muted");
    } else {
        keyBytes = new TextEncoder().encode(keyRaw);
        log(`[*] Key (str): "${keyRaw}"`, "muted");
    }

    const out = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ keyBytes[i % keyBytes.length];

    const ascii = Array.from(out).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : "·").join("");
    const hex   = Array.from(out).map(b => b.toString(16).padStart(2,"0")).join(" ");
    const b64   = btoa(Array.from(out).map(b => String.fromCharCode(b)).join(""));

    log(`[✓] XOR output (${out.length} bytes):`, "safe");
    log(`  ASCII:  ${ascii}`, "info");
    log(`  Hex:    ${hex}`, "muted");
    log(`  Base64: ${b64}`, "muted");
}

// ─── Classical Ciphers ────────────────────────────────────────
export function runCaesar() {
    const text  = document.getElementById("caesarInput")?.value || "";
    const shift = parseInt(document.getElementById("caesarShift")?.value || "13", 10);
    const op    = document.getElementById("caesarOp")?.value || "encrypt";
    const log   = mkLogger("caesarOutput");

    if (!text) { log("[ERROR] Enter text.", "err"); return; }

    const s = op === "encrypt"
        ? ((shift % 26) + 26) % 26
        : (26 - ((shift % 26 + 26) % 26)) % 26;

    const result = [...text].map(ch => {
        if (ch >= "A" && ch <= "Z") return String.fromCharCode(((ch.charCodeAt(0)-65+s)%26)+65);
        if (ch >= "a" && ch <= "z") return String.fromCharCode(((ch.charCodeAt(0)-97+s)%26)+97);
        return ch;
    }).join("");

    log(`[*] Caesar | shift=${shift} | ${op}`, "info");
    log(`[✓] ${result}`, "safe");
}

export function runCaesarBrute() {
    const text = document.getElementById("caesarInput")?.value || "";
    const log  = mkLogger("caesarOutput");

    if (!text) { log("[ERROR] Enter ciphertext.", "err"); return; }

    log("[*] All 25 Caesar shifts:", "info");
    log("─".repeat(50), "muted");

    for (let shift = 1; shift <= 25; shift++) {
        const r = [...text].map(ch => {
            if (ch >= "A" && ch <= "Z") return String.fromCharCode(((ch.charCodeAt(0)-65+shift)%26)+65);
            if (ch >= "a" && ch <= "z") return String.fromCharCode(((ch.charCodeAt(0)-97+shift)%26)+97);
            return ch;
        }).join("");
        const preview = r.length > 60 ? r.slice(0,60) + "…" : r;
        log(`  ROT${String(shift).padStart(2,"0")}: ${preview}`, "muted");
    }
}

export function runVigenere() {
    const text = document.getElementById("vigenereInput")?.value || "";
    const key  = (document.getElementById("vigenereKey")?.value || "").toUpperCase().replace(/[^A-Z]/g, "");
    const op   = document.getElementById("vigenereOp")?.value || "encrypt";
    const log  = mkLogger("vigenereOutput");

    if (!text) { log("[ERROR] Enter text.", "err"); return; }
    if (!key)  { log("[ERROR] Enter a key (letters only).", "err"); return; }

    let ki = 0;
    const result = [...text].map(ch => {
        const up = ch >= "A" && ch <= "Z", lo = ch >= "a" && ch <= "z";
        if (!up && !lo) return ch;
        const base = up ? 65 : 97;
        const cv = ch.charCodeAt(0) - base;
        const kv = key.charCodeAt(ki++ % key.length) - 65;
        const sv = op === "encrypt" ? (cv + kv) % 26 : (cv - kv + 26) % 26;
        return String.fromCharCode(sv + base);
    }).join("");

    log(`[*] Vigenere | key="${key}" | ${op}`, "info");
    log(`[✓] ${result}`, "safe");
}

export function runAtbash() {
    const text = document.getElementById("atbashInput")?.value || "";
    const log  = mkLogger("atbashOutput");
    if (!text) { log("[ERROR] Enter text.", "err"); return; }

    const result = [...text].map(ch => {
        if (ch >= "A" && ch <= "Z") return String.fromCharCode(90 - (ch.charCodeAt(0) - 65));
        if (ch >= "a" && ch <= "z") return String.fromCharCode(122 - (ch.charCodeAt(0) - 97));
        return ch;
    }).join("");

    log("[*] Atbash (symmetric — A↔Z, B↔Y, …)", "info");
    log(`[✓] ${result}`, "safe");
}

export function runRailFence() {
    const text  = document.getElementById("railInput")?.value || "";
    const rails = parseInt(document.getElementById("railCount")?.value || "3", 10);
    const op    = document.getElementById("railOp")?.value || "encrypt";
    const log   = mkLogger("railOutput");

    if (!text) { log("[ERROR] Enter text.", "err"); return; }
    if (rails < 2 || rails > text.length) { log("[ERROR] Rails must be 2 – text.length.", "err"); return; }

    let result;
    if (op === "encrypt") {
        const fence = Array.from({ length: rails }, () => []);
        let rail = 0, dir = 1;
        for (const ch of text) {
            fence[rail].push(ch);
            if (rail === 0) dir = 1;
            else if (rail === rails - 1) dir = -1;
            rail += dir;
        }
        result = fence.flat().join("");
    } else {
        const len = text.length;
        const idx = [];
        let rail = 0, dir = 1;
        for (let i = 0; i < len; i++) {
            idx.push(rail);
            if (rail === 0) dir = 1; else if (rail === rails-1) dir = -1;
            rail += dir;
        }
        const sorted = idx.map((r,i) => ({r,i})).sort((a,b) => a.r-b.r || a.i-b.i);
        const out = new Array(len);
        const chars = text.split("");
        sorted.forEach(({i},j) => { out[i] = chars[j]; });
        result = out.join("");
    }

    log(`[*] Rail Fence | ${rails} rails | ${op}`, "info");
    log(`[✓] ${result}`, "safe");
}

export function runFrequencyAnalysis() {
    const text  = (document.getElementById("freqInput")?.value || "").toUpperCase().replace(/[^A-Z]/g,"");
    const log   = mkLogger("freqOutput");
    if (!text) { log("[ERROR] Enter text.", "err"); return; }

    const counts = {};
    for (const ch of text) counts[ch] = (counts[ch] || 0) + 1;
    const sorted = Object.entries(counts).sort((a,b) => b[1]-a[1]);
    const total  = text.length;
    const maxCnt = sorted[0]?.[1] || 1;

    log(`[*] Frequency Analysis — ${total} letters`, "info");
    log("[*] English order: E T A O I N S H R D L C U M W F G Y P B V K J X Q Z", "muted");
    log("─".repeat(55), "muted");

    sorted.forEach(([ch, cnt]) => {
        const pct = (cnt / total * 100).toFixed(1);
        const bar = "█".repeat(Math.round(cnt / maxCnt * 28));
        log(`  ${ch}  ${bar.padEnd(28)}  ${cnt.toString().padStart(4)}  ${pct}%`, "info");
    });
    log("─".repeat(55), "muted");
    log(`[*] Most frequent: ${sorted.slice(0,5).map(([c])=>c).join(" ")}`, "info");
    log("[*] Compare to E T A O I for substitution cipher hints.", "muted");
}

export function runROT13() {
    const text = document.getElementById("rot13Input")?.value || "";
    const log  = mkLogger("rot13Output");
    if (!text) { log("[ERROR] Enter text.", "err"); return; }

    const result = [...text].map(ch => {
        if (ch >= "A" && ch <= "Z") return String.fromCharCode(((ch.charCodeAt(0)-65+13)%26)+65);
        if (ch >= "a" && ch <= "z") return String.fromCharCode(((ch.charCodeAt(0)-97+13)%26)+97);
        return ch;
    }).join("");

    log("[*] ROT13 (symmetric)", "info");
    log(`[✓] ${result}`, "safe");
}
