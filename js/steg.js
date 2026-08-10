/**
 * steg.js — StegoVault v3 Steganography Layer
 *
 * LSB encode/decode hot-loop runs in WebAssembly for ~10× speedup.
 * The WASM module is compiled inline (base64) — no external build step.
 * Falls back to pure JS if WASM is unavailable.
 *
 * Imports security utilities for all validation + DOM output.
 */

'use strict';

import {
    mkLogger, validateImageFile, validateImageDimensions,
    setImgSrc, html
} from './security.js';

import {
    initWasm, wasmEncode, wasmDecode, isWasmReady,
    MAX_PIXEL_BYTES
} from '../wasm/steg_core.js';

// WASM module kicks off initialisation on import (non-blocking).
// isWasmReady() returns true once loaded. Encode/decode check automatically.

// ─── Pure-JS LSB fallback ─────────────────────────────────────
function jsFallbackEncode(data, msgBits, depth) {
    const mask = 0xFF & (0xFF << depth);
    let bi = 0;
    for (let i = 0; i < data.length && bi < msgBits.length; i++) {
        if ((i + 1) % 4 === 0) continue;
        let slot = 0;
        for (let b = 0; b < depth && bi < msgBits.length; b++, bi++)
            slot = (slot << 1) | msgBits[bi];
        data[i] = (data[i] & mask) | slot;
    }
}

function jsFallbackDecode(data, depth) {
    const mask = (1 << depth) - 1;
    const bits = [];
    for (let i = 0; i < data.length; i++) {
        if ((i + 1) % 4 === 0) continue;
        const slot = data[i] & mask;
        for (let b = depth - 1; b >= 0; b--)
            bits.push((slot >> b) & 1);
    }
    return bits;
}

// ─── XOR Cipher (key schedule) ───────────────────────────────
function xorBytes(bytes, key) {
    if (!key || key.length === 0) return bytes;
    const keyBytes = new TextEncoder().encode(key);
    return bytes.map((b, i) => b ^ keyBytes[i % keyBytes.length]);
}

// ─── LSB State ────────────────────────────────────────────────
let lsbDepth = 1;
let lsbDecodeDepth = 1;
let encodeImg = null;
let decodeImg = null;
let compareOrig = null;
let compareSteg = null;

export const getLsbDepth = () => lsbDepth;
export const getLsbDecodeDepth = () => lsbDecodeDepth;

// ─── Segmented Control ────────────────────────────────────────
export function setLsbDepth(n, btn, ctrlId) {
    lsbDepth = n;
    document.querySelectorAll(`#${ctrlId} .seg-btn`).forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    updateCapacity();
}

export function setLsbDecodeDepth(n, btn, ctrlId) {
    lsbDecodeDepth = n;
    document.querySelectorAll(`#${ctrlId} .seg-btn`).forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
}

// ─── Capacity Bar ─────────────────────────────────────────────
export function updateCapacity() {
    const msgEl = document.getElementById('secretMsg');
    const fill = document.getElementById('capFill');
    const val = document.getElementById('capValue');
    const warn = document.getElementById('capWarn');
    if (!fill || !val || !warn) return;

    if (!encodeImg) {
        fill.style.width = '0%'; val.textContent = '—'; warn.classList.remove('show'); return;
    }

    const pixels = encodeImg.width * encodeImg.height;
    const maxBytes = Math.floor((pixels * 3 * lsbDepth) / 8) - 1;
    const msgBytes = new TextEncoder().encode(msgEl?.value || '').length;
    const pct = Math.min(100, (msgBytes / maxBytes) * 100);

    fill.style.width = pct + '%';
    fill.className = 'capacity-fill' + (pct > 90 ? ' danger' : pct > 70 ? ' warn' : '');
    val.textContent = `${msgBytes.toLocaleString()} / ${maxBytes.toLocaleString()} bytes (${pct.toFixed(1)}%)`;
    val.style.color = pct > 90 ? 'var(--danger)' : pct > 70 ? 'var(--warn)' : 'var(--sage)';
    warn.classList.toggle('show', msgBytes > maxBytes);
}

// ─── Upload Handlers ──────────────────────────────────────────
export function handleEncodeUpload(input) {
    const f = input.files[0]; if (!f) return;
    validateImageFile(f).then(res => {
        if (!res.valid) {
            const log = mkLogger('encodeOutput');
            log('[SECURITY] ' + res.error, 'err');
            input.value = ''; return;
        }
        const r = new FileReader();
        r.onload = e => {
            setImgSrc('encodePreview', e.target.result);
            const img = new Image();
            img.onload = () => { encodeImg = img; updateCapacity(); };
            img.src = e.target.result;
        };
        r.onerror = () => mkLogger('encodeOutput')('[ERROR] File read failed.', 'err');
        r.readAsDataURL(f);
    });
}

export function handleDecodeUpload(input) {
    const f = input.files[0]; if (!f) return;
    validateImageFile(f).then(res => {
        if (!res.valid) {
            const log = mkLogger('decodeOutput');
            log('[SECURITY] ' + res.error, 'err');
            input.value = ''; return;
        }
        const r = new FileReader();
        r.onload = e => {
            setImgSrc('decodePreview', e.target.result);
            const img = new Image();
            img.onload = () => decodeImg = img;
            img.src = e.target.result;
        };
        r.onerror = () => mkLogger('decodeOutput')('[ERROR] File read failed.', 'err');
        r.readAsDataURL(f);
    });
}

export function handleCompareUpload(type, input) {
    const f = input.files[0]; if (!f) return;
    const safeType = (type === 'orig' || type === 'steg') ? type : null;
    if (!safeType) return;
    validateImageFile(f).then(res => {
        if (!res.valid) { alert('[Security] ' + res.error); input.value = ''; return; }
        const r = new FileReader();
        r.onload = e => {
            const img = new Image();
            img.onload = () => { if (safeType === 'orig') compareOrig = img; else compareSteg = img; runCompare(); };
            img.src = e.target.result;
        };
        r.onerror = () => alert('[ERROR] File read failed.');
        r.readAsDataURL(f);
    });
}

// ─── Compare View ─────────────────────────────────────────────
export function runCompare() {
    if (!compareOrig || !compareSteg) return;
    for (const im of [compareOrig, compareSteg])
        if (!validateImageDimensions(im)) return;

    document.getElementById('compareWrap').style.display = 'grid';

    const W = Math.min(compareOrig.width, compareSteg.width, 400);
    const H = Math.min(compareOrig.height, compareSteg.height, 220);

    const oc = document.getElementById('compareOrigCanvas');
    oc.width = W; oc.height = H;
    const octx = oc.getContext('2d'); octx.drawImage(compareOrig, 0, 0, W, H);

    const sc = document.getElementById('compareStegCanvas');
    sc.width = W; sc.height = H;
    const sctx = sc.getContext('2d'); sctx.drawImage(compareSteg, 0, 0, W, H);

    const oData = octx.getImageData(0, 0, W, H);
    const sData = sctx.getImageData(0, 0, W, H);
    const diff = sctx.createImageData(W, H);
    let diffCount = 0;

    for (let i = 0; i < oData.data.length; i += 4) {
        const dr = Math.abs(oData.data[i] - sData.data[i]);
        const dg = Math.abs(oData.data[i + 1] - sData.data[i + 1]);
        const db = Math.abs(oData.data[i + 2] - sData.data[i + 2]);
        const changed = dr > 0 || dg > 0 || db > 0;
        if (changed) diffCount++;
        diff.data[i] = changed ? Math.min(255, dr * 10 + 160) : sData.data[i];
        diff.data[i + 1] = changed ? Math.min(80, dg * 5) : sData.data[i + 1];
        diff.data[i + 2] = changed ? Math.min(80, db * 5) : sData.data[i + 2];
        diff.data[i + 3] = 255;
    }
    sctx.putImageData(diff, 0, 0);

    const badge = document.getElementById('diffBadge');
    if (badge) badge.textContent = `${diffCount.toLocaleString()} px modified (${((diffCount / (W * H)) * 100).toFixed(2)}%)`;
}

// ─── LSB Encode ───────────────────────────────────────────────
export async function encodeMessage() {
    const log = mkLogger('encodeOutput');
    if (!encodeImg) { log('[ERROR] No cover image loaded.', 'err'); return; }
    if (!validateImageDimensions(encodeImg)) { log('[SECURITY] Invalid image dimensions.', 'err'); return; }

    const msg = document.getElementById('secretMsg')?.value || '';
    const key = (document.getElementById('encodeKey')?.value || '').slice(0, 256);
    const bits = lsbDepth;

    if (!msg) { log('[ERROR] No message to encode.', 'err'); return; }
    if (msg.length > 100_000) { log('[SECURITY] Message too long (max 100,000 chars).', 'err'); return; }

    log(`[*] Starting ${bits}-bit LSB encoding… (${isWasmReady() ? 'WASM' : 'JS fallback'})`, 'info');
    log(`[*] Cover image: ${encodeImg.width}×${encodeImg.height}px`, 'muted');

    // Draw image to canvas
    const canvas = document.createElement('canvas');
    canvas.width = encodeImg.width;
    canvas.height = encodeImg.height;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(encodeImg, 0, 0);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imageData.data; // Uint8ClampedArray

    // Build message bits
    const msgBytes = new TextEncoder().encode(msg);
    const xored = xorBytes(msgBytes, key);
    const withNull = new Uint8Array([...xored, 0]); // null terminator
    const msgBitsArr = [];
    for (const byte of withNull)
        for (let b = 7; b >= 0; b--) msgBitsArr.push((byte >> b) & 1);
    const msgBits = new Uint8Array(msgBitsArr);

    const maxSlots = Math.floor((data.length / 4) * 3);
    const needed = Math.ceil(msgBits.length / bits);
    if (needed > maxSlots) {
        log('[ERROR] Message too long for this image at this depth.', 'err'); return;
    }

    // Run encode — WASM if image fits in one memory page, JS fallback otherwise
    const dataArr = new Uint8Array(data.buffer.slice());
    if (isWasmReady() && data.length <= MAX_PIXEL_BYTES) {
        log(`[*] Using WASM engine (${data.length.toLocaleString()} bytes)…`, 'muted');
        const result = await wasmEncode(dataArr, msgBits, bits);
        if (result) {
            data.set(result);
        } else {
            log('[*] WASM unavailable for this image size — JS fallback', 'muted');
            jsFallbackEncode(dataArr, msgBits, bits);
            data.set(dataArr);
        }
    } else {
        if (data.length > MAX_PIXEL_BYTES)
            log(`[*] Image too large for WASM (${data.length.toLocaleString()} bytes) — JS fallback`, 'muted');
        jsFallbackEncode(dataArr, msgBits, bits);
        data.set(dataArr);
    }

    ctx.putImageData(imageData, 0, 0);

    const maxBytes = Math.floor((data.length / 4 * 3 * bits) / 8);
    log(`[✓] Encoded ${msg.length} chars via ${bits}-bit LSB`, 'info');
    log(`[✓] Key: ${key ? 'XOR-encrypted with passphrase' : 'None'}`, 'muted');
    log(`[*] Capacity used: ${((withNull.length / maxBytes) * 100).toFixed(1)}%`, 'muted');

    canvas.toBlob(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'stego_output.png'; a.click();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
        log('[✓] stego_output.png downloaded.', 'info');
    }, 'image/png');
}

// ─── LSB Decode ───────────────────────────────────────────────
export async function decodeMessage() {
    const log = mkLogger('decodeOutput');
    if (!decodeImg) { log('[ERROR] No stego image loaded.', 'err'); return; }
    if (!validateImageDimensions(decodeImg)) { log('[SECURITY] Invalid image dimensions.', 'err'); return; }

    const key = (document.getElementById('decodeKey')?.value || '').slice(0, 256);
    const bits = lsbDecodeDepth;

    log(`[*] Extracting ${bits}-bit LSB data…`, 'info');

    const canvas = document.createElement('canvas');
    canvas.width = decodeImg.width;
    canvas.height = decodeImg.height;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(decodeImg, 0, 0);
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imgData.data;
    const dataArr = new Uint8Array(data.buffer);

    // Use WASM for decode if image fits, JS fallback otherwise
    let slotBits;
    if (isWasmReady() && data.length <= MAX_PIXEL_BYTES) {
        log(`[*] Using WASM engine…`, 'muted');
        const wasmResult = await wasmDecode(dataArr, bits);
        slotBits = wasmResult ? Array.from(wasmResult) : jsFallbackDecode(dataArr, bits);
        if (!wasmResult) log('[*] WASM decode failed — JS fallback used', 'muted');
    } else {
        slotBits = jsFallbackDecode(dataArr, bits);
        if (data.length > MAX_PIXEL_BYTES)
            log('[*] Large image — JS fallback used', 'muted');
    }

    // Reassemble bytes
    let msgBytes = [];
    for (let i = 0; i < slotBits.length; i += 8) {
        const byte = slotBits.slice(i, i + 8).reduce((a, b, j) => a | (b << (7 - j)), 0);
        if (byte === 0) break;
        msgBytes.push(byte);
    }

    const decoded_raw = new Uint8Array(msgBytes);
    const decoded = key ? xorBytes(decoded_raw, key) : decoded_raw;
    const text = new TextDecoder().decode(decoded);

    if (text && text.trim()) {
        log('[✓] Extraction successful!', 'info');
        log(`[✓] Message: ${text}`, 'info');
    } else {
        log('[WARN] No readable data. Wrong depth/key or no data encoded.', 'warn');
    }
}

// ─── Bit Plane Visualizer ─────────────────────────────────────
export function renderBitPlanes(input) {
    const f = input.files[0]; if (!f) return;
    validateImageFile(f).then(res => {
        if (!res.valid) { alert('[Security] ' + res.error); input.value = ''; return; }
        const r = new FileReader();
        r.onload = e => { const img = new Image(); img.onload = () => doBitPlanes(img); img.src = e.target.result; };
        r.onerror = () => alert('[ERROR] File read failed.');
        r.readAsDataURL(f);
    });
}

export function showBitPlaneDemo() {
    const c = document.createElement('canvas'); c.width = 80; c.height = 80;
    const ctx = c.getContext('2d');
    for (let y = 0; y < 80; y++) for (let x = 0; x < 80; x++) {
        const v = (x * y) % 256;
        ctx.fillStyle = `rgb(${v},${(v * 3) % 256},${(v * 7) % 256})`;
        ctx.fillRect(x, y, 1, 1);
    }
    const id = ctx.getImageData(0, 0, 80, 80);
    for (let i = 0; i < 300; i++) id.data[i * 4] = (id.data[i * 4] & 0xFE) | (i % 2);
    ctx.putImageData(id, 0, 0);
    const img = new Image(); img.onload = () => doBitPlanes(img); img.src = c.toDataURL();
}

function doBitPlanes(img) {
    if (!validateImageDimensions(img)) { console.warn('doBitPlanes: invalid dimensions'); return; }
    const W = Math.min(img.width, 160), H = Math.min(img.height, 160);
    const src = document.createElement('canvas'); src.width = W; src.height = H;
    const sctx = src.getContext('2d'); sctx.drawImage(img, 0, 0, W, H);
    const srcData = sctx.getImageData(0, 0, W, H).data;

    const grid = document.getElementById('bitplaneGrid');
    grid.style.display = 'grid'; grid.replaceChildren();

    const labels = [
        'Red bit-0 (LSB)', 'Green bit-0', 'Blue bit-0',
        'Red bit-1', 'Green bit-1', 'Blue bit-1',
        'Red bit-7 (MSB)', 'Green bit-7', 'Blue bit-7'
    ];

    [[0, 0], [1, 0], [2, 0], [0, 1], [1, 1], [2, 1], [0, 7], [1, 7], [2, 7]].forEach(([ch, bit], idx) => {
        const c = document.createElement('canvas'); c.width = W; c.height = H;
        const ctx = c.getContext('2d');
        const id = ctx.createImageData(W, H);
        for (let i = 0; i < W * H; i++) {
            const v = ((srcData[i * 4 + ch] >> bit) & 1) * 255;
            id.data[i * 4] = id.data[i * 4 + 1] = id.data[i * 4 + 2] = v; id.data[i * 4 + 3] = 255;
        }
        ctx.putImageData(id, 0, 0);

        const div = document.createElement('div'); div.className = 'bitplane-cell';
        const lbl = document.createElement('div'); lbl.className = 'bp-label';
        lbl.textContent = labels[idx];
        lbl.style.color = bit === 0 ? 'var(--amber)' : 'var(--text3)';
        div.appendChild(c); div.appendChild(lbl);
        grid.appendChild(div);
    });
}

// ─── Chi-Square Detection ─────────────────────────────────────
export function runChiSquare(input) {
    const f = input.files[0]; if (!f) return;
    validateImageFile(f).then(res => {
        if (!res.valid) {
            const out = document.getElementById('chiOutput');
            out.style.display = 'block'; out.replaceChildren();
            const term = document.createElement('div'); term.className = 'terminal';
            const s = document.createElement('span'); s.className = 't-line t-err';
            s.textContent = '[SECURITY] ' + res.error;
            term.appendChild(s); out.appendChild(term);
            input.value = ''; return;
        }
        const r = new FileReader();
        r.onload = e => {
            const img = new Image();
            img.onload = () => {
                if (!validateImageDimensions(img)) return;

                const canvas = document.createElement('canvas');
                canvas.width = img.width; canvas.height = img.height;
                const ctx = canvas.getContext('2d'); ctx.drawImage(img, 0, 0);
                const data = ctx.getImageData(0, 0, img.width, img.height).data;

                const freq = new Array(256).fill(0);
                for (let i = 0; i < data.length; i += 4) freq[data[i]]++;

                let chi = 0, n = 0;
                for (let v = 0; v < 255; v += 2) {
                    const obs = freq[v] + freq[v + 1], exp = obs / 2;
                    if (exp > 0) { chi += Math.pow(freq[v] - exp, 2) / exp + Math.pow(freq[v + 1] - exp, 2) / exp; n++; }
                }
                const avgChi = chi / n;
                const suspicious = avgChi < 2.0;
                const prob = Math.max(0, Math.min(100, 100 - (avgChi / 5) * 100));

                // Build output via DOM API — no innerHTML with user data
                const out = document.getElementById('chiOutput');
                out.style.display = 'block'; out.replaceChildren();

                const term = document.createElement('div'); term.className = 'terminal'; term.style.marginBottom = '14px';
                [
                    [`[*] Chi-Square Analysis Complete`, 'info'],
                    [`[*] Image: ${img.width}×${img.height} · ${(f.size / 1024).toFixed(1)} KB`, 'muted'],
                    [`[*] Chi² value: ${avgChi.toFixed(4)}`, suspicious ? 'err' : ''],
                    [`[*] Verdict: ${suspicious ? '⚠ LIKELY CONTAINS HIDDEN DATA' : '✓ No anomaly detected'}`, suspicious ? 'err' : 'info'],
                ].forEach(([msg, cls]) => {
                    const s = document.createElement('span');
                    s.className = 't-line' + (cls ? ' t-' + cls : '');
                    s.textContent = msg;
                    term.appendChild(s); term.appendChild(document.createElement('br'));
                });
                out.appendChild(term);

                const pf = document.createElement('div'); pf.className = 'progress-field';
                const pl = document.createElement('div'); pl.className = 'progress-labels';
                const pll = document.createElement('span'); pll.textContent = 'Steg Probability';
                const plv = document.createElement('span'); plv.textContent = prob.toFixed(1) + '%';
                pl.append(pll, plv);
                const pt = document.createElement('div'); pt.className = 'progress-track';
                const fill = document.createElement('div');
                fill.className = 'capacity-fill ' + (prob > 60 ? 'danger' : prob > 30 ? 'warn' : '');
                fill.style.width = prob + '%';
                pt.appendChild(fill); pf.append(pl, pt); out.appendChild(pf);

                const row = document.createElement('div'); row.style.cssText = 'margin-top:10px;display:flex;gap:8px';
                const b1 = document.createElement('span'); b1.className = `badge ${suspicious ? 'badge-rose' : 'badge-sage'}`; b1.textContent = suspicious ? 'SUSPICIOUS' : 'CLEAN';
                const b2 = document.createElement('span'); b2.className = 'badge badge-muted'; b2.textContent = `χ² = ${avgChi.toFixed(3)}`;
                row.append(b1, b2); out.appendChild(row);
            };
            img.src = e.target.result;
        };
        r.onerror = () => alert('[ERROR] File read failed.');
        r.readAsDataURL(f);
    });
}

// ─── RS (Regular-Singular) Analysis ───────────────────────────
export function runRSAnalysis(input) {
    const f = input.files[0]; if (!f) return;
    validateImageFile(f).then(res => {
        if (!res.valid) {
            const out = document.getElementById('rsOutput');
            if (out) { out.style.display = 'block'; out.replaceChildren(); }
            alert('[Security] ' + res.error); input.value = ''; return;
        }
        const r = new FileReader();
        r.onload = e => {
            const img = new Image();
            img.onload = () => {
                if (!validateImageDimensions(img)) return;
                _doRSAnalysis(img, f);
            };
            img.src = e.target.result;
        };
        r.onerror = () => alert('[ERROR] File read failed.');
        r.readAsDataURL(f);
    });
}

function _doRSAnalysis(img, file) {
    const W = Math.min(img.width, 1024), H = Math.min(img.height, 1024);
    const canvas = document.createElement('canvas'); canvas.width = W; canvas.height = H;
    const ctx = canvas.getContext('2d'); ctx.drawImage(img, 0, 0, W, H);
    const data = ctx.getImageData(0, 0, W, H).data;

    // RS analysis on red channel with groups of 4
    const groupSize = 4;
    let R_pos = 0, S_pos = 0, R_neg = 0, S_neg = 0;

    function smoothness(group) {
        let sum = 0;
        for (let i = 1; i < group.length; i++) sum += Math.abs(group[i] - group[i - 1]);
        return sum;
    }

    function flipPositive(val) { return (val % 2 === 0) ? val + 1 : val - 1; }
    function flipNegative(val) {
        const v = flipPositive(val);
        return (v === val + 1) ? val - 1 : val + 1;
    }

    const mask = [0, 1, 1, 0]; // Flipping mask

    for (let i = 0; i < data.length - groupSize * 4; i += groupSize * 4) {
        const group = [];
        for (let j = 0; j < groupSize; j++) group.push(data[i + j * 4]); // Red channel

        const S0 = smoothness(group);

        // Positive flip
        const gPos = group.map((v, k) => mask[k] ? flipPositive(v) : v);
        const SP = smoothness(gPos);
        if (SP > S0) R_pos++;
        else if (SP < S0) S_pos++;

        // Negative flip
        const gNeg = group.map((v, k) => mask[k] ? flipNegative(v) : v);
        const SN = smoothness(gNeg);
        if (SN > S0) R_neg++;
        else if (SN < S0) S_neg++;
    }

    const total = R_pos + S_pos + R_neg + S_neg || 1;
    const R_pct = (R_pos / total * 100).toFixed(1);
    const S_pct = (S_pos / total * 100).toFixed(1);
    const Rn_pct = (R_neg / total * 100).toFixed(1);
    const Sn_pct = (S_neg / total * 100).toFixed(1);

    // Estimate embedding rate: d ≈ |R_pos - R_neg| / (R_pos + R_neg) simplified
    const diff = Math.abs(R_pos - R_neg);
    const sum = R_pos + R_neg || 1;
    const embedRate = Math.min(100, (1 - diff / sum) * 100);
    const suspicious = embedRate > 60;

    // Render output
    const out = document.getElementById('rsOutput');
    if (!out) return;
    out.style.display = 'block'; out.replaceChildren();

    const term = document.createElement('div'); term.className = 'terminal'; term.style.marginBottom = '14px';
    [
        [`[*] RS Analysis Complete (Red Channel)`, 'info'],
        [`[*] Image: ${img.width}×${img.height} · ${(file.size / 1024).toFixed(1)} KB`, 'muted'],
        [`[*] Groups analyzed: ${Math.floor(data.length / (groupSize * 4))}`, 'muted'],
        [`[*] R+ = ${R_pos} (${R_pct}%)  S+ = ${S_pos} (${S_pct}%)`, ''],
        [`[*] R- = ${R_neg} (${Rn_pct}%)  S- = ${S_neg} (${Sn_pct}%)`, ''],
        [`[*] R+ ≈ R- : ${Math.abs(R_pos - R_neg) < total * 0.05 ? 'YES — suspicious' : 'NO — natural'}`, suspicious ? 'err' : 'info'],
        [`[*] Estimated embedding rate: ${embedRate.toFixed(1)}%`, suspicious ? 'err' : 'info'],
        [`[*] Verdict: ${suspicious ? '⚠ LIKELY LSB MODIFIED' : '✓ Appears clean'}`, suspicious ? 'err' : 'info'],
    ].forEach(([msg, cls]) => {
        const s = document.createElement('span');
        s.className = 't-line' + (cls ? ' t-' + cls : '');
        s.textContent = msg;
        term.appendChild(s); term.appendChild(document.createElement('br'));
    });
    out.appendChild(term);

    // Draw RS bar chart
    const chartCanvas = document.createElement('canvas');
    chartCanvas.width = 360; chartCanvas.height = 160;
    chartCanvas.style.cssText = 'width:100%;max-width:360px;border-radius:8px;background:rgba(0,0,0,0.3);margin-top:8px';
    const cctx = chartCanvas.getContext('2d');

    const maxVal = Math.max(R_pos, S_pos, R_neg, S_neg, 1);
    const bars = [
        { label: 'R+', val: R_pos, color: 'rgba(110,231,183,0.8)' },
        { label: 'S+', val: S_pos, color: 'rgba(78,201,232,0.8)' },
        { label: 'R-', val: R_neg, color: 'rgba(245,166,35,0.8)' },
        { label: 'S-', val: S_neg, color: 'rgba(255,107,138,0.8)' },
    ];
    const bw = 50, gap = 25, startX = 40;
    bars.forEach((b, i) => {
        const x = startX + i * (bw + gap);
        const h = (b.val / maxVal) * 110;
        cctx.fillStyle = b.color;
        cctx.fillRect(x, 140 - h, bw, h);
        cctx.fillStyle = 'rgba(255,255,255,0.6)';
        cctx.font = '11px DM Mono, monospace';
        cctx.textAlign = 'center';
        cctx.fillText(b.label, x + bw / 2, 155);
        cctx.fillText(String(b.val), x + bw / 2, 135 - h);
    });
    out.appendChild(chartCanvas);

    // Badges
    const row = document.createElement('div'); row.style.cssText = 'margin-top:10px;display:flex;gap:8px;flex-wrap:wrap';
    const b1 = document.createElement('span'); b1.className = `badge ${suspicious ? 'badge-rose' : 'badge-sage'}`;
    b1.textContent = suspicious ? 'LIKELY MODIFIED' : 'LIKELY CLEAN';
    const b2 = document.createElement('span'); b2.className = 'badge badge-muted'; b2.textContent = `Rate: ${embedRate.toFixed(1)}%`;
    row.append(b1, b2); out.appendChild(row);
}

// ─── Histogram Analysis ───────────────────────────────────────
let _histogramChannel = 'all';

export function setHistogramChannel(ch, btn) {
    _histogramChannel = ch;
    document.querySelectorAll('#histChannelCtrl .seg-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    if (_lastHistImg) _drawHistogram(_lastHistImg);
}

let _lastHistImg = null;

export function runHistogramAnalysis(input) {
    const f = input.files[0]; if (!f) return;
    validateImageFile(f).then(res => {
        if (!res.valid) { alert('[Security] ' + res.error); input.value = ''; return; }
        const r = new FileReader();
        r.onload = e => {
            const img = new Image();
            img.onload = () => {
                if (!validateImageDimensions(img)) return;
                _lastHistImg = img;
                _drawHistogram(img);
            };
            img.src = e.target.result;
        };
        r.onerror = () => alert('[ERROR] File read failed.');
        r.readAsDataURL(f);
    });
}

function _drawHistogram(img) {
    const canvas = document.getElementById('histCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    // Get pixel data
    const src = document.createElement('canvas');
    src.width = Math.min(img.width, 800);
    src.height = Math.min(img.height, 800);
    const sctx = src.getContext('2d');
    sctx.drawImage(img, 0, 0, src.width, src.height);
    const data = sctx.getImageData(0, 0, src.width, src.height).data;

    // Build frequency arrays
    const freqR = new Array(256).fill(0);
    const freqG = new Array(256).fill(0);
    const freqB = new Array(256).fill(0);
    for (let i = 0; i < data.length; i += 4) {
        freqR[data[i]]++;
        freqG[data[i + 1]]++;
        freqB[data[i + 2]]++;
    }

    const ch = _histogramChannel;
    const channels = [];
    if (ch === 'all' || ch === 'r') channels.push({ freq: freqR, color: 'rgba(255,80,80,0.7)', label: 'Red' });
    if (ch === 'all' || ch === 'g') channels.push({ freq: freqG, color: 'rgba(80,255,120,0.7)', label: 'Green' });
    if (ch === 'all' || ch === 'b') channels.push({ freq: freqB, color: 'rgba(80,140,255,0.7)', label: 'Blue' });

    const allFreqs = channels.flatMap(c => c.freq);
    const maxFreq = Math.max(...allFreqs, 1);
    const bw = W / 256;

    channels.forEach(c => {
        ctx.beginPath();
        ctx.strokeStyle = c.color;
        ctx.lineWidth = 1.2;
        c.freq.forEach((count, i) => {
            const x = i * bw;
            const h = (count / maxFreq) * (H - 30);
            if (i === 0) ctx.moveTo(x, H - 20 - h);
            else ctx.lineTo(x, H - 20 - h);
        });
        ctx.stroke();

        // Fill with low alpha
        ctx.lineTo((255) * bw, H - 20);
        ctx.lineTo(0, H - 20);
        ctx.closePath();
        ctx.fillStyle = c.color.replace('0.7', '0.15');
        ctx.fill();
    });

    // Axis line
    ctx.fillStyle = 'rgba(255,255,255,0.15)';
    ctx.fillRect(0, H - 20, W, 1);
    ctx.fillStyle = 'rgba(255,255,255,0.3)';
    ctx.font = '10px DM Mono, monospace';
    ctx.fillText('0', 4, H - 5);
    ctx.fillText('255', W - 25, H - 5);

    // Pair anomaly detection (POV analysis)
    const statsEl = document.getElementById('histStats');
    if (statsEl) {
        statsEl.replaceChildren();
        let pairAnomaly = 0;
        for (let v = 0; v < 255; v += 2) {
            const diff = Math.abs(freqR[v] - freqR[v + 1]);
            const avg = (freqR[v] + freqR[v + 1]) / 2 || 1;
            if (diff / avg < 0.05) pairAnomaly++;
        }
        const anomalyPct = (pairAnomaly / 128 * 100).toFixed(1);
        const suspicious = pairAnomaly > 90;

        const term = document.createElement('div'); term.className = 'terminal';
        [
            [`[*] Histogram Analysis Complete`, 'info'],
            [`[*] Image: ${img.width}×${img.height} pixels`, 'muted'],
            [`[*] Adjacent pair matches (Red): ${pairAnomaly}/128 (${anomalyPct}%)`, suspicious ? 'err' : ''],
            [`[*] ${suspicious ? '⚠ HIGH pair equalization — LSB embedding suspected' : '✓ Normal pair distribution — no LSB anomaly detected'}`, suspicious ? 'err' : 'info'],
        ].forEach(([msg, cls]) => {
            const s = document.createElement('span');
            s.className = 't-line' + (cls ? ' t-' + cls : '');
            s.textContent = msg;
            term.appendChild(s); term.appendChild(document.createElement('br'));
        });
        statsEl.appendChild(term);
    }
}

// ─── Sample Pairs Analysis (SPA) ─────────────────────────────
export function runSPAAnalysis(input) {
    const f = input.files[0]; if (!f) return;
    validateImageFile(f).then(res => {
        if (!res.valid) { alert('[Security] ' + res.error); input.value = ''; return; }
        const r = new FileReader();
        r.onload = e => {
            const img = new Image();
            img.onload = () => {
                if (!validateImageDimensions(img)) return;
                _doSPA(img, f);
            };
            img.src = e.target.result;
        };
        r.onerror = () => alert('[ERROR] File read failed.');
        r.readAsDataURL(f);
    });
}

function _doSPA(img, file) {
    const W = Math.min(img.width, 1024), H = Math.min(img.height, 1024);
    const canvas = document.createElement('canvas'); canvas.width = W; canvas.height = H;
    const ctx = canvas.getContext('2d'); ctx.drawImage(img, 0, 0, W, H);
    const data = ctx.getImageData(0, 0, W, H).data;

    // SPA: compare adjacent pixel pairs in red channel
    let closePairs = 0, farPairs = 0, totalPairs = 0;
    let P2n = 0, P2n1 = 0; // Pairs where values are 2n and 2n+1

    for (let i = 0; i < data.length - 8; i += 8) {
        const v1 = data[i];     // Red of pixel 1
        const v2 = data[i + 4]; // Red of pixel 2
        totalPairs++;

        const diff = Math.abs(v1 - v2);
        if (diff <= 1) closePairs++;
        else farPairs++;

        // Check if pair is (2k, 2k+1) or (2k+1, 2k)
        const min = Math.min(v1, v2), max = Math.max(v1, v2);
        if (max - min === 1 && min % 2 === 0) P2n++;
        if (max - min === 1 && min % 2 === 1) P2n1++;
    }

    // Simplified embedding rate estimation
    const ratio = totalPairs > 0 ? P2n / (P2n + P2n1 || 1) : 0.5;
    const embedRate = Math.min(100, Math.max(0, (ratio - 0.5) * 200 + 50));
    const suspicious = embedRate > 60;

    const closePct = (closePairs / totalPairs * 100).toFixed(1);
    const farPct = (farPairs / totalPairs * 100).toFixed(1);

    const out = document.getElementById('spaOutput');
    if (!out) return;
    out.style.display = 'block'; out.replaceChildren();

    const term = document.createElement('div'); term.className = 'terminal'; term.style.marginBottom = '14px';
    [
        [`[*] Sample Pairs Analysis Complete`, 'info'],
        [`[*] Image: ${img.width}×${img.height} · ${(file.size / 1024).toFixed(1)} KB`, 'muted'],
        [`[*] Total sample pairs: ${totalPairs.toLocaleString()}`, 'muted'],
        [`[*] Close pairs (|Δ| ≤ 1): ${closePairs.toLocaleString()} (${closePct}%)`, ''],
        [`[*] Far pairs (|Δ| > 1): ${farPairs.toLocaleString()} (${farPct}%)`, ''],
        [`[*] Even-odd pair ratio: ${ratio.toFixed(4)}`, suspicious ? 'warn' : ''],
        [`[*] Estimated embedding rate: ${embedRate.toFixed(1)}%`, suspicious ? 'err' : 'info'],
        [`[*] Verdict: ${suspicious ? '⚠ STATISTICAL ANOMALY — LSB embedding likely' : '✓ Normal pair distribution'}`, suspicious ? 'err' : 'info'],
    ].forEach(([msg, cls]) => {
        const s = document.createElement('span');
        s.className = 't-line' + (cls ? ' t-' + cls : '');
        s.textContent = msg;
        term.appendChild(s); term.appendChild(document.createElement('br'));
    });
    out.appendChild(term);

    // Progress bar for embedding rate
    const pf = document.createElement('div'); pf.className = 'progress-field';
    const pl = document.createElement('div'); pl.className = 'progress-labels';
    const pll = document.createElement('span'); pll.textContent = 'Estimated Embedding Rate';
    const plv = document.createElement('span'); plv.textContent = embedRate.toFixed(1) + '%';
    pl.append(pll, plv);
    const pt = document.createElement('div'); pt.className = 'progress-track';
    const fill = document.createElement('div');
    fill.className = 'capacity-fill ' + (embedRate > 60 ? 'danger' : embedRate > 30 ? 'warn' : '');
    fill.style.width = Math.min(100, embedRate) + '%';
    pt.appendChild(fill); pf.append(pl, pt); out.appendChild(pf);

    const row = document.createElement('div'); row.style.cssText = 'margin-top:10px;display:flex;gap:8px';
    const b1 = document.createElement('span'); b1.className = `badge ${suspicious ? 'badge-rose' : 'badge-sage'}`;
    b1.textContent = suspicious ? 'ANOMALY DETECTED' : 'CLEAN';
    const b2 = document.createElement('span'); b2.className = 'badge badge-muted'; b2.textContent = `Ratio: ${ratio.toFixed(4)}`;
    row.append(b1, b2); out.appendChild(row);
}