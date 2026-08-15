/**
 * forensics.js — CipherNexus v3 File Forensics Toolkit
 * Hex dump, strings extractor, PNG chunk analyzer,
 * embedded file carver, EXIF/metadata extractor.
 */

"use strict";

import { mkLogger } from "./security.js";

// ─── File Signatures ──────────────────────────────────────────
const FILE_SIGS = [
    { name: "JPEG",       bytes: [0xFF,0xD8,0xFF],                         ext: "jpg"  },
    { name: "PNG",        bytes: [0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A], ext: "png"  },
    { name: "GIF87a",     bytes: [0x47,0x49,0x46,0x38,0x37,0x61],          ext: "gif"  },
    { name: "GIF89a",     bytes: [0x47,0x49,0x46,0x38,0x39,0x61],          ext: "gif"  },
    { name: "ZIP/PK",     bytes: [0x50,0x4B,0x03,0x04],                    ext: "zip"  },
    { name: "ZIP (end)",  bytes: [0x50,0x4B,0x05,0x06],                    ext: "zip"  },
    { name: "RAR4",       bytes: [0x52,0x61,0x72,0x21,0x1A,0x07,0x00],     ext: "rar"  },
    { name: "RAR5",       bytes: [0x52,0x61,0x72,0x21,0x1A,0x07,0x01],     ext: "rar"  },
    { name: "7-Zip",      bytes: [0x37,0x7A,0xBC,0xAF,0x27,0x1C],          ext: "7z"   },
    { name: "PDF",        bytes: [0x25,0x50,0x44,0x46],                    ext: "pdf"  },
    { name: "ELF",        bytes: [0x7F,0x45,0x4C,0x46],                    ext: "elf"  },
    { name: "Zlib(def)",  bytes: [0x78,0x9C],                              ext: "zlib" },
    { name: "Zlib(low)",  bytes: [0x78,0x01],                              ext: "zlib" },
    { name: "Zlib(best)", bytes: [0x78,0xDA],                              ext: "zlib" },
    { name: "GZIP",       bytes: [0x1F,0x8B],                              ext: "gz"   },
    { name: "BMP",        bytes: [0x42,0x4D],                              ext: "bmp"  },
    { name: "TIFF (LE)",  bytes: [0x49,0x49,0x2A,0x00],                    ext: "tif"  },
    { name: "TIFF (BE)",  bytes: [0x4D,0x4D,0x00,0x2A],                    ext: "tif"  },
    { name: "OGG",        bytes: [0x4F,0x67,0x67,0x53],                    ext: "ogg"  },
    { name: "SQLite",     bytes: [0x53,0x51,0x4C,0x69,0x74,0x65,0x20],     ext: "db"   },
    { name: "TAR (ustar)",bytes: [0x75,0x73,0x74,0x61,0x72],               ext: "tar"  },
    { name: "BZIP2",      bytes: [0x42,0x5A,0x68],                         ext: "bz2"  },
    { name: "XZ",         bytes: [0xFD,0x37,0x7A,0x58,0x5A,0x00],          ext: "xz"   },
    { name: "LZ4",        bytes: [0x04,0x22,0x4D,0x18],                    ext: "lz4"  },
    { name: "Zstd",       bytes: [0x28,0xB5,0x2F,0xFD],                    ext: "zst"  },
];

function readFile(fileInput, asBuffer) {
    return new Promise((resolve, reject) => {
        const file = fileInput.files[0];
        if (!file) { reject(new Error("No file selected")); return; }
        const reader = new FileReader();
        reader.onload = (e) => resolve({ file, buffer: e.target.result });
        reader.onerror = () => reject(new Error("File read error"));
        if (asBuffer) reader.readAsArrayBuffer(file);
        else reader.readAsText(file);
    });
}

// ─── Hex Dump ─────────────────────────────────────────────────
export async function runHexDump(fileInput) {
    const log = mkLogger("hexdumpOutput");
    let data;
    try { data = await readFile(fileInput, true); } catch (e) { log(`[ERROR] ${e.message}`, "err"); return; }
    const { file, buffer } = data;
    const bytes = new Uint8Array(buffer);
    const limit = Math.min(bytes.length, 2048);

    log(`[*] ${file.name} — ${file.size.toLocaleString()} bytes — showing first ${limit}`, "info");
    log("Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |ASCII           |", "muted");
    log("─".repeat(80), "muted");

    for (let i = 0; i < limit; i += 16) {
        const row = bytes.slice(i, Math.min(i + 16, limit));
        const off = i.toString(16).padStart(8, "0");
        const hex1 = Array.from(row.slice(0, 8)).map(b => b.toString(16).padStart(2, "0")).join(" ").padEnd(23, " ");
        const hex2 = Array.from(row.slice(8)).map(b => b.toString(16).padStart(2, "0")).join(" ").padEnd(23, " ");
        const ascii = Array.from(row).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".").join("").padEnd(16, " ");
        log(`${off}  ${hex1}  ${hex2}  |${ascii}|`, "muted");
    }
    if (bytes.length > limit) {
        log(`[*] … ${(bytes.length - limit).toLocaleString()} more bytes not shown`, "warn");
    }
}

// ─── Strings Extractor ────────────────────────────────────────
export async function runStringsExtract(fileInput) {
    const minLen = parseInt(document.getElementById("stringsMinLen")?.value || "4", 10);
    const log = mkLogger("stringsOutput");
    let data;
    try { data = await readFile(fileInput, true); } catch (e) { log(`[ERROR] ${e.message}`, "err"); return; }
    const { file, buffer } = data;
    const bytes = new Uint8Array(buffer);

    log(`[*] Scanning ${file.name} for printable strings (min ${minLen} chars)…`, "info");

    const results = [];
    let cur = "", startOff = 0;
    for (let i = 0; i <= bytes.length; i++) {
        const b = bytes[i];
        if (b >= 32 && b <= 126) {
            if (!cur) startOff = i;
            cur += String.fromCharCode(b);
        } else {
            if (cur.length >= minLen) results.push({ off: startOff, str: cur });
            cur = "";
        }
    }

    log(`[✓] ${results.length} string(s) found`, "safe");
    if (results.length === 0) { log("[*] None found.", "warn"); return; }

    const cap = Math.min(results.length, 300);
    results.slice(0, cap).forEach(({ off, str }) => {
        const preview = str.length > 100 ? str.slice(0, 100) + "…" : str;
        const cls = str.length > 10 ? "info" : "muted";
        log(`0x${off.toString(16).padStart(8,"0")}  ${preview}`, cls);
    });
    if (results.length > cap) log(`[*] … ${results.length - cap} more omitted`, "warn");
}

// ─── PNG Chunk Analyzer ───────────────────────────────────────
const KNOWN_PNG = new Set([
    "IHDR","IDAT","IEND","PLTE","tRNS","cHRM","gAMA","iCCP",
    "sBIT","sRGB","bKGD","hIST","pHYs","sPLT","tIME",
    "tEXt","zTXt","iTXt","eXIf","acTL","fcTL","fdAT"
]);

export async function runPNGChunks(fileInput) {
    const log = mkLogger("pngchunkOutput");
    let data;
    try { data = await readFile(fileInput, true); } catch (e) { log(`[ERROR] ${e.message}`, "err"); return; }
    const { file, buffer } = data;
    const bytes = new Uint8Array(buffer);
    const view = new DataView(buffer);

    const PNG_SIG = [0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A];
    if (!PNG_SIG.every((b, i) => bytes[i] === b)) {
        log("[ERROR] Not a valid PNG file (signature mismatch).", "err");
        return;
    }

    log(`[*] PNG: ${file.name} (${file.size.toLocaleString()} bytes)`, "info");
    log(`[✓] PNG signature valid`, "safe");
    log("─".repeat(60), "muted");

    let offset = 8, iendOffset = -1;
    const chunks = [];

    while (offset + 12 <= bytes.length) {
        const length = view.getUint32(offset, false);
        if (offset + 8 + length + 4 > bytes.length) break;
        const type = String.fromCharCode(bytes[offset+4],bytes[offset+5],bytes[offset+6],bytes[offset+7]);
        const dataStart = offset + 8;
        chunks.push({ offset, type, length, dataStart });
        if (type === "IEND") { iendOffset = offset + 8 + length + 4; break; }
        offset += 8 + length + 4;
    }

    chunks.forEach(({ offset: off, type, length, dataStart }) => {
        const known = KNOWN_PNG.has(type);
        const flag = known ? "  " : "⚠ ";
        const cls  = known ? "muted" : "warn";
        log(`${flag}[${type}]  offset=0x${off.toString(16).padStart(6,"0")}  length=${length}`, cls);

        if (type === "IHDR" && length >= 13) {
            const w = view.getUint32(dataStart, false);
            const h = view.getUint32(dataStart+4, false);
            const bd = bytes[dataStart+8];
            const ct = bytes[dataStart+9];
            const ctMap = {0:"Greyscale",2:"RGB",3:"Indexed",4:"Greyscale+Alpha",6:"RGBA"};
            log(`     ${w}×${h} px | bit depth ${bd} | ${ctMap[ct]||"?"}`, "info");
        }
        if ((type === "tEXt") && length < 4096) {
            const raw = bytes.slice(dataStart, dataStart + length);
            const nul = raw.indexOf(0);
            const kw  = Array.from(raw.slice(0, nul)).map(b => String.fromCharCode(b)).join("");
            const val = Array.from(raw.slice(nul+1)).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : "").join("");
            log(`     ${kw}: ${val}`, "info");
        }
        if (type === "iTXt" && length < 8192) {
            const raw = bytes.slice(dataStart, dataStart + length);
            const nul = raw.indexOf(0);
            const kw  = Array.from(raw.slice(0, Math.max(0, nul))).map(b => String.fromCharCode(b)).join("");
            log(`     Keyword: ${kw}  [international text, ${length} bytes]`, "info");
        }
        if (!known) log(`     UNKNOWN chunk — may contain hidden data!`, "warn");
    });

    const trailing = bytes.length - (iendOffset > 0 ? iendOffset : bytes.length);
    log("─".repeat(60), "muted");
    log(`[*] ${chunks.length} chunk(s) parsed`, "info");
    if (trailing > 0) {
        log(`[!] ${trailing} bytes of TRAILING DATA after IEND — common CTF technique!`, "warn");
        const preview = Array.from(bytes.slice(iendOffset, Math.min(iendOffset + 32, bytes.length)))
            .map(b => b.toString(16).padStart(2,"0")).join(" ");
        log(`    First bytes: ${preview}`, "warn");
    } else {
        log(`[✓] No trailing data detected`, "safe");
    }
}

// ─── Embedded File Carver ─────────────────────────────────────
export async function runFileCarver(fileInput) {
    const log = mkLogger("carverOutput");
    let data;
    try { data = await readFile(fileInput, true); } catch (e) { log(`[ERROR] ${e.message}`, "err"); return; }
    const { file, buffer } = data;
    const bytes = new Uint8Array(buffer);

    log(`[*] Scanning ${file.name} for embedded file signatures…`, "info");

    // Detect host file type (skip its own leading signature)
    const selfSig = FILE_SIGS.find(s => s.bytes.every((b, i) => bytes[i] === b));
    const selfSkip = selfSig ? selfSig.bytes.length : 0;

    const hits = [];
    for (let i = selfSkip > 0 ? 1 : 0; i < bytes.length; i++) {
        for (const sig of FILE_SIGS) {
            if (i + sig.bytes.length > bytes.length) continue;
            if (sig.bytes.every((b, j) => bytes[i + j] === b)) {
                hits.push({ offset: i, ...sig });
            }
        }
    }

    if (hits.length === 0) {
        log("[✓] No embedded file signatures detected.", "safe");
        return;
    }

    log(`[!] ${hits.length} embedded signature(s) found!`, "warn");
    log("─".repeat(60), "muted");
    hits.forEach(({ offset, name, ext }) => {
        log(`[!] ${name.padEnd(12)} .${ext}  at byte offset 0x${offset.toString(16).padStart(8,"0")} (${offset})`, "warn");
    });
    log("─".repeat(60), "muted");
    log(`[*] Extract with: binwalk -e <file>  or  foremost -i <file>`, "info");
}

// ─── EXIF / Metadata Extractor ────────────────────────────────
const EXIF_TAGS = {
    0x010E:"ImageDescription", 0x010F:"Make",       0x0110:"Model",
    0x0112:"Orientation",      0x0131:"Software",    0x0132:"DateTime",
    0x013B:"Artist",           0x8298:"Copyright",
    0x9003:"DateTimeOriginal", 0x9004:"DateTimeDigitized",
    0x920A:"FocalLength",      0x927C:"MakerNote",   0x9286:"UserComment",
    0xA001:"ColorSpace",       0xA002:"PixelXDimension", 0xA003:"PixelYDimension",
    0x8769:"ExifIFD",          0x8825:"GPSIFD",
    // GPS
    0x0001:"GPSLatitudeRef",   0x0002:"GPSLatitude",
    0x0003:"GPSLongitudeRef",  0x0004:"GPSLongitude",
    0x0005:"GPSAltitudeRef",   0x0006:"GPSAltitude",
    0x001D:"GPSDateStamp",
};

export async function runMetadataExtract(fileInput) {
    const log = mkLogger("metaOutput");
    let data;
    try { data = await readFile(fileInput, true); } catch (e) { log(`[ERROR] ${e.message}`, "err"); return; }
    const { file, buffer } = data;
    const bytes = new Uint8Array(buffer.slice(0, 131072)); // 128KB cap
    const view  = new DataView(buffer, 0, bytes.length);

    log(`[*] File: ${file.name}`, "info");
    log(`[*] Size: ${file.size.toLocaleString()} bytes | Modified: ${new Date(file.lastModified).toISOString()}`, "muted");
    log(`[*] MIME (declared): ${file.type || "unknown"}`, "muted");
    log("─".repeat(60), "muted");

    const isJPEG = bytes[0] === 0xFF && bytes[1] === 0xD8;
    const isPNG  = bytes[0] === 0x89 && bytes[1] === 0x50;

    if (isJPEG) parseJPEGMeta(bytes, view, log);
    else if (isPNG) parsePNGMeta(bytes, view, log);
    else {
        log("[*] Format not recognised for deep metadata parsing.", "warn");
        log("[*] Try the Strings Extractor tab for embedded text.", "muted");
    }
}

function parseJPEGMeta(bytes, view, log) {
    log("[*] Format: JPEG", "info");
    let offset = 2;
    let found = 0;

    while (offset + 4 < bytes.length) {
        if (bytes[offset] !== 0xFF) break;
        const marker = bytes[offset + 1];
        if (marker === 0xD9) break;
        if (marker === 0xD8 || (marker >= 0xD0 && marker <= 0xD7)) { offset += 2; continue; }
        if (offset + 4 > bytes.length) break;

        const segLen = view.getUint16(offset + 2, false);

        if (marker === 0xE1) {
            // APP1 — EXIF or XMP
            const sig4 = String.fromCharCode(bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7]);
            if (sig4 === "Exif") {
                found++;
                log("[✓] EXIF APP1 segment found", "safe");
                parseEXIFBlock(bytes, view, offset + 10, log);
            } else {
                log("[*] APP1 (XMP or other) segment — " + segLen + " bytes", "muted");
            }
        }
        if (marker === 0xFE) {
            // Comment
            const comment = Array.from(bytes.slice(offset+4, Math.min(offset+2+segLen, bytes.length)))
                .map(b => b >= 32 && b <= 126 ? String.fromCharCode(b) : "").join("");
            if (comment) { found++; log(`[!] JPEG Comment: "${comment}"`, "warn"); }
        }
        if (marker === 0xED) {
            found++;
            log("[*] APP13 (IPTC/Photoshop) segment — " + segLen + " bytes", "info");
        }

        offset += 2 + segLen;
    }
    if (!found) log("[*] No metadata segments found (stripped).", "muted");
}

function parseEXIFBlock(bytes, view, tiffBase, log) {
    if (tiffBase + 8 >= bytes.length) return;
    const bo = String.fromCharCode(bytes[tiffBase], bytes[tiffBase+1]);
    const le = bo === "II";
    const r16 = (o) => view.getUint16(tiffBase + o, le);
    const r32 = (o) => view.getUint32(tiffBase + o, le);
    const s32 = (o) => view.getInt32(tiffBase + o, le);

    const readIFD = (ifdOff, indent = "") => {
        if (ifdOff + 2 > bytes.length - tiffBase) return;
        const count = r16(ifdOff);
        for (let i = 0; i < Math.min(count, 100); i++) {
            const eo = ifdOff + 2 + i * 12;
            if (eo + 12 > bytes.length - tiffBase) break;
            const tag  = r16(eo);
            const type = r16(eo + 2);
            const cnt  = r32(eo + 4);
            const name = EXIF_TAGS[tag];
            if (!name || name === "MakerNote") continue;

            const tsize = [0,1,1,2,4,8,1,1,2,4,8][type] || 1;
            const total = cnt * tsize;
            const valOff = total > 4 ? r32(eo + 8) : eo + 8;

            let val = "";
            try {
                if (type === 2) {
                    val = Array.from(bytes.slice(tiffBase+valOff, tiffBase+valOff+cnt))
                        .filter(b => b >= 32 && b < 127).map(b => String.fromCharCode(b)).join("").trim();
                } else if (type === 3 && cnt === 1) {
                    val = r16(total <= 4 ? eo + 8 : valOff).toString();
                } else if (type === 4 && cnt === 1) {
                    val = r32(total <= 4 ? eo + 8 : valOff).toString();
                } else if (type === 5 && cnt >= 1) {
                    const n = r32(valOff), d = r32(valOff+4);
                    val = d ? `${n}/${d} (${(n/d).toFixed(3)})` : `${n}/0`;
                } else if (type === 10 && cnt >= 1) {
                    const n = s32(valOff), d = s32(valOff+4);
                    val = d ? `${n}/${d} (${(n/d).toFixed(3)})` : `${n}/0`;
                } else { val = `[type=${type} count=${cnt}]`; }
            } catch { val = "[parse error]"; }

            if (name === "ExifIFD" || name === "GPSIFD") {
                const subOff = r32(eo + 8);
                log(`${indent}[${name}] ↓`, "info");
                readIFD(subOff, indent + "  ");
            } else {
                log(`${indent}${name}: ${val}`, "info");
            }
        }
    };

    const ifd0 = r32(4);
    readIFD(ifd0);
}

function parsePNGMeta(bytes, view, log) {
    log("[*] Format: PNG", "info");
    let offset = 8, found = 0;

    while (offset + 12 <= bytes.length) {
        const length = view.getUint32(offset, false);
        const type = String.fromCharCode(bytes[offset+4],bytes[offset+5],bytes[offset+6],bytes[offset+7]);

        if (type === "tEXt" && length < 4096) {
            found++;
            const raw = bytes.slice(offset+8, offset+8+length);
            const nul = raw.indexOf(0);
            const kw  = Array.from(raw.slice(0, nul)).map(b => String.fromCharCode(b)).join("");
            const val = Array.from(raw.slice(nul+1)).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : "").join("");
            log(`  tEXt/${kw}: ${val}`, "info");
        }
        if (type === "iTXt" && length < 8192) {
            found++;
            const raw = bytes.slice(offset+8, offset+8+length);
            const nul = raw.indexOf(0);
            const kw  = Array.from(raw.slice(0, Math.max(0,nul))).map(b => String.fromCharCode(b)).join("");
            log(`  iTXt/${kw}: [${length} bytes of international text]`, "info");
        }
        if (type === "tIME" && length === 7) {
            found++;
            const y = view.getUint16(offset+8, false);
            const [mo,d,h,mi,s] = [bytes[offset+10],bytes[offset+11],bytes[offset+12],bytes[offset+13],bytes[offset+14]];
            log(`  tIME: ${y}-${String(mo).padStart(2,"0")}-${String(d).padStart(2,"0")} ${String(h).padStart(2,"0")}:${String(mi).padStart(2,"0")}:${String(s).padStart(2,"0")} UTC`, "info");
        }
        if (type === "eXIf" && length > 4) {
            found++;
            log(`  eXIf: ${length} bytes of EXIF data embedded in PNG`, "warn");
        }
        if (type === "IEND") break;
        offset += 8 + length + 4;
    }
    if (!found) log("[*] No metadata chunks found (tEXt / iTXt / tIME / eXIf).", "muted");
}
