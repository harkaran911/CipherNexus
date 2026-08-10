/**
 * cracker_worker.js — StegoVault v3
 * High-performance, pure JS synchronous hashing for Web Worker cracking.
 * Handles Dictionary, Bruteforce, and Mask attacks.
 */

"use strict";

// ============================================================================
// PURE JS HASH IMPLEMENTATIONS (Optimized for synchronous brute-force speed)
// ============================================================================

const hexMatch = (hashBytes, targetHex) => {
    let hex = "";
    for(let i=0; i<hashBytes.length; i++){
        hex += hashBytes[i].toString(16).padStart(2,'0');
    }
    return hex === targetHex;
};

// --- MD5 ---
function md5(str) {
    let hash = [1732584193, -271733879, -1732584194, 271733878];
    let s = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ];
    let k = [
        -680876936, -389564586,  606105819, -1044525330, -176418897,  1200080426,
        -1473231341, -45705983,  1770035416, -1958414417, -42063, -1990404162,
        1804603682, -40341101, -1502002290,  1236535329, -165796510, -1069501632,
        643717713, -373897302, -701558691,  38016083, -660478335, -405537848,
        568446438, -1019803690, -187363961,  1163531501, -1444681467, -51403784,
        1735328473, -1926607734, -378558, -2022574463,  1839030562, -35309556,
        -1530992060,  1272893353, -155497632, -1094730640,  681279174, -358537222,
        -722521979,  76029189, -640364487, -421815835,  530742520, -995338651,
        -198630844,  1126891415, -1416354905, -57434055,  1700485571, -1894986606,
        -1051523, -2054922799,  1873313359, -30611744, -1560198380,  1309151649,
        -145523070, -1120210379,  718787259, -343485551
    ];

    const blocks = [];
    for(let i = 0; i < str.length; i++) {
        blocks[i >> 2] |= str.charCodeAt(i) << ((i % 4) * 8);
    }
    blocks[str.length >> 2] |= 0x80 << ((str.length % 4) * 8);
    blocks[(((str.length + 8) >> 6) << 4) + 14] = str.length * 8;

    for (let i = 0; i < blocks.length; i += 16) {
        let a = hash[0], b = hash[1], c = hash[2], d = hash[3], f, g;
        for (let j = 0; j < 64; j++) {
            if (j < 16) { f = (b & c) | ((~b) & d); g = j; }
            else if (j < 32) { f = (d & b) | ((~d) & c); g = (5 * j + 1) % 16; }
            else if (j < 48) { f = b ^ c ^ d; g = (3 * j + 5) % 16; }
            else { f = c ^ (b | (~d)); g = (7 * j) % 16; }

            let temp = d;
            d = c;
            c = b;
            let val = (a + f + k[j] + (blocks[i + g] || 0)) | 0;
            b = (b + ((val << s[j]) | (val >>> (32 - s[j])))) | 0;
            a = temp;
        }
        hash[0] = (hash[0] + a) | 0;
        hash[1] = (hash[1] + b) | 0;
        hash[2] = (hash[2] + c) | 0;
        hash[3] = (hash[3] + d) | 0;
    }
    let res = [];
    for (let i=0; i<4; i++){
        res.push((hash[i]>>0)&0xff, (hash[i]>>8)&0xff, (hash[i]>>16)&0xff, (hash[i]>>24)&0xff);
    }
    return res;
}

// --- SHA-1 ---
function sha1(str) {
    const H = [1732584193, 4023233417, 2562383102, 271733878, 3285377520];
    const w = new Int32Array(80);
    const m = [];
    let l = str.length;
    for (let i = 0; i < l; i++) { m[i >> 2] |= str.charCodeAt(i) << (24 - (i % 4) * 8); }
    m[l >> 2] |= 0x80 << (24 - (l % 4) * 8);
    m[(((l + 8) >> 6) << 4) + 15] = l * 8;
    
    for (let i = 0; i < m.length; i += 16) {
        let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4];
        for (let j = 0; j < 80; j++) {
            if (j < 16) w[j] = m[i + j] | 0;
            else {
                let n = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
                w[j] = (n << 1) | (n >>> 31);
            }
            let t = ((a << 5) | (a >>> 27)) + e + w[j] | 0;
            if (j < 20) t += ((b & c) | (~b & d)) + 1518500249;
            else if (j < 40) t += (b ^ c ^ d) + 1859775393;
            else if (j < 60) t += ((b & c) | (b & d) | (c & d)) - 1894007588;
            else t += (b ^ c ^ d) - 899497514;
            e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;
        }
        H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0;
        H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
        H[4] = (H[4] + e) | 0;
    }
    let res = [];
    for(let i=0; i<5; i++){
        res.push((H[i]>>24)&0xff, (H[i]>>16)&0xff, (H[i]>>8)&0xff, (H[i]>>0)&0xff);
    }
    return res;
}

// --- SHA-256 ---
function sha256(str) {
    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    let H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
    let w = new Int32Array(64);
    let m = [];
    let l = str.length;
    for (let i = 0; i < l; i++) { m[i >> 2] |= str.charCodeAt(i) << (24 - (i % 4) * 8); }
    m[l >> 2] |= 0x80 << (24 - (l % 4) * 8);
    m[(((l + 8) >> 6) << 4) + 15] = l * 8;

    for (let i = 0; i < m.length; i += 16) {
        let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
        for (let j = 0; j < 64; j++) {
            if (j < 16) w[j] = m[i + j] | 0;
            else {
                let s0 = (w[j - 15] >>> 7 | w[j - 15] << 25) ^ (w[j - 15] >>> 18 | w[j - 15] << 14) ^ (w[j - 15] >>> 3);
                let s1 = (w[j - 2] >>> 17 | w[j - 2] << 15) ^ (w[j - 2] >>> 19 | w[j - 2] << 13) ^ (w[j - 2] >>> 10);
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
            }
            let S1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7);
            let ch = (e & f) ^ (~e & g);
            let temp1 = (h + S1 + ch + K[j] + w[j]) | 0;
            let S0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = (S0 + maj) | 0;

            h = g; g = f; f = e; e = (d + temp1) | 0;
            d = c; c = b; b = a; a = (temp1 + temp2) | 0;
        }
        H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
        H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    let res = [];
    for(let i=0; i<8; i++){
        res.push((H[i]>>24)&0xff, (H[i]>>16)&0xff, (H[i]>>8)&0xff, (H[i]>>0)&0xff);
    }
    return res;
}

// ============================================================================
// WORKER MESSAGE HANDLER
// ============================================================================

self.onmessage = function(e) {
    const { id, type, hashAlgo, targetHashHex, payload } = e.data;
    
    // Select the hash function
    let hashFn = null;
    if (hashAlgo === "MD5") hashFn = md5;
    else if (hashAlgo === "SHA-1") hashFn = sha1;
    else if (hashAlgo === "SHA-256") hashFn = sha256;
    else {
        postMessage({ id, status: "error", error: "Hash algorithm not supported in this JS worker."});
        return;
    }

    let batchCount = 0;
    let found = false;
    let tickCount = 0;
    const REPORT_INTERVAL = 10000; // report progress every 10,000 hashes

    const checkHash = (candidate) => {
        batchCount++;
        tickCount++;
        if (tickCount >= REPORT_INTERVAL) {
            postMessage({ id, status: "progress", count: tickCount });
            tickCount = 0;
        }
        const b = hashFn(candidate);
        if (hexMatch(b, targetHashHex)) {
            found = candidate;
            return true;
        }
        return false;
    };

    if (type === "dictionary") {
        // payload: { words: [], rules: [] }
        const words = payload.words || [];
        const rules = payload.rules || ["none"];
        
        for (let base of words) {
            for (let rule of rules) {
                let candidate = base;
                // very simple rules engine
                if (rule === "lowercase") candidate = candidate.toLowerCase();
                if (rule === "uppercase") candidate = candidate.toUpperCase();
                if (rule === "capitalize") candidate = candidate.charAt(0).toUpperCase() + candidate.slice(1).toLowerCase();
                if (rule === "appendNum") { // test appending 0-99
                    for(let i=0; i<100; i++){
                        if (checkHash(candidate + i)) break;
                    }
                    if (found) break;
                    continue; // we already checked the variants
                }
                
                if (checkHash(candidate)) break;
            }
            if (found) break;
        }
    } 
    else if (type === "mask") {
        // payload: { prefix: "", charset: "abcdef...", length: 4 }
        // For simplicity, we just generate permutations recursively up to max length
        // This receives a specific prefix chunk from the core scheduler so workers split work.
        const charset = payload.charset;
        const targetLen = payload.length;
        const prefix = payload.prefix;
        
        const recurse = (current) => {
            if (found) return;
            if (current.length === targetLen) {
                checkHash(current);
                return;
            }
            for (let i = 0; i < charset.length; i++) {
                recurse(current + charset[i]);
            }
        };
        recurse(prefix);
    }

    // Flush remaining count
    if (tickCount > 0) {
        postMessage({ id, status: "progress", count: tickCount });
    }

    // Done
    if (found) {
        postMessage({ id, status: "found", result: found, finalCount: batchCount });
    } else {
        postMessage({ id, status: "done", finalCount: batchCount });
    }
};
