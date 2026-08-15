/**
 * cracker.js — CipherNexus v3
 * UI logic and Worker Pool manager for Password Cracking Lab.
 */

"use strict";

import { mkLogger, appendToTerminal } from "./security.js";

// Top ~100 common passwords for immediate testing without a file upload
const DEFAULT_WORDLIST = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", 
    "1234567", "dragon", "123123", "baseball", "monkey", "letmein", "football", "shadow", 
    "mustang", "trustno1", "michael", "senha", "1234567890", "admin", "admin123", "admin1234",
    "password123", "Welcome1", "P@ssword1", "password!", "root", "toor", "test", "test1234",
    "hunter2", "stegovault", "hacker", "hacker123", "cyber", "security", "vault", "123456789012"
];

let workers = [];
let totalHashes = 0;
let isRunning = false;
let startTime = 0;
let statsInterval = null;
let foundResult = null;
let customWordlist = [];

export function initCrackLab() {
    // Populate wordlist selector count
    const wlInfo = document.getElementById("wordlistInfo");
    if (wlInfo) wlInfo.textContent = `Default Wordlist loaded (${DEFAULT_WORDLIST.length} words)`;
}

export function handleWordlistUpload(fileInput) {
    const file = fileInput.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        const text = e.target.result;
        // Split by line and clean empty/whitespace
        customWordlist = text.split(/\r?\n/).map(s => s.trim()).filter(s => s.length > 0);
        const wlInfo = document.getElementById("wordlistInfo");
        if (wlInfo) {
            wlInfo.textContent = `Custom Wordlist: ${file.name} (${customWordlist.length.toLocaleString()} words)`;
        }
    };
    reader.readAsText(file);
}

export function startCracker() {
    if (isRunning) return;

    const targetHashHex = (document.getElementById("crackHashInput")?.value || "").trim().toLowerCase();
    const hashAlgo = document.getElementById("crackHashAlgo")?.value || "MD5";
    const attackType = document.getElementById("crackAttackType")?.value || "dictionary";

    const log = mkLogger("crackOutput");

    if (!targetHashHex || !/^[0-9a-f]+$/.test(targetHashHex)) {
        log("[ERROR] Please provide a valid hexadecimal hash target.", "err");
        return;
    }

    const EXPECTED_LENGTHS = { "MD5": 32, "SHA-1": 40, "SHA-256": 64 };
    const expectedLen = EXPECTED_LENGTHS[hashAlgo];
    if (expectedLen && targetHashHex.length !== expectedLen) {
        log(`[ERROR] Hash length mismatch: ${hashAlgo} requires ${expectedLen} hex chars, got ${targetHashHex.length}.`, "err");
        return;
    }

    log(`[*] Initializing parallel WebWorker pool...`, "muted");
    log(`[*] Target Hash: ${targetHashHex.slice(0,16)}...`, "info");
    log(`[*] Algorithm: ${hashAlgo} · Attack: ${attackType}`, "info");

    const coreCount = navigator.hardwareConcurrency || 4;
    log(`[*] Spawning ${coreCount} worker threads.`, "muted");

    totalHashes = 0;
    isRunning = true;
    foundResult = null;
    startTime = performance.now();
    workers = [];
    
    let activeWorkers = coreCount;

    // Build workload chunks
    let chunks = [];
    if (attackType === "dictionary") {
        const rules = document.getElementById("crackRulesToggle")?.checked ? ["none", "lowercase", "uppercase", "capitalize", "appendNum"] : ["none"];
        const listToUse = customWordlist.length > 0 ? customWordlist : DEFAULT_WORDLIST;
        log(`[*] Applying lists: ${listToUse.length.toLocaleString()} words x ${rules.length} rules`, "info");
        
        // Chunk the array
        const chunkSize = Math.max(1, Math.ceil(listToUse.length / coreCount));
        for (let i=0; i<coreCount; i++) {
            chunks.push({
                type: "dictionary",
                payload: {
                    words: listToUse.slice(i * chunkSize, (i+1) * chunkSize),
                    rules: rules
                }
            });
        }
    } else if (attackType === "mask") {
        // e.g. Bruteforce 5 chars lowercase (a-z: 26^5 = 11,881,376 combinations)
        const charset = "abcdefghijklmnopqrstuvwxyz";
        const length = 5; 
        log(`[*] Mask Attack: ${length} chars, charset: ${charset.slice(0,5)}... [WARNING: CPU Intensive]`, "warn");

        // Distribute work by splitting the first character across threads
        // We divide the 26 start letters across the cores
        for (let i=0; i<charset.length; i++) {
            chunks.push({
                type: "mask",
                payload: {
                    prefix: charset[i],
                    charset: charset,
                    length: length
                }
            });
        }
    }

    // Launch workers
    const nextChunk = () => chunks.shift();

    for (let w = 0; w < coreCount; w++) {
        const worker = new Worker("./js/cracker_worker.js");
        
        const assignWork = () => {
            const chunk = nextChunk();
            if (chunk) {
                worker.postMessage({ id: w, type: chunk.type, hashAlgo, targetHashHex, payload: chunk.payload });
            } else {
                activeWorkers--;
                worker.terminate();
                if (activeWorkers === 0) stopCracker();
            }
        };

        worker.onmessage = (e) => {
            if (e.data.status === "progress") {
                totalHashes += e.data.count;
            } else if (e.data.status === "found") {
                totalHashes += e.data.finalCount || 0;
                foundResult = e.data.result;
                log(`[!] HASH CRACKED: -> ${foundResult} <-`, "safe");
                stopCracker(); 
            } else if (e.data.status === "done") {
                totalHashes += e.data.finalCount || 0;
                assignWork();
            } else if (e.data.status === "error") {
                log(`[ERROR] Worker error: ${e.data.error}`, "err");
                assignWork();
            }
        };

        workers.push(worker);
        assignWork();
    }

    // Live Stats updater
    const speedEl = document.getElementById("crackSpeed");
    statsInterval = setInterval(() => {
        if (!isRunning) return;
        const elapsed = (performance.now() - startTime) / 1000;
        const speed = totalHashes / elapsed;
        if (speedEl) {
            speedEl.textContent = `${Math.round(speed).toLocaleString()} H/s`;
        }
    }, 500);
}

export function stopCracker() {
    if (!isRunning) return;
    isRunning = false;

    workers.forEach(w => w.terminate());
    workers = [];
    clearInterval(statsInterval);

    const elapsed = (performance.now() - startTime) / 1000;
    const speed = totalHashes / elapsed;

    // Use appendToTerminal directly to preserve all prior output
    const log = (msg, cls) => appendToTerminal("crackOutput", msg, cls);
    log(`[*] Attack terminated.`, "muted");
    log(`[*] Stats: ${totalHashes.toLocaleString()} total hashes in ${elapsed.toFixed(2)}s (~${Math.round(speed).toLocaleString()} H/s).`, "info");

    if (foundResult) {
        log(`[✓] SUCCESS: Plaintext is "${foundResult}"`, "safe");
    } else {
        log(`[✗] Exhausted keyspace. Hash not found.`, "warn");
    }
}
