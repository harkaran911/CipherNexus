"use strict";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: false });

function textToBase64(str) {
  try {
    const bytes = encoder.encode(str);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  } catch {
    return "Error encoding Base64";
  }
}

function base64ToText(b64) {
  try {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return decoder.decode(bytes);
  } catch {
    return null; // Invalid base64
  }
}

function textToUrl(str) {
  try {
    return encodeURIComponent(str);
  } catch {
    return "Error encoding URL";
  }
}

function urlToText(urlStr) {
  try {
    return decodeURIComponent(urlStr);
  } catch {
    return null; 
  }
}

function textToHex(str) {
  try {
    const bytes = encoder.encode(str);
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  } catch {
    return "Error encoding Hex";
  }
}

function hexToText(hexStr) {
  try {
    const cleanHex = hexStr.replace(/\s+/g, "");
    if (cleanHex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(cleanHex)) return null;
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
    }
    return decoder.decode(bytes);
  } catch {
    return null;
  }
}

function textToBin(str) {
    try {
      const bytes = encoder.encode(str);
      let bin = "";
      for (let i = 0; i < bytes.length; i++) {
        bin += bytes[i].toString(2).padStart(8, "0") + " ";
      }
      return bin.trim();
    } catch {
      return "Error encoding Binary";
    }
}

function binToText(binStr) {
    try {
        const cleanBin = binStr.replace(/[^01]/g, "");
        if (cleanBin.length % 8 !== 0) return null;
        const bytes = new Uint8Array(cleanBin.length / 8);
        for (let i = 0; i < cleanBin.length; i += 8) {
            bytes[i / 8] = parseInt(cleanBin.substring(i, i + 8), 2);
        }
        return decoder.decode(bytes);
    } catch {
        return null;
    }
}

/**
 * @param {string} sourceId The ID of the element that triggered the input
 */
export function handleEncodingSync(sourceId) {
    const plainEl = document.getElementById("encPlain");
    const b64El = document.getElementById("encBase64");
    const urlEl = document.getElementById("encUrl");
    const hexEl = document.getElementById("encHex");
    const binEl = document.getElementById("encBin");

    if (!plainEl || !b64El || !urlEl || !hexEl || !binEl) return;

    let baseText = "";
    let valid = true;

    // Decode from source to get the base text
    if (sourceId === "encPlain") {
        baseText = plainEl.value;
    } else if (sourceId === "encBase64") {
        const decoded = base64ToText(b64El.value);
        if (decoded === null) valid = false; else baseText = decoded;
    } else if (sourceId === "encUrl") {
        const decoded = urlToText(urlEl.value);
        if (decoded === null) valid = false; else baseText = decoded;
    } else if (sourceId === "encHex") {
        const decoded = hexToText(hexEl.value);
        if (decoded === null) valid = false; else baseText = decoded;
    } else if (sourceId === "encBin") {
        const decoded = binToText(binEl.value);
        if (decoded === null) valid = false; else baseText = decoded;
    }

    const setErrorState = (el, isError) => {
        if (!el) return;
        if (isError) {
            el.style.color = "var(--danger)";
        } else {
            el.style.color = "var(--text)";
        }
    };

    if (!valid && b64El.value.trim() !== "" && hexEl.value.trim() !== "" && binEl.value.trim() !== "") {
        // If the source was invalid and non-empty, mark target plain as errored visually
        if (sourceId !== "encPlain") {
            setErrorState(plainEl, true);
        }
        return;
    }
    
    setErrorState(plainEl, false);
    setErrorState(b64El, false);
    setErrorState(urlEl, false);
    setErrorState(hexEl, false);
    setErrorState(binEl, false);

    // Propagate baseText to all fields except the active source
    if (sourceId !== "encPlain") plainEl.value = baseText;
    if (sourceId !== "encBase64") b64El.value = textToBase64(baseText);
    if (sourceId !== "encUrl") urlEl.value = textToUrl(baseText);
    if (sourceId !== "encHex") hexEl.value = textToHex(baseText);
    if (sourceId !== "encBin") binEl.value = textToBin(baseText);
}
