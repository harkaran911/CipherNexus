/**
 * audio_steg.js — CipherNexus v3 Audio Steganography Lab
 * Encodes/Decodes data into 16-bit PCM WAV using LSB.
 * Includes interactive Spectrogram visualizer.
 */

"use strict";

import { strToBytes, bytesToStr } from "./crypto.js";
import { mkLogger } from "./security.js";

let audioCtx = null;
let currentAudioBuffer = null;
let currentPcm16 = null; // Int16Array
let sampleRate = 44100;

// Reusable Analyser nodes
let analyserNode = null;
let sourceNode = null;
let animationId = null;

// Ensure AudioContext is created on user interaction
function getAudioContext() {
    if (!audioCtx) {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    return audioCtx;
}

export async function handleAudioUpload(fileInput) {
    const file = fileInput.files[0];
    if (!file) return;

    const log = mkLogger("audioLog");
    log(`[*] Loading audio file: ${file.name}...`, "muted");

    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const arrayBuffer = e.target.result;
            const ctx = getAudioContext();
            currentAudioBuffer = await ctx.decodeAudioData(arrayBuffer);
            sampleRate = currentAudioBuffer.sampleRate;
            
            log(`[✓] Audio decoded: ${currentAudioBuffer.duration.toFixed(2)}s | ${sampleRate} Hz | ${currentAudioBuffer.numberOfChannels} ch`, "safe");
            
            // Convert to 16-bit PCM immediately for LSB operations
            currentPcm16 = floatTo16BitPCM(currentAudioBuffer.getChannelData(0));
            
            // Draw static waveform or prepare spectrogram
            document.getElementById('audioStatus').innerText = "Audio loaded successfully. Ready to encode/decode.";
            drawSpectrogramPreview();
        } catch (err) {
            log(`[ERROR] Failed to decode audio: ${err.message}`, "err");
        }
    };
    reader.readAsArrayBuffer(file);
}

// Convert Float32Array (-1.0 to 1.0) to Int16Array (-32768 to 32767)
function floatTo16BitPCM(float32Array) {
    const int16Array = new Int16Array(float32Array.length);
    for (let i = 0; i < float32Array.length; i++) {
        let s = Math.max(-1, Math.min(1, float32Array[i]));
        int16Array[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
    }
    return int16Array;
}

export function encodeAudioMessage() {
    const log = mkLogger("audioLog");
    if (!currentPcm16) {
        log("[ERROR] No audio file loaded.", "err");
        return;
    }

    const message = document.getElementById("audioMessageInput")?.value || "";
    if (!message) {
        log("[ERROR] Enter a message to hide.", "err");
        return;
    }

    // Convert message to bytes and prepend length (4 bytes)
    const msgBytes = strToBytes(message);
    const payload = new Uint8Array(4 + msgBytes.length);
    const view = new DataView(payload.buffer);
    view.setUint32(0, msgBytes.length, false);
    payload.set(msgBytes, 4);

    const requiredSamples = payload.length * 8;
    if (requiredSamples > currentPcm16.length) {
        log(`[ERROR] Audio file too short! Need ${requiredSamples} samples, but have ${currentPcm16.length}.`, "err");
        return;
    }

    // LSB Encoding (1 bit per 16-bit sample)
    let sampleIdx = 0;
    for (let i = 0; i < payload.length; i++) {
        let byte = payload[i];
        for (let b = 7; b >= 0; b--) {
            let bit = (byte >> b) & 1;
            // Clear LSB and set to target bit
            currentPcm16[sampleIdx] = (currentPcm16[sampleIdx] & ~1) | bit;
            sampleIdx++;
        }
    }

    log(`[✓] Embedded ${msgBytes.length} bytes into ${sampleIdx} audio samples.`, "safe");

    // Enable download and playback buttons
    const downloadBtn = document.getElementById("audioDownloadBtn");
    if(downloadBtn) downloadBtn.disabled = false;
    
    // Auto-update visualizer to show the noise injection
    drawSpectrogramPreview();
}

export function decodeAudioMessage() {
    const log = mkLogger("audioLog");
    if (!currentPcm16) {
        log("[ERROR] No audio file loaded.", "err");
        return;
    }

    log("[*] Extracting LSB payload...", "muted");

    // Read first 32 bits to get length
    let length = 0;
    for (let i = 0; i < 32; i++) {
        let bit = currentPcm16[i] & 1;
        length = (length << 1) | bit;
    }

    if (length <= 0 || length > 1000000) { // arbitrary sanity check 1MB max
        log(`[ERROR] Invalid hidden message length detected (${length} bytes). Not a stego-file or corrupted.`, "err");
        return;
    }

    let sampleIdx = 32;
    const msgBytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        let byte = 0;
        for (let b = 0; b < 8; b++) {
            let bit = currentPcm16[sampleIdx] & 1;
            byte = (byte << 1) | bit;
            sampleIdx++;
        }
        msgBytes[i] = byte;
    }

    const extractedText = bytesToStr(msgBytes);
    document.getElementById("audioMessageInput").value = extractedText;
    log(`[✓] Successfully extracted message (${length} bytes).`, "safe");
    window.triggerMissionEffect?.('success'); // In case it's part of a mission
}

export function exportWAV() {
    if (!currentPcm16) return;
    const log = mkLogger("audioLog");
    
    const wavBuffer = createWavFile(currentPcm16, sampleRate);
    const blob = new Blob([wavBuffer], { type: "audio/wav" });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement("a");
    a.href = url;
    a.download = "stego_audio.wav";
    a.click();
    URL.revokeObjectURL(url);
    log("[*] Exported lossless WAV file. Compression would destroy the LSB payload.", "info");
}

function createWavFile(pcmData, sampleRate) {
    const wavHeaderLength = 44;
    const buffer = new ArrayBuffer(wavHeaderLength + pcmData.length * 2);
    const view = new DataView(buffer);

    // RIFF chunk descriptor
    writeString(view, 0, 'RIFF');
    view.setUint32(4, 36 + pcmData.length * 2, true);
    writeString(view, 8, 'WAVE');

    // fmt sub-chunk
    writeString(view, 12, 'fmt ');
    view.setUint32(16, 16, true); // Subchunk1Size (16 for PCM)
    view.setUint16(20, 1, true); // AudioFormat (1 for PCM)
    view.setUint16(22, 1, true); // NumChannels (1: mono)
    view.setUint32(24, sampleRate, true); // SampleRate
    view.setUint32(28, sampleRate * 2, true); // ByteRate (SampleRate * NumChannels * BitsPerSample/8)
    view.setUint16(32, 2, true); // BlockAlign (NumChannels * BitsPerSample/8)
    view.setUint16(34, 16, true); // BitsPerSample

    // data sub-chunk
    writeString(view, 36, 'data');
    view.setUint32(40, pcmData.length * 2, true);

    // Write PCM samples
    let offset = 44;
    for (let i = 0; i < pcmData.length; i++, offset += 2) {
        view.setInt16(offset, pcmData[i], true);
    }

    return buffer;
}

function writeString(view, offset, string) {
    for (let i = 0; i < string.length; i++) {
        view.setUint8(offset + i, string.charCodeAt(i));
    }
}

// ─── Spectrogram Visualization ──────────────────────────────────────────

export function playAndVisualize() {
    if (!currentPcm16) return;
    
    const ctx = getAudioContext();
    if (sourceNode) sourceNode.stop();
    if (animationId) cancelAnimationFrame(animationId);

    // Convert Int16 back to Float32 for playback
    const float32 = new Float32Array(currentPcm16.length);
    for (let i = 0; i < currentPcm16.length; i++) {
        float32[i] = currentPcm16[i] / (currentPcm16[i] < 0 ? 0x8000 : 0x7FFF);
    }

    const audioBuf = ctx.createBuffer(1, float32.length, sampleRate);
    audioBuf.copyToChannel(float32, 0);

    sourceNode = ctx.createBufferSource();
    sourceNode.buffer = audioBuf;

    analyserNode = ctx.createAnalyser();
    analyserNode.fftSize = 2048;
    analyserNode.smoothingTimeConstant = 0.8;

    sourceNode.connect(analyserNode);
    analyserNode.connect(ctx.destination);
    
    sourceNode.start();
    drawLiveSpectrogram();
}

function drawLiveSpectrogram() {
    const canvas = document.getElementById("audioCanvas");
    if (!canvas || !analyserNode) return;
    const ctx = canvas.getContext("2d");
    
    const bufferLength = analyserNode.frequencyBinCount;
    const dataArray = new Uint8Array(bufferLength);
    
    const w = canvas.width;
    const h = canvas.height;
    
    // Shift previous image left
    const tempCanvas = document.createElement("canvas");
    tempCanvas.width = w;
    tempCanvas.height = h;
    const tempCtx = tempCanvas.getContext("2d");
    tempCtx.drawImage(canvas, 0, 0, w, h);
    
    ctx.fillStyle = "rgba(13, 13, 26, 1)";
    ctx.fillRect(0, 0, w, h);
    ctx.drawImage(tempCanvas, -2, 0, w, h); // speed of 2px
    
    analyserNode.getByteFrequencyData(dataArray);
    
    // Draw current frequency slice on the right edge
    for (let i = 0; i < bufferLength; i++) {
        let value = dataArray[i];
        let percent = value / 255;
        let y = h - (i / bufferLength) * h;
        
        // Color mapping: dark blue -> cyan -> amber
        let r = Math.floor(percent * 245);
        let g = Math.floor(percent * 166 + (1 - percent) * 50);
        let b = Math.floor((1 - percent) * 200 + percent * 35);
        
        ctx.fillStyle = `rgb(${r},${g},${b})`;
        ctx.fillRect(w - 2, y, 2, h / bufferLength);
    }
    
    animationId = requestAnimationFrame(drawLiveSpectrogram);
}

// Draw a static FFT preview of the entire file (simulated) or just the first few chunks
function drawSpectrogramPreview() {
    const canvas = document.getElementById("audioCanvas");
    if (!canvas || !currentPcm16) return;
    const ctx = canvas.getContext("2d");
    const w = canvas.width;
    const h = canvas.height;
    
    ctx.fillStyle = "rgba(13, 13, 26, 0.5)";
    ctx.fillRect(0, 0, w, h);
    
    // Draw waveform representation
    ctx.lineWidth = 1;
    ctx.strokeStyle = "rgba(78, 201, 232, 0.7)";
    ctx.beginPath();
    
    const step = Math.ceil(currentPcm16.length / w);
    const amp = h / 2;
    
    for(let i=0; i < w; i++) {
        let min = 1.0;
        let max = -1.0;
        for(let j=0; j < step; j++) {
            let idx = (i * step) + j;
            if(idx < currentPcm16.length) {
                let datum = currentPcm16[idx] / 32768.0;
                if(datum < min) min = datum;
                if(datum > max) max = datum;
            }
        }
        ctx.moveTo(i, amp + min * amp);
        ctx.lineTo(i, amp + max * amp);
    }
    ctx.stroke();
    
    // Highlight LSB anomaly zones if payload is present
    // Just a visual representation for the lab context
    ctx.fillStyle = "rgba(245, 166, 35, 0.2)";
    ctx.fillRect(0, 0, w, 4); // Highlight high frequency band
}
