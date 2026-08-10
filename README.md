# CipherNexus

CipherNexus is a browser-based steganography and cryptography learning suite. It combines interactive visualizations, practical tools, and real-world attack references to teach data hiding, steganalysis, encryption modes, hashing, disk encryption, and password cracking.

## What this project contains

- **Steganography Lab**: Hide and extract messages inside PNG images using multi-bit LSB embedding with optional XOR passphrase protection.
- **Steganalysis Lab**: Detect hidden content using chi-square, RS analysis, histogram forensics, sample pair analysis, and compare-original vs stego visualizations.
- **Audio Steganography**: Embed secret text into WAV audio LSB samples, visualize the spectrogram, and export stego WAV files.
- **Hashing & Integrity Lab**: Live hashing for SHA-1, SHA-256, SHA-384, SHA-512, avalanche effect demonstrator, file integrity verification, and HMAC authentication.
- **Encoding Lab**: Convert live between plaintext, Base64, URL encoding, hex, and binary formats.
- **AES Modes Lab**: Demonstrate AES ECB, CBC, CTR, and GCM modes, including IV/nonce behavior, block chaining, and pattern leaks.
- **RSA Lab**: Generate RSA key pairs, encrypt/decrypt messages, sign/verify data, and explore RSA math.
- **Disk Encryption Lab**: PBKDF2 key derivation, entropy visualization, and passphrase strength estimation.
- **Disk Pentest Reference**: Illustrate common disk encryption attack vectors and provide real command-line forensic references.
- **Hash Cracker Lab**: Browser-based MD5, SHA-1, and SHA-256 cracking with dictionary and mask attacks using Web Workers.
- **Theory Reference**: Reference material for steganography, AES, RSA, entropy, and cold boot attacks.

## Project structure

- `index.html` — main application interface and module layout.
- `style.css` — UI styling and responsive layout.
- `js/` — JavaScript modules powering UI interactions, steganography, cryptography, audio processing, hashing, and cracking logic.
- `wasm/steg_core.js` — WebAssembly steganography core for optimized image embedding and extraction.
- `lib/three.module.min.js` — Three.js runtime for the animated background scene.
- `.vscode/settings.json` — editor settings for Live Server port configuration.
- `package.json` / `package-lock.json` — runtime dependency metadata. The UI is browser-first; no build step is required for normal use.
- `LICENSE` — MIT license.

## Getting started

### Option 1: Open directly

1. Open `index.html` in a modern browser such as Chrome, Edge, or Firefox.
2. Click **INITIALIZE SYSTEM** and choose a module from the sidebar.

### Option 2: Serve locally (recommended)

Serving the project from a local web server avoids browser file origin restrictions and is the recommended method.

#### With Python 3

```powershell
cd CipherNexus
python -m http.server 5500
```

Then open `http://localhost:5500` in your browser.

#### With Node.js

If you want to run a local static server:

```powershell
cd CipherNexus
npm install
npx http-server . -p 5500
```

Then open `http://localhost:5500`.

> Note: `npm install` is optional for normal app usage. The browser UI itself does not require a build step.

## Usage highlights

- Use the **Hide & Extract** module to embed secret text into PNG images and then recover it using the same LSB depth and optional passphrase.
- Use the **Steg Analysis** module to examine suspicious images and reveal hidden data patterns through statistical forensic techniques.
- Use the **AES Modes Lab** to compare encryption output for ECB, CBC, CTR, and GCM and learn why AES-GCM is the modern recommendation.
- Use the **RSA Lab** to derive RSA keys from primes, encrypt/decrypt messages, and verify digital signatures.
- Use the **Hashing & Integrity Lab** to compare hash algorithms, test HMACs, and validate file integrity.

## Browser support

This project is designed for modern browsers that support the Web Crypto API, Web Workers, WebAssembly, and the HTML5 File API.

## License

This project is licensed under the MIT License. See `LICENSE` for details.
