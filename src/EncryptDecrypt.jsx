import React, { useState } from "react";

/**
 * MUST match backend PAYLOAD_ENC_KEY
 * Backend does: sha256(process.env.PAYLOAD_ENC_KEY)
 */
const SECRET_KEY =
  "f3a9b2c8e4d1a7f9b8c6e3d2a1f4c7b9d8e6f5a3b1c2d4e6f8a9b0c1d2e3f4";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/* =========================
   BINARY SAFE BASE64 (FIX)
   ========================= */
function uint8ToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000; // prevents call stack overflow on large payloads

  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, chunk);
  }

  return btoa(binary);
}

function base64ToUint8(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

/* =========================
   KEY (MATCHES NODE BACKEND)
   ========================= */
async function getCryptoKey() {
  // Node: crypto.createHash("sha256").update(KEY).digest()
  const keyBytes = await window.crypto.subtle.digest(
    "SHA-256",
    encoder.encode(SECRET_KEY)
  );

  return window.crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

/* =========================
   ENCRYPT (Backend Compatible)
   Format: base64(iv + tag + ciphertext)
   ========================= */
async function encrypt(text) {
  if (!text) return "";

  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // same as backend
  const key = await getCryptoKey();

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(text)
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);

  // WebCrypto output = ciphertext + 16 byte auth tag (at end)
  const tag = encryptedBytes.slice(-16);
  const ciphertext = encryptedBytes.slice(0, -16);

  // Backend expects: iv + tag + ciphertext
  const combined = new Uint8Array(iv.length + tag.length + ciphertext.length);
  combined.set(iv, 0);
  combined.set(tag, iv.length);
  combined.set(ciphertext, iv.length + tag.length);

  return uint8ToBase64(combined);
}

/* =========================
   DECRYPT (Backend Compatible)
   Accepts:
   1. Raw base64
   2. { _data: "base64" }
   ========================= */
async function decrypt(input) {
  if (!input) return "";

  let base64 = input;

  // Handle API response format: { _data: "..." }
  try {
    const parsed = JSON.parse(input);
    if (parsed && parsed._data) {
      base64 = parsed._data;
    }
  } catch {
    // input is already base64
  }

  const bytes = base64ToUint8(base64);

  // Extract based on backend structure
  const iv = bytes.slice(0, 12);
  const tag = bytes.slice(12, 28);
  const ciphertext = bytes.slice(28);

  const key = await getCryptoKey();

  // WebCrypto requires: ciphertext + tag
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    combined
  );

  return decoder.decode(decryptedBuffer);
}

/* =========================
   UI TOOL
   ========================= */
export default function EncryptDecrypt() {
  const [plainText, setPlainText] = useState("");
  const [encryptedText, setEncryptedText] = useState("");
  const [decryptedText, setDecryptedText] = useState("");
  const [loading, setLoading] = useState(false);

  const handleEncrypt = async () => {
    try {
      setLoading(true);
      const result = await encrypt(plainText);
      setEncryptedText(result);
    } catch (err) {
      console.error("Encryption failed:", err);
      alert("Encryption error. Check console.");
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    try {
      setLoading(true);
      const result = await decrypt(encryptedText);
      setDecryptedText(result);
    } catch (err) {
      console.error("Decryption failed:", err);
      alert("Invalid encrypted data, wrong key, or corrupted payload");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        fontFamily: "monospace",
      }}
    >
      {/* Encrypted Input */}
      <textarea
        style={{ width: "40%", padding: 10 }}
        placeholder="Paste encrypted base64 OR full API response with _data"
        value={encryptedText}
        onChange={(e) => setEncryptedText(e.target.value)}
      />

      {/* Controls */}
      <div
        style={{
          width: "20%",
          background: "#8fd0ea",
          padding: 20,
          display: "flex",
          flexDirection: "column",
          gap: 10,
          justifyContent: "center",
        }}
      >
        <button
          onClick={handleDecrypt}
          disabled={loading}
          style={{ width: "100%", padding: 10, fontWeight: "bold" }}
        >
          {loading ? "Processing..." : "Decrypt"}
        </button>

        <button
          onClick={handleEncrypt}
          disabled={loading}
          style={{ width: "100%", padding: 10, fontWeight: "bold" }}
        >
          {loading ? "Processing..." : "Encrypt"}
        </button>
      </div>

      {/* Output + Plain Input */}
      <div style={{ width: "40%", padding: 10 }}>
        <textarea
          style={{ width: "100%", height: "45%" }}
          placeholder="Decrypted / JSON output"
          value={decryptedText}
          readOnly
        />

        <textarea
          style={{ width: "100%", height: "45%", marginTop: 10 }}
          placeholder='Enter data to encrypt (example: {"name":"yash"})'
          value={plainText}
          onChange={(e) => setPlainText(e.target.value)}
        />
      </div>
    </div>
  );
}
