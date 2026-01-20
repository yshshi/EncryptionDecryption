import React, { useState } from "react";

/**
 * MUST match backend PAYLOAD_ENC_KEY
 * Frontend will SHA-256 hash this key to match backend
 */
const SECRET_KEY = "9f1c3e5a7b2d4f8e6c0a1b9d5e7f2a4c";

/**
 * Convert hex string to Uint8Array (fallback)
 */
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Get crypto key matching backend AES-256-GCM (SHA-256 digest)
 */
async function getCryptoKey() {
  const keyBytes = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(SECRET_KEY)
  );

  return window.crypto.subtle.importKey(
    "raw",
    keyBytes,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt text to backend-compatible format (IV + TAG + CIPHER)
 */
async function encrypt(text) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await getCryptoKey();

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(text)
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);

  // SubtleCrypto: last 16 bytes are tag
  const tag = encryptedBytes.slice(-16);
  const ciphertext = encryptedBytes.slice(0, -16);

  // Combine in Node backend order: iv + tag + ciphertext
  const combined = new Uint8Array(iv.length + tag.length + ciphertext.length);
  combined.set(iv, 0);
  combined.set(tag, iv.length);
  combined.set(ciphertext, iv.length + tag.length);

  return btoa(String.fromCharCode(...combined));
}


/**
 * Decrypt backend-compatible AES-256-GCM payload
 */
async function decrypt(input) {
  let base64 = input;

  try {
    const parsed = JSON.parse(input);
    if (parsed._data) base64 = parsed._data;
  } catch {}

  const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));

  const iv = bytes.slice(0, 12);
  const tag = bytes.slice(12, 28);
  const ciphertext = bytes.slice(28);

  const key = await getCryptoKey();

  // SubtleCrypto expects ciphertext + tag
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


export default function EncryptDecrypt() {
  const [plainText, setPlainText] = useState("");
  const [encryptedText, setEncryptedText] = useState("");
  const [decryptedText, setDecryptedText] = useState("");

  const handleEncrypt = async () => {
    try {
      const result = await encrypt(plainText);
      setEncryptedText(result);
    } catch (err) {
      console.error("❌ Encryption failed:", err);
      alert("Encryption error, check console.");
    }
  };

  const handleDecrypt = async () => {
    try {
      const result = await decrypt(encryptedText);
      setDecryptedText(result);
    } catch (err) {
      console.error("❌ Decryption failed:", err);
      alert("Invalid encrypted data or wrong key");
    }
  };

  return (
    <div style={{ display: "flex", height: "100vh", fontFamily: "monospace" }}>
      <textarea
        style={{ width: "40%", padding: 10 }}
        placeholder="Encrypted data (_data or base64)"
        value={encryptedText}
        onChange={e => setEncryptedText(e.target.value)}
      />

      <div style={{ width: "20%", background: "#8fd0ea", padding: 20 }}>
        <button onClick={handleDecrypt} style={{ width: "100%", marginBottom: 10 }}>
          Decrypt
        </button>
        <button onClick={handleEncrypt} style={{ width: "100%" }}>
          Encrypt
        </button>
      </div>

      <div style={{ width: "40%", padding: 10 }}>
        <textarea
          style={{ width: "100%", height: "45%" }}
          placeholder="Decrypted / JSON output"
          value={decryptedText}
          readOnly
        />
        <textarea
          style={{ width: "100%", height: "45%", marginTop: 10 }}
          placeholder="Enter data to be encrypted"
          value={plainText}
          onChange={e => setPlainText(e.target.value)}
        />
      </div>
    </div>
  );
}
