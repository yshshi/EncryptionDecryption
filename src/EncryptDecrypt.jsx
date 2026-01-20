import React, { useState } from "react";

/**
 * MUST match backend PAYLOAD_ENC_KEY
 * 32 bytes = AES-256
 */
const SECRET_KEY =
  "9f1c3e5a7b2d4f8e6c0a1b9d5e7f2a4c";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

async function getCryptoKey() {

  return window.crypto.subtle.importKey(
    "raw",
    encoder.encode(SECRET_KEY),
    "AES-GCM",
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(text) {

  const iv = window.crypto.getRandomValues(new Uint8Array(12));


  const key = await getCryptoKey();

  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(text)
  );

  const encryptedBytes = new Uint8Array(encrypted);
 

  const combined = new Uint8Array(iv.length + encryptedBytes.length);
  combined.set(iv, 0);
  combined.set(encryptedBytes, iv.length);

  const base64 = btoa(String.fromCharCode(...combined));


  return base64;
}

async function decrypt(input) {


  let base64 = input;

  // ✅ Handle wrapped JSON { "_data": "..." }
  try {
    const parsed = JSON.parse(input);
    if (parsed._data) {
     
      base64 = parsed._data;
    }
  } catch {
    console.log("ℹ️ Input is not JSON, treating as base64");
  }



  const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));


  const iv = bytes.slice(0, 12);
  const encrypted = bytes.slice(12);


  const key = await getCryptoKey();

  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    encrypted
  );

  const result = decoder.decode(decrypted);


  return result;
}

export default function EncryptDecrypt() {
  const [plainText, setPlainText] = useState("");
  const [encryptedText, setEncryptedText] = useState("");
  const [decryptedText, setDecryptedText] = useState("");

  const handleEncrypt = async () => {

    const result = await encrypt(plainText);
    setEncryptedText(result);
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
