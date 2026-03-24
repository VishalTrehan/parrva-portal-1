process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const fs = require("fs");
const path = require("path");
const { webcrypto } = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// ======================================================
// LOAD CORRECT PUBLIC KEYS
// ======================================================

// AUTH KEY (PaRRVA Token Generation) — AtCTj4Oo...
const AUTH_PUBLIC_KEY = fs.readFileSync(
  path.join(__dirname, "keys/payload-public.pem"),
  "utf8"
);

// PDC KEY (Advice Submission) — ojQVs6yFZ...
const PDC_PUBLIC_KEY = fs.readFileSync(
  path.join(__dirname, "keys/pdc_public_key.pem"),
  "utf8"
);

// ======================================================
// LOW-LEVEL HELPERS (EXACTLY LIKE POSTMAN SCRIPT)
// ======================================================
function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
  const bin = Buffer.from(b64, "base64");
  return new Uint8Array(bin).buffer;
}

function base64urlEncode(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// ======================================================
// JWE ENCRYPTION (1:1 PORT OF POSTMAN encryptJWE)
// ======================================================
async function encryptJWE(payload, publicKeyPem) {
  const subtle = webcrypto.subtle;

  // CEK: AES-GCM 256
  const cek = await subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"]
  );

  // Import RSA public key
  const publicKey = await subtle.importKey(
    "spki",
    pemToArrayBuffer(publicKeyPem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );

  // Encrypt CEK with RSA-OAEP
  const exportedCek = await subtle.exportKey("raw", cek);
  const encryptedKey = await subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    exportedCek
  );

  // Protected header
  const header = {
    alg: "RSA-OAEP-256",
    enc: "A256GCM"
  };
  const encodedHeader = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(header))
  );

  // IV
  const iv = webcrypto.getRandomValues(new Uint8Array(12));

  // Encrypt payload with AES-GCM, AAD = encodedHeader
  const encryptedPayload = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: new TextEncoder().encode(encodedHeader)
    },
    cek,
    new TextEncoder().encode(payload)
  );

  const encryptedBuf = new Uint8Array(encryptedPayload);
  const ciphertext = encryptedBuf.slice(0, encryptedBuf.length - 16);
  const tag = encryptedBuf.slice(encryptedBuf.length - 16);

  const jwe = [
    encodedHeader,
    base64urlEncode(encryptedKey),
    base64urlEncode(iv),
    base64urlEncode(ciphertext),
    base64urlEncode(tag)
  ].join(".");

  return jwe;
}

// ======================================================
// AUTHENTICATION (TOKEN GENERATION)
// ======================================================
app.post("/api/authenticate", async (req, res) => {
  try {
    const { enrolmentId, password, role } = req.body;

    const payloadObj = {
      username: enrolmentId,
      password,
      role
    };

    const plainPayload = JSON.stringify(payloadObj);

    const jwe = await encryptJWE(plainPayload, AUTH_PUBLIC_KEY);

    const resp = await fetch(
      "https://careparrva.com/api/parrva/pdc/auth/authenticate",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ data: jwe })
      }
    );

    const text = await resp.text();
    let json;

    try {
      json = JSON.parse(text);
    } catch {
      return res.status(500).json({
        error: "Non-JSON response from PaRRVA",
        raw: text
      });
    }

    return res.status(resp.ok ? 200 : 500).json(json);
  } catch (err) {
    console.error("Auth error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// ======================================================
// GENERIC FUNCTION FOR PDC ADVICE SUBMISSION
// ======================================================
async function submitAdvice(req, res, endpoint) {
  try {
    const { trade, token } = req.body;

    const plainPayload = JSON.stringify(trade);
    const jwe = await encryptJWE(plainPayload, PDC_PUBLIC_KEY);

    const resp = await fetch(`https://pdc.nseasl.com${endpoint}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify([{ data: jwe }])
    });

    const text = await resp.text();
    let json;

    try {
      json = JSON.parse(text);
    } catch {
      return res.status(500).json({
        error: "Non-JSON response from PDC",
        raw: text
      });
    }

    return res.status(resp.ok ? 200 : 500).json(json);
  } catch (err) {
    console.error("Advice error:", err);
    return res.status(500).json({ error: err.message });
  }
}

// Intraday
app.post("/api/intraday", (req, res) =>
  submitAdvice(req, res, "/advice/iainput/intraday")
);

// Single Stock
app.post("/api/singlestock", (req, res) =>
  submitAdvice(req, res, "/advice/iainput/singlestock")
);

// Derivative
app.post("/api/derivative", (req, res) =>
  submitAdvice(req, res, "/advice/iainput/derivative")
);

// Strategy
app.post("/api/strategy", (req, res) =>
  submitAdvice(req, res, "/advice/iainput/strategy")
);

// Algo Input
app.post("/api/algoinput", (req, res) =>
  submitAdvice(req, res, "/advice/iainput/algoinput")
);

// ======================================================
// START SERVER
// ======================================================
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
