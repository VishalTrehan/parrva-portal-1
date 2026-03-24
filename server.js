process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const jose = require("node-jose");
const fs = require("fs");
const path = require("path");

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
// GENERIC JWE ENCRYPTION FUNCTION
// ======================================================
async function encryptWithKey(publicKeyPem, payloadObj) {
  const keyStore = jose.JWK.createKeyStore();
  const key = await keyStore.add(publicKeyPem, "pem");

  const payload = JSON.stringify(payloadObj);

  const jwe = await jose.JWE.createEncrypt(
    {
      format: "compact",
      fields: {
        alg: "RSA-OAEP-256",
        enc: "A256GCM"
      }
    },
    key
  )
    .update(payload)
    .final();

  return jwe;
}

// ======================================================
// AUTHENTICATION (TOKEN GENERATION)
// ======================================================
app.post("/api/authenticate", async (req, res) => {
  try {
    const { enrolmentId, password, role } = req.body;

    // PaRRVA expects "username", not "userId"
    const payload = {
      username: enrolmentId,
      password,
      role
    };

    const jwe = await encryptWithKey(AUTH_PUBLIC_KEY, payload);

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

    const jwe = await encryptWithKey(PDC_PUBLIC_KEY, trade);

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

// ======================================================
// ADVICE ROUTES (MATCHING POSTMAN COLLECTION)
// ======================================================

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
