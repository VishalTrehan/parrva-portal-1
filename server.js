const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const jose = require("node-jose");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());

// Load PEM keys
const PARRVA_PUBLIC_KEY = fs.readFileSync(path.join(__dirname, "keys/payload-public.pem"), "utf8");
const PDC_PUBLIC_KEY = fs.readFileSync(path.join(__dirname, "keys/pdc_public_key.pem"), "utf8");

// Encrypt using RSA-OAEP-256 + A256GCM
async function encryptWithKey(publicKeyPem, payloadObj) {
  const keystore = jose.JWK.createKeyStore();
  const key = await keystore.add(publicKeyPem, "pem");
  const payload = JSON.stringify(payloadObj);

  const jwe = await jose.JWE.createEncrypt(
    {
      format: "compact",
      fields: {
        cty: "application/json",
        enc: "A256GCM",
        alg: "RSA-OAEP-256"
      }
    },
    key
  )
    .update(payload)
    .final();

  return jwe;
}

// 1️⃣ Generate Token
app.post("/api/authenticate", async (req, res) => {
  try {
    const { enrolmentId, password, role } = req.body;

    const encryptedData = await encryptWithKey(PARRVA_PUBLIC_KEY, {
      userId: enrolmentId,
      password,
      role
    });

    const response = await fetch(
      "https://www.careparrva.com/api/parrva/pdc/auth/authenticate",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ data: encryptedData })
      }
    );

    const json = await response.json();
    res.json(json);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Helper: IA vs RA routing
function getRoute(enrolmentId) {
  return enrolmentId.toUpperCase().startsWith("RA") ? "rainput" : "iainput";
}

// 2️⃣ Submit encrypted payload to PDC
async function sendToPDC(enrolmentId, token, endpoint, payloadArray) {
  const encryptedData = await encryptWithKey(PDC_PUBLIC_KEY, payloadArray);

  const route = getRoute(enrolmentId);
  const url = `https://pdc.nseasl.com/advice/${route}/${endpoint}`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      accept: "*/*",
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      Encryption: "true"
    },
    body: JSON.stringify({ data: encryptedData })
  });

  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

// API endpoints
app.post("/api/intraday", async (req, res) => {
  const { enrolmentId, token, trade } = req.body;
  res.json(await sendToPDC(enrolmentId, token, "intraday", [trade]));
});

app.post("/api/singlestock", async (req, res) => {
  const { enrolmentId, token, trade } = req.body;
  res.json(await sendToPDC(enrolmentId, token, "singlestock", [trade]));
});

app.post("/api/derivative", async (req, res) => {
  const { enrolmentId, token, trade } = req.body;
  res.json(await sendToPDC(enrolmentId, token, "derivative", [trade]));
});

app.post("/api/strategy", async (req, res) => {
  const { enrolmentId, token, trade } = req.body;
  res.json(await sendToPDC(enrolmentId, token, "strategy", [trade]));
});

app.post("/api/algoinput", async (req, res) => {
  const { enrolmentId, token, algo } = req.body;
  res.json(await sendToPDC(enrolmentId, token, "algoinput", [algo]));
});

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log("Server running on port", PORT));
