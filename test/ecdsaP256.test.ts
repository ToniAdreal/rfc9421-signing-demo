import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyPem,
  generateEd25519KeyPair,
  generateP256KeyPair,
  importPublicKey,
  secretKey,
  signRequest,
  verifyAllLabels,
  verifyRequest,
} from "../src/index.js";

const BODY = JSON.stringify({ amount: 100, currency: "USD" });
const CREATED = 1700000000;

function signP256(body?: string | Buffer) {
  const { publicKey, privateKey } = generateP256KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body,
    },
    {
      keyId: "test-p256",
      alg: "ecdsa-p256-sha256",
      key: privateKey,
      created: CREATED,
    },
  );
  return { publicKey, privateKey, signed };
}

test("ecdsa-p256-sha256 round-trip with body", () => {
  const { publicKey, signed } = signP256(BODY);

  assert.match(
    signed.headers["signature-input"],
    /;alg="ecdsa-p256-sha256"$/,
  );
  assert.ok(signed.headers["content-digest"].startsWith("sha-512=:"));
  assert.match(signed.headers["signature"], /^sig1=:[A-Za-z0-9+/=]+:$/);

  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "test-p256");
  assert.equal(res.alg, "ecdsa-p256-sha256");
});

test("signature-input serializes the alg parameter verbatim", () => {
  const { signed } = signP256(BODY);
  assert.match(
    signed.headers["signature-input"],
    /^sig1=\("@method" "@authority" "@path" "content-digest"\);created=1700000000;keyid="test-p256";alg="ecdsa-p256-sha256"$/,
  );
});

test("ecdsa-p256-sha256 round-trip without body", () => {
  const { publicKey, privateKey } = generateP256KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/status?verbose=1",
      headers: {},
    },
    { keyId: "test-p256", alg: "ecdsa-p256-sha256", key: privateKey, created: CREATED },
  );

  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ecdsa-p256-sha256");
});

test("wrong P-256 key fails with SIGNATURE_MISMATCH", () => {
  const { signed } = signP256(BODY);
  const { publicKey: other } = generateP256KeyPair();

  const res = verifyRequest(signed, { key: other, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("tampered body fails with BODY_DIGEST_MISMATCH", () => {
  const { publicKey, signed } = signP256(BODY);
  const tampered = {
    ...signed,
    headers: { ...signed.headers },
    body: JSON.stringify({ amount: 999, currency: "USD" }),
  };

  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("flipped signature byte fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, signed } = signP256(BODY);
  const raw = Buffer.from(
    signed.headers["signature"].slice("sig1=:".length, -1),
    "base64",
  );
  raw[raw.length - 1] ^= 0x01;
  const tampered = {
    ...signed,
    headers: {
      ...signed.headers,
      signature: `sig1=:${raw.toString("base64")}:`,
    },
  };

  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("p256 signature checked against an ed25519 key is rejected, not confused", () => {
  const { signed } = signP256(BODY);
  const { publicKey: edKey } = generateEd25519KeyPair();

  const res = verifyRequest(signed, { key: edKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  // node:crypto rejects the key/algorithm pairing outright
  // (VERIFICATION_ERROR) — it never verifies the p256 signature
  // *as* ed25519.
  assert.equal(res.code, "VERIFICATION_ERROR");
});

test("p256 signature checked against an hmac secret is rejected, not confused", () => {
  const { signed } = signP256(BODY);
  const hmacSecret = secretKey("another-32-byte-secret-for-hmac-test");

  const res = verifyRequest(signed, { key: hmacSecret, now: CREATED + 60 });
  assert.equal(res.ok, false);
  // An ecdsa-p256-sha256 signature never passes as hmac-sha256.
  assert.equal(res.code, "VERIFICATION_ERROR");
});

test("keyResolver composes with ecdsa-p256-sha256", () => {
  const { publicKey, signed } = signP256(BODY);

  const res = verifyRequest(signed, {
    keyResolver: (keyId) =>
      keyId === "test-p256" ? publicKey : undefined,
    now: CREATED + 60,
  });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ecdsa-p256-sha256");
  assert.equal(res.keyId, "test-p256");
});

test("verifyAllLabels verifies a mixed p256 + ed25519 request", () => {
  const { publicKey: p256Pub, privateKey: p256Priv } = generateP256KeyPair();
  const { publicKey: edPub, privateKey: edPriv } = generateEd25519KeyPair();
  const req = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: BODY,
  };
  const first = signRequest(req, {
    keyId: "p256-signer",
    alg: "ecdsa-p256-sha256",
    key: p256Priv,
    created: CREATED,
    label: "sig-p256",
  });
  const second = signRequest(req, {
    keyId: "ed-signer",
    alg: "ed25519",
    key: edPriv,
    created: CREATED,
    label: "sig-ed",
  });
  const merged = {
    ...first,
    headers: {
      ...first.headers,
      "signature-input": `${first.headers["signature-input"]}, ${second.headers["signature-input"]}`,
      signature: `${first.headers["signature"]}, ${second.headers["signature"]}`,
    },
  };

  const results = verifyAllLabels(merged, {
    keys: { "sig-p256": p256Pub, "sig-ed": edPub },
    now: CREATED + 60,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[0].alg, "ecdsa-p256-sha256");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].alg, "ed25519");
});

test("generateP256KeyPair produces a P-256 EC pair that survives PEM export/import", () => {
  const { publicKey, privateKey } = generateP256KeyPair();
  assert.equal(publicKey.asymmetricKeyType, "ec");
  assert.equal(privateKey.asymmetricKeyType, "ec");

  const imported = importPublicKey(exportPublicKeyPem(publicKey));
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/status",
      headers: {},
    },
    { keyId: "pem-p256", alg: "ecdsa-p256-sha256", key: privateKey, created: CREATED },
  );
  const res = verifyRequest(signed, { key: imported, now: CREATED + 60 });
  assert.equal(res.ok, true);
});
