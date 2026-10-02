import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  verifyRequest,
} from "../src/index.js";

const BODY = JSON.stringify({ amount: 100, currency: "USD" });
const CREATED = 1700000000;

test("ed25519 round-trip with body", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    { keyId: "test-ed25519", alg: "ed25519", key: privateKey, created: CREATED },
  );

  assert.match(
    signed.headers["signature-input"],
    /^sig1=\("@method" "@authority" "@path" "content-digest"\);created=1700000000;keyid="test-ed25519";alg="ed25519"$/,
  );
  assert.ok(signed.headers["content-digest"].startsWith("sha-512=:"));
  assert.match(signed.headers["signature"], /^sig1=:[A-Za-z0-9+/=]+:$/);

  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "test-ed25519");
  assert.equal(res.alg, "ed25519");
});

test("hmac-sha256 round-trip without body", () => {
  const secret = secretKey("top-secret");
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/status?verbose=1",
      headers: {},
    },
    { keyId: "test-hmac", alg: "hmac-sha256", key: secret, created: CREATED },
  );

  assert.match(
    signed.headers["signature-input"],
    /^sig1=\("@method" "@authority" "@path"\);created=1700000000;keyid="test-hmac";alg="hmac-sha256"$/,
  );
  assert.ok(!("content-digest" in signed.headers));

  const res = verifyRequest(signed, { key: secret, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("expires parameter is enforced on the wire", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/x", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      expires: CREATED + 300,
    },
  );
  assert.match(signed.headers["signature-input"], /;expires=1700000300/);
  assert.equal(
    verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok,
    true,
  );
  const late = verifyRequest(signed, { key: publicKey, now: CREATED + 301 });
  assert.equal(late.ok, false);
  assert.equal(late.reason, "signature expired");
});
