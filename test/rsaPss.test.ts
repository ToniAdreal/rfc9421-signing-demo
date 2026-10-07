import test from "node:test";
import assert from "node:assert/strict";
import { createSign } from "node:crypto";
import {
  buildSignatureBase,
  exportPublicKeyPem,
  generateEd25519KeyPair,
  generateRsaPssKeyPair,
  importPublicKey,
  parseSignatureInput,
  secretKey,
  signRequest,
  verifyAllLabels,
  verifyRequest,
} from "../src/index.js";

const BODY = JSON.stringify({ amount: 100, currency: "USD" });
const CREATED = 1700000000;

function signRsaPss(body?: string | Buffer) {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body,
    },
    {
      keyId: "test-rsa-pss",
      alg: "rsa-pss-sha512",
      key: privateKey,
      created: CREATED,
    },
  );
  return { publicKey, privateKey, signed };
}

test("rsa-pss-sha512 round-trip with body", () => {
  const { publicKey, signed } = signRsaPss(BODY);

  assert.match(
    signed.headers["signature-input"],
    /;alg="rsa-pss-sha512"$/,
  );
  assert.ok(signed.headers["content-digest"].startsWith("sha-512=:"));
  // 2048-bit RSA signature → 256 raw bytes, base64-wrapped per §4.2.
  assert.match(signed.headers["signature"], /^sig1=:[A-Za-z0-9+/=]+:$/);

  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "test-rsa-pss");
  assert.equal(res.alg, "rsa-pss-sha512");
});

test("signature-input serializes the alg parameter verbatim", () => {
  const { signed } = signRsaPss(BODY);
  assert.equal(
    signed.headers["signature-input"],
    'sig1=("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="test-rsa-pss";alg="rsa-pss-sha512"',
  );
});

test("rsa-pss-sha512 round-trip without body", () => {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/status?verbose=1",
      headers: {},
    },
    {
      keyId: "test-rsa-pss",
      alg: "rsa-pss-sha512",
      key: privateKey,
      created: CREATED,
    },
  );

  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "rsa-pss-sha512");
});

test("PSS signatures are probabilistic: same request signs to different bytes, both verify", () => {
  // RFC 9421 §7.3.5 / §3.3.1: the RSASSA-PSS output is non-deterministic,
  // so re-sign-and-compare is never a valid verification strategy.
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const req = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: BODY,
  };
  const opts = {
    keyId: "test-rsa-pss",
    alg: "rsa-pss-sha512" as const,
    key: privateKey,
    created: CREATED,
  };
  const a = signRequest(req, opts);
  const b = signRequest(req, opts);
  const sigA = a.headers["signature"];
  const sigB = b.headers["signature"];
  assert.notEqual(sigA, sigB);
  assert.equal(verifyRequest(a, { key: publicKey, now: CREATED + 60 }).ok, true);
  assert.equal(verifyRequest(b, { key: publicKey, now: CREATED + 60 }).ok, true);
});

test("wrong RSA key fails with SIGNATURE_MISMATCH", () => {
  const { signed } = signRsaPss(BODY);
  const { publicKey: other } = generateRsaPssKeyPair();

  const res = verifyRequest(signed, { key: other, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("tampered body fails with BODY_DIGEST_MISMATCH", () => {
  const { publicKey, signed } = signRsaPss(BODY);
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
  const { publicKey, signed } = signRsaPss(BODY);
  const raw = Buffer.from(
    signed.headers["signature"].slice("sig1=:".length, -1),
    "base64",
  );
  raw[0] ^= 0x01;
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

test("a PKCS#1 v1.5 signature never verifies as rsa-pss-sha512", () => {
  // PSS wire shape: signing the same base with PKCS#1 v1.5 padding
  // (RFC 9421 §3.3.2) under alg "rsa-pss-sha512" must not verify —
  // the verifier pins PSS padding with a 64-byte salt (RFC 9421 §3.3.1).
  const { publicKey, privateKey, signed } = signRsaPss(BODY);
  const parsed = parseSignatureInput(
    signed.headers["signature-input"],
    "sig1",
  );
  const base = buildSignatureBase(
    parsed.componentIds,
    { method: signed.method, url: signed.url, headers: signed.headers },
    parsed.params,
  );
  const v15 = createSign("sha512").update(base, "utf8").sign(privateKey);
  const swapped = {
    ...signed,
    headers: {
      ...signed.headers,
      signature: `sig1=:${v15.toString("base64")}:`,
    },
  };

  const res = verifyRequest(swapped, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
});

test("rsa-pss signature checked against an ed25519 key is rejected, not confused", () => {
  const { signed } = signRsaPss(BODY);
  const { publicKey: edKey } = generateEd25519KeyPair();

  const res = verifyRequest(signed, { key: edKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  // node:crypto rejects the key/algorithm pairing outright
  // (VERIFICATION_ERROR) — an RSA-PSS signature never verifies
  // *as* ed25519.
  assert.equal(res.code, "VERIFICATION_ERROR");
});

test("rsa-pss signature checked against an hmac secret is rejected, not confused", () => {
  const { signed } = signRsaPss(BODY);
  const hmacSecret = secretKey("another-32-byte-secret-for-hmac-test");

  const res = verifyRequest(signed, { key: hmacSecret, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "VERIFICATION_ERROR");
});

test("keyResolver composes with rsa-pss-sha512", () => {
  const { publicKey, signed } = signRsaPss(BODY);

  const res = verifyRequest(signed, {
    keyResolver: (keyId) =>
      keyId === "test-rsa-pss" ? publicKey : undefined,
    now: CREATED + 60,
  });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "rsa-pss-sha512");
  assert.equal(res.keyId, "test-rsa-pss");
});

test("verifyAllLabels verifies a mixed rsa-pss + ed25519 request", () => {
  const { publicKey: rsaPub, privateKey: rsaPriv } = generateRsaPssKeyPair();
  const { publicKey: edPub, privateKey: edPriv } = generateEd25519KeyPair();
  const req = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: BODY,
  };
  const first = signRequest(req, {
    keyId: "rsa-signer",
    alg: "rsa-pss-sha512",
    key: rsaPriv,
    created: CREATED,
    label: "sig-rsa",
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
    keys: { "sig-rsa": rsaPub, "sig-ed": edPub },
    now: CREATED + 60,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[0].alg, "rsa-pss-sha512");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].alg, "ed25519");
});

test("generateRsaPssKeyPair produces an RSA pair that survives PEM export/import", () => {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  assert.equal(publicKey.asymmetricKeyType, "rsa");
  assert.equal(privateKey.asymmetricKeyType, "rsa");

  const imported = importPublicKey(exportPublicKeyPem(publicKey));
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/status",
      headers: {},
    },
    {
      keyId: "pem-rsa-pss",
      alg: "rsa-pss-sha512",
      key: privateKey,
      created: CREATED,
    },
  );
  const res = verifyRequest(signed, { key: imported, now: CREATED + 60 });
  assert.equal(res.ok, true);
});
