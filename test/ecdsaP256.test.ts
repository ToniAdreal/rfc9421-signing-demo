import test from "node:test";
import assert from "node:assert/strict";
import { createVerify } from "node:crypto";
import {
  buildSignatureBase,
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

/** Re-encode a raw 64-octet r||s value as DER, the pre-fix wire form. */
function rawToDer(raw: Buffer): Buffer {
  const encInt = (x: Buffer): Buffer => {
    let b = x;
    while (b.length > 1 && b[0] === 0x00 && (b[1] & 0x80) === 0) b = b.subarray(1);
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
    return Buffer.concat([Buffer.from([0x02, b.length]), b]);
  };
  const body = Buffer.concat([encInt(raw.subarray(0, 32)), encInt(raw.subarray(32, 64))]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

test("new ecdsa-p256-sha256 signatures are the 64-octet raw r||s form of RFC 9421 §3.3.4", () => {
  const { publicKey, signed } = signP256(BODY);
  const raw = Buffer.from(
    signed.headers["signature"].slice("sig1=:".length, -1),
    "base64",
  );
  // §3.3.4: r and s each padded to 32 octets — never a DER value, whose
  // length varies with the integers (70–72 octets for P-256).
  assert.equal(raw.length, 64);
  // Independent check with node:crypto alone over the rebuilt signature
  // base: the wire bytes verify as an ieee-p1363 (raw r||s) signature,
  // and do NOT verify when read as DER — the encoding itself is pinned,
  // not just this library's self-consistent round-trip.
  const base = buildSignatureBase(
    ["@method", "@authority", "@path", "content-digest"],
    signed,
    { created: CREATED, keyid: "test-p256", alg: "ecdsa-p256-sha256" },
  );
  const okP1363 = createVerify("sha256")
    .update(base, "utf8")
    .verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, raw);
  assert.equal(okP1363, true);
  let okDer = false;
  try {
    okDer = createVerify("sha256").update(base, "utf8").verify(publicKey, raw);
  } catch {
    okDer = false;
  }
  assert.equal(okDer, false);
});

test("DER-encoded signatures (the pre-fix wire form) are rejected, with no fallback", () => {
  const { publicKey, signed } = signP256(BODY);
  const raw = Buffer.from(
    signed.headers["signature"].slice("sig1=:".length, -1),
    "base64",
  );
  const der = rawToDer(raw);
  assert.notEqual(der.length, 64);
  const tampered = {
    ...signed,
    headers: {
      ...signed.headers,
      signature: `sig1=:${der.toString("base64")}:`,
    },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
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
