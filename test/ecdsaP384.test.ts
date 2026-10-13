import test from "node:test";
import assert from "node:assert/strict";
import { createSign, createVerify, type KeyObject } from "node:crypto";
import {
  buildSignatureBase,
  contentDigest,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkP384,
  exportPublicKeyPem,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateP384KeyPair,
  importPublicKey,
  importPublicKeyJwkP384,
  signatureInputValue,
  signRequest,
  verifyRequest,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

const BODY = JSON.stringify({ amount: 100, currency: "USD" });
const CREATED = 1700000000;

function signP384(body?: string | Buffer) {
  const { publicKey, privateKey } = generateP384KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body,
    },
    {
      keyId: "test-p384",
      alg: "ecdsa-p384-sha384",
      key: privateKey,
      created: CREATED,
    },
  );
  return { publicKey, privateKey, signed };
}

test("ecdsa-p384-sha384 round-trip with body", () => {
  const { publicKey, signed } = signP384(BODY);

  assert.match(
    signed.headers["signature-input"],
    /;alg="ecdsa-p384-sha384"$/,
  );
  assert.ok(signed.headers["content-digest"].startsWith("sha-512=:"));
  assert.match(signed.headers["signature"], /^sig1=:[A-Za-z0-9+/=]+:$/);

  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "test-p384");
  assert.equal(res.alg, "ecdsa-p384-sha384");
});

test("signature-input serializes the alg parameter verbatim", () => {
  const { signed } = signP384(BODY);
  assert.match(
    signed.headers["signature-input"],
    /^sig1=\("@method" "@authority" "@path" "content-digest"\);created=1700000000;keyid="test-p384";alg="ecdsa-p384-sha384"$/,
  );
});

test("new ecdsa-p384-sha384 signatures are the 96-octet raw r||s form of RFC 9421 §3.3.5", () => {
  const { publicKey, signed } = signP384(BODY);
  const raw = Buffer.from(
    signed.headers["signature"].slice("sig1=:".length, -1),
    "base64",
  );
  // §3.3.5: r and s each padded to 48 octets — never a DER value, whose
  // length varies with the integers, and never the 64-octet P-256 width.
  assert.equal(raw.length, 96);
  // Independent check with node:crypto alone over the rebuilt signature
  // base: the wire bytes verify as an ieee-p1363 (raw r||s) signature
  // under SHA-384, and do NOT verify when read as DER.
  const base = buildSignatureBase(
    ["@method", "@authority", "@path", "content-digest"],
    signed,
    { created: CREATED, keyid: "test-p384", alg: "ecdsa-p384-sha384" },
  );
  const okP1363 = createVerify("sha384")
    .update(base, "utf8")
    .verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, raw);
  assert.equal(okP1363, true);
  let okDer = false;
  try {
    okDer = createVerify("sha384").update(base, "utf8").verify(publicKey, raw);
  } catch {
    okDer = false;
  }
  assert.equal(okDer, false);
});

test("ecdsa-p384-sha384 round-trip without body", () => {
  const { publicKey, privateKey } = generateP384KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/status?verbose=1",
      headers: {},
    },
    { keyId: "test-p384", alg: "ecdsa-p384-sha384", key: privateKey, created: CREATED },
  );

  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ecdsa-p384-sha384");
});

test("wrong P-384 key fails with SIGNATURE_MISMATCH", () => {
  const { signed } = signP384(BODY);
  const { publicKey: other } = generateP384KeyPair();

  const res = verifyRequest(signed, { key: other, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("tampered body fails with BODY_DIGEST_MISMATCH", () => {
  const { publicKey, signed } = signP384(BODY);
  const tampered = {
    ...signed,
    headers: { ...signed.headers },
    body: JSON.stringify({ amount: 999, currency: "USD" }),
  };

  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("a P-256 signature re-labelled as ecdsa-p384-sha384 fails with SIGNATURE_MISMATCH", () => {
  // The 64-octet P-256 width is pinned separately from the 96-octet
  // P-384 width: re-labelling cannot smuggle the narrower signature
  // past the P-384 length guard.
  const { privateKey: p256Priv } = generateP256KeyPair();
  const { publicKey: p384Pub } = generateP384KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    { keyId: "test-p256", alg: "ecdsa-p256-sha256", key: p256Priv, created: CREATED },
  );
  const relabelled: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        'alg="ecdsa-p256-sha256"',
        'alg="ecdsa-p384-sha384"',
      ),
    },
  };
  const res = verifyRequest(relabelled, { key: p384Pub, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("p384 signature checked against an ed25519 key is rejected, not confused", () => {
  const { signed } = signP384(BODY);
  const { publicKey: edKey } = generateEd25519KeyPair();

  const res = verifyRequest(signed, { key: edKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "VERIFICATION_ERROR");
});

test("p384 signature checked against a P-256 key never verifies", () => {
  const { signed } = signP384(BODY);
  const { publicKey: p256Pub } = generateP256KeyPair();

  const res = verifyRequest(signed, { key: p256Pub, now: CREATED + 60 });
  assert.equal(res.ok, false);
});

/**
 * Sign like a foreign signer that never emits the optional `alg`
 * parameter: build the signature base with params that carry no `alg`,
 * then sign with node:crypto directly (SHA-384, raw r||s per RFC 9421
 * §3.3.5).
 */
function signP384WithoutAlg(
  req: RequestLike,
  privateKey: KeyObject,
): SignedHttpRequest {
  const covered = ["@method", "@authority", "@path", "content-digest"];
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    headers[k] = Array.isArray(v) ? v.join(", ") : v;
  }
  headers["content-digest"] = contentDigest(req.body!);
  const params = { created: CREATED, keyid: "test-p384" }; // no alg, ever
  const base = buildSignatureBase(
    covered,
    { method: req.method, url: req.url, headers, body: req.body },
    params,
  );
  const sig = createSign("sha384")
    .update(base, "utf8")
    .sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
  headers["signature-input"] = signatureInputValue("sig1", covered, params);
  headers["signature"] = `sig1=:${sig.toString("base64")}:`;
  assert.ok(!headers["signature-input"].includes("alg="));
  return { method: req.method, url: req.url, headers, body: req.body };
}

test("algFallback \"infer\" maps a P-384 key to ecdsa-p384-sha384", () => {
  const { publicKey, privateKey } = generateP384KeyPair();
  const wire = signP384WithoutAlg(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    privateKey,
  );
  const res = verifyRequest(wire, {
    key: publicKey,
    now: CREATED + 60,
    algFallback: "infer",
  });
  assert.equal(res.ok, true, `expected ok, got ${JSON.stringify(res)}`);
  assert.equal(res.alg, "ecdsa-p384-sha384");
});

test("algFallback \"infer\" rejects a wire ecdsa-p384-sha384 alg paired with a P-256 key", () => {
  const { signed } = signP384(BODY);
  const { publicKey: p256Pub } = generateP256KeyPair();
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: p256Pub,
        now: CREATED + 60,
        algFallback: "infer",
      }),
    /incompatible with the configured key/,
  );
});

test("P-384 JWK round-trip: export, import, verify", () => {
  const { publicKey, signed } = signP384(BODY);
  const jwk = exportPublicKeyJwkP384(publicKey);
  assert.equal(jwk.kty, "EC");
  assert.equal(jwk.crv, "P-384");
  // P-384 coordinates are 48 bytes each.
  assert.equal(Buffer.from(jwk.x, "base64url").length, 48);
  assert.equal(Buffer.from(jwk.y, "base64url").length, 48);

  const wireKey = JSON.parse(JSON.stringify(jwk)) as unknown;
  const imported = importPublicKeyJwkP384(wireKey);
  const res = verifyRequest(signed, { key: imported, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ecdsa-p384-sha384");
});

test("P-384 JWK helpers refuse other curves and private material", () => {
  const { publicKey: p256Pub } = generateP256KeyPair();
  assert.throws(
    () => exportPublicKeyJwkP384(p256Pub),
    /expected a P-384 public KeyObject/,
  );
  const p256Jwk = exportPublicKeyJwkP256(p256Pub);
  assert.throws(
    () => importPublicKeyJwkP384(p256Jwk),
    /expected crv "P-384"/,
  );
  const { publicKey: p384Pub } = generateP384KeyPair();
  const withPrivate = { ...exportPublicKeyJwkP384(p384Pub), d: "AAAA" };
  assert.throws(
    () => importPublicKeyJwkP384(withPrivate),
    /private key material/,
  );
});

test("generateP384KeyPair produces a secp384r1 pair that survives PEM export/import", () => {
  const { publicKey, privateKey } = generateP384KeyPair();
  assert.equal(publicKey.asymmetricKeyType, "ec");
  assert.equal(publicKey.asymmetricKeyDetails?.namedCurve, "secp384r1");
  assert.equal(privateKey.asymmetricKeyDetails?.namedCurve, "secp384r1");

  const imported = importPublicKey(exportPublicKeyPem(publicKey));
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/status",
      headers: {},
    },
    { keyId: "pem-p384", alg: "ecdsa-p384-sha384", key: privateKey, created: CREATED },
  );
  const res = verifyRequest(signed, { key: imported, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("keyResolver composes with ecdsa-p384-sha384", () => {
  const { publicKey, signed } = signP384(BODY);

  const res = verifyRequest(signed, {
    keyResolver: (keyId) =>
      keyId === "test-p384" ? publicKey : undefined,
    now: CREATED + 60,
  });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ecdsa-p384-sha384");
  assert.equal(res.keyId, "test-p384");
});
