import test from "node:test";
import assert from "node:assert/strict";
import { createSign, createVerify, type KeyObject } from "node:crypto";
import {
  addSignature,
  buildSignatureBase,
  contentDigest,
  exportPublicKeyJwkP384,
  exportPublicKeyJwkP521,
  exportPublicKeyPem,
  generateEd25519KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  importPublicKey,
  importPublicKeyJwkP521,
  signatureInputValue,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

const BODY = JSON.stringify({ amount: 100, currency: "USD" });
const CREATED = 1700000000;

function signP521(body?: string | Buffer) {
  const { publicKey, privateKey } = generateP521KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body,
    },
    {
      keyId: "test-p521",
      alg: "ecdsa-p521-sha512",
      key: privateKey,
      created: CREATED,
    },
  );
  return { publicKey, privateKey, signed };
}

test("ecdsa-p521-sha512 round-trip with body", () => {
  const { publicKey, signed } = signP521(BODY);

  assert.match(
    signed.headers["signature-input"],
    /;alg="ecdsa-p521-sha512"$/,
  );
  assert.ok(signed.headers["content-digest"].startsWith("sha-512=:"));
  assert.match(signed.headers["signature"], /^sig1=:[A-Za-z0-9+/=]+:$/);

  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "test-p521");
  assert.equal(res.alg, "ecdsa-p521-sha512");
});

test("signature-input serializes the alg parameter verbatim", () => {
  const { signed } = signP521(BODY);
  assert.match(
    signed.headers["signature-input"],
    /^sig1=\("@method" "@authority" "@path" "content-digest"\);created=1700000000;keyid="test-p521";alg="ecdsa-p521-sha512"$/,
  );
});

test("new ecdsa-p521-sha512 signatures are the 132-octet raw r||s form of RFC 9421 §3.3.6", () => {
  const { publicKey, signed } = signP521(BODY);
  const raw = Buffer.from(
    signed.headers["signature"].slice("sig1=:".length, -1),
    "base64",
  );
  // §3.3.6: r and s each padded to 66 octets — never a DER value, whose
  // length varies with the integers, and never the 96-octet P-384 width.
  assert.equal(raw.length, 132);
  // Independent check with node:crypto alone over the rebuilt signature
  // base: the wire bytes verify as an ieee-p1363 (raw r||s) signature
  // under SHA-512, and do NOT verify when read as DER.
  const base = buildSignatureBase(
    ["@method", "@authority", "@path", "content-digest"],
    signed,
    { created: CREATED, keyid: "test-p521", alg: "ecdsa-p521-sha512" },
  );
  const okP1363 = createVerify("sha512")
    .update(base, "utf8")
    .verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, raw);
  assert.equal(okP1363, true);
  let okDer = false;
  try {
    okDer = createVerify("sha512").update(base, "utf8").verify(publicKey, raw);
  } catch {
    okDer = false;
  }
  assert.equal(okDer, false);
});

test("ecdsa-p521-sha512 round-trip without body", () => {
  const { publicKey, privateKey } = generateP521KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/status?verbose=1",
      headers: {},
    },
    { keyId: "test-p521", alg: "ecdsa-p521-sha512", key: privateKey, created: CREATED },
  );

  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ecdsa-p521-sha512");
});

test("wrong P-521 key fails with SIGNATURE_MISMATCH", () => {
  const { signed } = signP521(BODY);
  const { publicKey: other } = generateP521KeyPair();

  const res = verifyRequest(signed, { key: other, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("tampered body fails with BODY_DIGEST_MISMATCH", () => {
  const { publicKey, signed } = signP521(BODY);
  const tampered = {
    ...signed,
    headers: { ...signed.headers },
    body: JSON.stringify({ amount: 999, currency: "USD" }),
  };

  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("a P-384 signature re-labelled as ecdsa-p521-sha512 fails with SIGNATURE_MISMATCH", () => {
  // The 96-octet P-384 width is pinned separately from the 132-octet
  // P-521 width: re-labelling cannot smuggle the narrower signature
  // past the P-521 length guard.
  const { privateKey: p384Priv } = generateP384KeyPair();
  const { publicKey: p521Pub } = generateP521KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    { keyId: "test-p384", alg: "ecdsa-p384-sha384", key: p384Priv, created: CREATED },
  );
  const relabelled: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        'alg="ecdsa-p384-sha384"',
        'alg="ecdsa-p521-sha512"',
      ),
    },
  };
  const res = verifyRequest(relabelled, { key: p521Pub, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("p521 signature checked against an ed25519 key is rejected, not confused", () => {
  const { signed } = signP521(BODY);
  const { publicKey: edKey } = generateEd25519KeyPair();

  const res = verifyRequest(signed, { key: edKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "VERIFICATION_ERROR");
});

test("p521 signature checked against a P-384 key never verifies", () => {
  const { signed } = signP521(BODY);
  const { publicKey: p384Pub } = generateP384KeyPair();

  const res = verifyRequest(signed, { key: p384Pub, now: CREATED + 60 });
  assert.equal(res.ok, false);
});

/**
 * Sign like a foreign signer that never emits the optional `alg`
 * parameter: build the signature base with params that carry no `alg`,
 * then sign with node:crypto directly (SHA-512, raw r||s per RFC 9421
 * §3.3.6).
 */
function signP521WithoutAlg(
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
  const params = { created: CREATED, keyid: "test-p521" }; // no alg, ever
  const base = buildSignatureBase(
    covered,
    { method: req.method, url: req.url, headers, body: req.body },
    params,
  );
  const sig = createSign("sha512")
    .update(base, "utf8")
    .sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
  headers["signature-input"] = signatureInputValue("sig1", covered, params);
  headers["signature"] = `sig1=:${sig.toString("base64")}:`;
  assert.ok(!headers["signature-input"].includes("alg="));
  return { method: req.method, url: req.url, headers, body: req.body };
}

test("algFallback \"infer\" maps a P-521 key to ecdsa-p521-sha512", () => {
  const { publicKey, privateKey } = generateP521KeyPair();
  const wire = signP521WithoutAlg(
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
  assert.equal(res.alg, "ecdsa-p521-sha512");
});

test("algFallback \"infer\" rejects a wire ecdsa-p521-sha512 alg paired with a P-384 key", () => {
  const { signed } = signP521(BODY);
  const { publicKey: p384Pub } = generateP384KeyPair();
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: p384Pub,
        now: CREATED + 60,
        algFallback: "infer",
      }),
    /incompatible with the configured key/,
  );
});

test("P-521 JWK round-trip: export, import, verify", () => {
  const { publicKey, signed } = signP521(BODY);
  const jwk = exportPublicKeyJwkP521(publicKey);
  assert.equal(jwk.kty, "EC");
  assert.equal(jwk.crv, "P-521");
  // P-521 coordinates are 66 bytes each.
  assert.equal(Buffer.from(jwk.x, "base64url").length, 66);
  assert.equal(Buffer.from(jwk.y, "base64url").length, 66);

  const wireKey = JSON.parse(JSON.stringify(jwk)) as unknown;
  const imported = importPublicKeyJwkP521(wireKey);
  const res = verifyRequest(signed, { key: imported, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ecdsa-p521-sha512");
});

test("P-521 JWK helpers refuse other curves and private material", () => {
  const { publicKey: p384Pub } = generateP384KeyPair();
  assert.throws(
    () => exportPublicKeyJwkP521(p384Pub),
    /expected a P-521 public KeyObject/,
  );
  const p384Jwk = exportPublicKeyJwkP384(p384Pub);
  assert.throws(
    () => importPublicKeyJwkP521(p384Jwk),
    /expected crv "P-521"/,
  );
  const { publicKey: p521Pub } = generateP521KeyPair();
  const withPrivate = { ...exportPublicKeyJwkP521(p521Pub), d: "AAAA" };
  assert.throws(
    () => importPublicKeyJwkP521(withPrivate),
    /private key material/,
  );
});

test("generateP521KeyPair produces a secp521r1 pair that survives PEM export/import", () => {
  const { publicKey, privateKey } = generateP521KeyPair();
  assert.equal(publicKey.asymmetricKeyType, "ec");
  assert.equal(publicKey.asymmetricKeyDetails?.namedCurve, "secp521r1");
  assert.equal(privateKey.asymmetricKeyDetails?.namedCurve, "secp521r1");

  const imported = importPublicKey(exportPublicKeyPem(publicKey));
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/status",
      headers: {},
    },
    { keyId: "pem-p521", alg: "ecdsa-p521-sha512", key: privateKey, created: CREATED },
  );
  const res = verifyRequest(signed, { key: imported, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("keyResolver composes with ecdsa-p521-sha512", () => {
  const { publicKey, signed } = signP521(BODY);

  const res = verifyRequest(signed, {
    keyResolver: (keyId) =>
      keyId === "test-p521" ? publicKey : undefined,
    now: CREATED + 60,
  });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ecdsa-p521-sha512");
  assert.equal(res.keyId, "test-p521");
});

test("verifyAllLabels verifies a mixed p521 + ed25519 request per label", () => {
  const { publicKey: p521Pub, privateKey: p521Priv } = generateP521KeyPair();
  const { publicKey: edPub, privateKey: edPriv } = generateEd25519KeyPair();
  const first = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    {
      keyId: "test-p521",
      alg: "ecdsa-p521-sha512",
      key: p521Priv,
      created: CREATED,
      label: "merchant",
    },
  );
  const dual = addSignature(first, {
    keyId: "test-ed",
    alg: "ed25519",
    key: edPriv,
    created: CREATED,
    label: "gateway",
  });
  const results = verifyAllLabels(dual, {
    keys: { merchant: p521Pub, gateway: edPub },
    now: CREATED + 60,
  });
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  assert.equal(results[0].ok, true);
  assert.equal(results[0].alg, "ecdsa-p521-sha512");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].alg, "ed25519");
});
