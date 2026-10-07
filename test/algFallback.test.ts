import test from "node:test";
import assert from "node:assert/strict";
import {
  constants,
  createHmac,
  createSign,
  generateKeyPairSync,
  randomBytes,
  sign as edSign,
  type KeyObject,
} from "node:crypto";
import {
  buildSignatureBase,
  contentDigest,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateRsaPssKeyPair,
  secretKey,
  signatureInputValue,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

// RFC 9421, Appendix B.2.5 ("Signing a Request Using hmac-sha256") — the
// same verbatim vectors as test/rfc9421AppendixB.test.ts (fetched from
// https://www.rfc-editor.org/rfc/rfc9421.txt). The vector deliberately
// omits the `alg` parameter: `alg` is optional per RFC 9421 §2.3.

/** RFC 9421 §B.1.5 test-shared-secret: 64 random bytes, Base64. */
const B25_KEY_B64 =
  "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBt" +
  "bmHhIDi6pcl8jsasjlTMtDQ==";

/** RFC 9421 §B.2.5 Signature-Input value under label sig-b25 (no `alg`). */
const B25_SIGNATURE_INPUT = `sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`;

/** RFC 9421 §B.2.5 expected MAC value. */
const B25_SIGNATURE_B64 = "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=";

/** The §B.2 test-request message, as this library sees it. */
function b25Wire(): RequestLike {
  return {
    method: "POST",
    url: "http://example.com/foo?param=Value&Pet=dog",
    headers: {
      date: "Tue, 20 Apr 2021 02:07:55 GMT",
      "content-type": "application/json",
      "signature-input": B25_SIGNATURE_INPUT,
      signature: `sig-b25=:${B25_SIGNATURE_B64}:`,
    },
  };
}

function demoRequest(body?: string): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body,
  };
}

/**
 * Sign like a foreign signer that never emits the optional `alg`
 * parameter: build the signature base with params that carry no `alg`,
 * then sign with node:crypto directly (mirroring src/sign.ts's crypto
 * choices: ed25519 raw, P-256 DER, RSA-PSS with saltLength 64 per
 * RFC 9421 §3.3.1, hmac-sha256).
 */
function signWithoutAlg(
  req: RequestLike,
  opts: { keyId: string; key: KeyObject; created?: number; label?: string },
): SignedHttpRequest {
  const label = opts.label ?? "sig1";
  const created = opts.created ?? Math.floor(Date.now() / 1000);
  const covered =
    req.body !== undefined
      ? ["@method", "@authority", "@path", "content-digest"]
      : ["@method", "@authority", "@path"];
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    headers[k] = Array.isArray(v) ? v.join(", ") : v;
  }
  if (covered.includes("content-digest")) {
    if (req.body === undefined)
      throw new Error("content-digest is covered but the request has no body");
    headers["content-digest"] = contentDigest(req.body);
  }
  const params = { created, keyid: opts.keyId }; // no alg, ever
  const signingInput: RequestLike = {
    method: req.method,
    url: req.url,
    headers,
    body: req.body,
  };
  const base = buildSignatureBase(covered, signingInput, params);
  const key = opts.key;
  let sig: Buffer;
  if (key.type === "secret") {
    sig = createHmac("sha256", key).update(base, "utf8").digest();
  } else if (key.asymmetricKeyType === "ed25519") {
    sig = edSign(null, Buffer.from(base, "utf8"), key);
  } else if (key.asymmetricKeyType === "rsa") {
    // RSA-PSS with SHA-512, MGF1 with SHA-512, and a 64-byte salt — the
    // RFC 9421 §3.3.1 wire shape this library pins on its rsa-pss-sha512
    // verify branch.
    sig = createSign("sha512")
      .update(base, "utf8")
      .sign({
        key,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 64,
      });
  } else {
    sig = createSign("sha256").update(base, "utf8").sign(key);
  }
  headers["signature-input"] = signatureInputValue(label, covered, params);
  headers["signature"] = `${label}=:${sig.toString("base64")}:`;
  assert.ok(
    !headers["signature-input"].includes("alg="),
    "precondition: foreign wire must not carry alg",
  );
  return { method: req.method, url: req.url, headers, body: req.body };
}

test("RFC 9421 B.2.5 wire value verifies end-to-end with algFallback \"infer\"", () => {
  const res = verifyRequest(b25Wire(), {
    key: secretKey(Buffer.from(B25_KEY_B64, "base64")),
    label: "sig-b25",
    algFallback: "infer",
  });
  assert.equal(res.ok, true, `expected ok, got ${JSON.stringify(res)}`);
  assert.equal(res.alg, "hmac-sha256");
  assert.equal(res.keyId, "test-shared-secret");
  assert.equal(res.label, "sig-b25");
});

test("without the opt-in, a missing alg keeps the legacy ed25519 default", () => {
  const key = secretKey(Buffer.from(B25_KEY_B64, "base64"));
  const res = verifyRequest(b25Wire(), { key, label: "sig-b25" });
  assert.equal(res.ok, false);
  // Unchanged legacy behavior: the ed25519 default is tried against a
  // secret key and the crypto layer rejects the shape.
  assert.equal(res.code, "VERIFICATION_ERROR");
});

test("explicit algFallback: false keeps the legacy behavior", () => {
  const key = secretKey(Buffer.from(B25_KEY_B64, "base64"));
  const res = verifyRequest(b25Wire(), {
    key,
    label: "sig-b25",
    algFallback: false,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "VERIFICATION_ERROR");
});

test("infer: ed25519 signature without alg verifies against an ed25519 key", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const wire = signWithoutAlg(demoRequest(JSON.stringify({ amount: 100 })), {
    keyId: "merchant-key",
    key: privateKey,
  });
  const res = verifyRequest(wire, { key: publicKey, algFallback: "infer" });
  assert.equal(res.ok, true, `expected ok, got ${JSON.stringify(res)}`);
  assert.equal(res.alg, "ed25519");
});

test("infer: P-256 signature without alg verifies against a P-256 key", () => {
  const { publicKey, privateKey } = generateP256KeyPair();
  const wire = signWithoutAlg(demoRequest(JSON.stringify({ amount: 100 })), {
    keyId: "p256-key",
    key: privateKey,
  });
  const res = verifyRequest(wire, { key: publicKey, algFallback: "infer" });
  assert.equal(res.ok, true, `expected ok, got ${JSON.stringify(res)}`);
  assert.equal(res.alg, "ecdsa-p256-sha256");
});

test("infer: wire alg=\"ed25519\" with a secret key throws a configuration error", () => {
  const { privateKey } = generateEd25519KeyPair();
  const signed = signRequest(demoRequest(JSON.stringify({ amount: 1 })), {
    keyId: "merchant-key",
    alg: "ed25519",
    key: privateKey,
  });
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: secretKey(randomBytes(32)),
        algFallback: "infer",
      }),
    /incompatible with the configured key/,
    "ed25519/secret shape conflict must be a clear config error, not VERIFICATION_ERROR",
  );
});

test("infer: wire alg=\"hmac-sha256\" with an ed25519 key throws a configuration error", () => {
  const { publicKey } = generateEd25519KeyPair();
  const signed = signRequest(demoRequest(JSON.stringify({ amount: 1 })), {
    keyId: "shared-secret",
    alg: "hmac-sha256",
    key: secretKey(randomBytes(32)),
  });
  assert.throws(
    () => verifyRequest(signed, { key: publicKey, algFallback: "infer" }),
    /incompatible with the configured key/,
    "hmac/ed25519 shape conflict must be a clear config error",
  );
});

test("infer: RSA-PSS signature without alg verifies against an RSA key", () => {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const wire = signWithoutAlg(demoRequest(JSON.stringify({ amount: 100 })), {
    keyId: "rsa-merchant",
    key: privateKey,
  });
  const res = verifyRequest(wire, { key: publicKey, algFallback: "infer" });
  assert.equal(res.ok, true, `expected ok, got ${JSON.stringify(res)}`);
  assert.equal(res.alg, "rsa-pss-sha512");
});

test("infer: wire alg=\"rsa-pss-sha512\" with an RSA key does not throw", () => {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const signed = signRequest(demoRequest(JSON.stringify({ amount: 1 })), {
    keyId: "rsa-merchant",
    alg: "rsa-pss-sha512",
    key: privateKey,
  });
  const res = verifyRequest(signed, { key: publicKey, algFallback: "infer" });
  assert.equal(res.ok, true, `expected ok, got ${JSON.stringify(res)}`);
  assert.equal(res.alg, "rsa-pss-sha512");
});

test("infer: wire alg=\"ed25519\" with an RSA key throws a configuration error", () => {
  const { publicKey: rsaPublic } = generateRsaPssKeyPair();
  const { privateKey: edPriv } = generateEd25519KeyPair();
  const signed = signRequest(demoRequest(JSON.stringify({ amount: 1 })), {
    keyId: "merchant-key",
    alg: "ed25519",
    key: edPriv,
  });
  assert.throws(
    () => verifyRequest(signed, { key: rsaPublic, algFallback: "infer" }),
    /incompatible with the configured key/,
    "ed25519/RSA shape conflict must be a clear config error",
  );
});

test("infer: an unmappable key shape (non-P-256 EC) throws a configuration error", () => {
  const { publicKey: p384Public } = generateKeyPairSync("ec", {
    namedCurve: "secp384r1",
  });
  const { privateKey } = generateEd25519KeyPair();
  const wire = signWithoutAlg(demoRequest(JSON.stringify({ amount: 1 })), {
    keyId: "merchant-key",
    key: privateKey,
  });
  assert.throws(
    () => verifyRequest(wire, { key: p384Public, algFallback: "infer" }),
    /cannot infer an algorithm/,
    "secp384r1 key has no supported mapping under infer",
  );
});

test("infer composes with verifyAllLabels: per-label inference in a multi-party request", () => {
  const { publicKey: edPub, privateKey: edPriv } = generateEd25519KeyPair();
  const secret = secretKey(randomBytes(32));
  const body = JSON.stringify({ amount: 100 });
  const a = signRequest(demoRequest(body), {
    keyId: "merchant-key",
    alg: "ed25519",
    key: edPriv,
    label: "sig-a",
  });
  // Gateway is a foreign signer that omits the optional `alg` parameter.
  const b = signWithoutAlg(demoRequest(body), {
    keyId: "gateway-secret",
    key: secret,
    label: "sig-b",
  });
  const wire: RequestLike = {
    ...a,
    headers: {
      ...a.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  };
  const results = verifyAllLabels(wire, {
    keys: { "sig-a": edPub, "sig-b": secret },
    algFallback: "infer",
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "sig-a");
  assert.equal(
    results[0].ok,
    true,
    `sig-a failed: ${JSON.stringify(results[0])}`,
  );
  assert.equal(results[0].alg, "ed25519");
  assert.equal(results[1].label, "sig-b");
  assert.equal(
    results[1].ok,
    true,
    `sig-b failed: ${JSON.stringify(results[1])}`,
  );
  assert.equal(results[1].alg, "hmac-sha256");
});
