import test from "node:test";
import assert from "node:assert/strict";
import {
  createHmac,
  randomBytes,
  sign as edSign,
  type KeyObject,
} from "node:crypto";
import {
  buildSignatureBase,
  contentDigest,
  generateEd25519KeyPair,
  secretKey,
  signatureInputValue,
  verifyResponse,
  type HttpResponseLike,
  type SignatureParams,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #905: `verifyResponse` inherits `VerifyOptions.algFallback`
// from `verifyRequest`, so a gateway callback verifier can accept a
// foreign response signature that omits the optional `alg` parameter
// (RFC 9421 §2.3 leaves `alg` optional; Appendix B.2.5's hmac-sha256
// vector omits it) — but no response-side test ever proved the
// fallback survives the response path. That matters because the
// response signature's `alg` (or its absence) comes from the
// response's own `signature-input` header, not from any request
// header: the request-side fallback tests (test/algFallback.test.ts)
// cannot prove the response forwarder reads the response's wire
// `alg`, passes the `algFallback` option through, or reports
// `VERIFICATION_ERROR` on the response shape. These tests pin the
// response side directly, mirroring the request-side semantics one
// for one: under `algFallback: "infer"` an ed25519 signature and an
// hmac-sha256 signature without `alg` each verify against a matching
// key; without the opt-in the same hmac wire fails with
// `VERIFICATION_ERROR` (the legacy default is ed25519, tried against
// a secret key); and a forgery is still reported as
// `SIGNATURE_MISMATCH`, never masked by the inference.

const CREATED = 1700000000;
const BODY = JSON.stringify({ settled: true, amount: 100 });

function response(overrides: Partial<HttpResponseLike> = {}): HttpResponseLike {
  return { status: 200, headers: {}, body: BODY, ...overrides };
}

/**
 * Sign like a foreign signer that never emits the optional `alg`
 * parameter: build the signature base with params that carry no `alg`,
 * then sign with node:crypto directly (mirroring src/sign.ts's crypto
 * choices: ed25519 raw, hmac-sha256). The base is built over the same
 * internal shape `verifyResponse` rebuilds (method "", url
 * "https://response.invalid/", the response's own status), covering
 * `@status` plus `content-digest` when the response has a body.
 */
function signResponseWithoutAlg(
  res: HttpResponseLike,
  key: KeyObject,
  keyId: string,
): SignedHttpResponse {
  const covered =
    res.body !== undefined ? ["@status", "content-digest"] : ["@status"];
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(res.headers)) {
    if (v === undefined) continue;
    headers[k] = Array.isArray(v) ? v.join(", ") : v;
  }
  if (covered.includes("content-digest")) {
    if (res.body === undefined)
      throw new Error("content-digest is covered but the response has no body");
    headers["content-digest"] = contentDigest(res.body);
  }
  const params: SignatureParams = { created: CREATED, keyid: keyId }; // no alg, ever
  const base = buildSignatureBase(
    covered,
    {
      method: "",
      url: "https://response.invalid/",
      headers,
      body: res.body,
      status: res.status,
    },
    params,
  );
  let sig: Buffer;
  if (key.type === "secret") {
    sig = createHmac("sha256", key).update(base, "utf8").digest();
  } else if (key.asymmetricKeyType === "ed25519") {
    sig = edSign(null, Buffer.from(base, "utf8"), key);
  } else {
    throw new Error("signResponseWithoutAlg: unsupported key shape for this helper");
  }
  headers["signature-input"] = signatureInputValue("sig1", covered, params);
  headers["signature"] = `sig1=:${sig.toString("base64")}:`;
  assert.ok(
    !headers["signature-input"].includes("alg="),
    "precondition: foreign wire must not carry alg",
  );
  return {
    status: res.status,
    headers,
    ...(res.body !== undefined ? { body: res.body } : {}),
  };
}

function ed25519Wire(overrides: Partial<HttpResponseLike> = {}): {
  signed: SignedHttpResponse;
  publicKey: KeyObject;
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponseWithoutAlg(response(overrides), privateKey, "gateway-key-1");
  return { signed, publicKey };
}

function hmacWire(overrides: Partial<HttpResponseLike> = {}): {
  signed: SignedHttpResponse;
  secret: KeyObject;
} {
  const secret = secretKey(randomBytes(32));
  const signed = signResponseWithoutAlg(response(overrides), secret, "gateway-secret-1");
  return { signed, secret };
}

test('response algFallback "infer": ed25519 signature without alg verifies', () => {
  const { signed, publicKey } = ed25519Wire();
  const result = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    algFallback: "infer",
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.alg, "ed25519");
  assert.equal(result.keyId, "gateway-key-1");
  assert.equal(result.created, CREATED);
  assert.deepEqual(result.coveredComponents, ["@status", "content-digest"]);
});

test('response algFallback "infer": hmac-sha256 signature without alg verifies', () => {
  const { signed, secret } = hmacWire();
  const result = verifyResponse(signed, {
    key: secret,
    now: CREATED + 60,
    algFallback: "infer",
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.alg, "hmac-sha256");
  assert.equal(result.keyId, "gateway-secret-1");
  assert.equal(result.created, CREATED);
  assert.deepEqual(result.coveredComponents, ["@status", "content-digest"]);
});

test("response algFallback unset: hmac signature without alg keeps the legacy ed25519 default", () => {
  const { signed, secret } = hmacWire();
  const result = verifyResponse(signed, { key: secret, now: CREATED + 60 });
  assert.equal(result.ok, false);
  // Unchanged legacy behavior: the ed25519 default is tried against a
  // secret key and the crypto layer rejects the shape.
  assert.equal(result.code, "VERIFICATION_ERROR");
});

test("response algFallback: false keeps the legacy behavior", () => {
  const { signed, secret } = hmacWire();
  const result = verifyResponse(signed, {
    key: secret,
    now: CREATED + 60,
    algFallback: false,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "VERIFICATION_ERROR");
});

test("response algFallback unset: ed25519 signature without alg still verifies (the default IS ed25519)", () => {
  const { signed, publicKey } = ed25519Wire();
  const result = verifyResponse(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.alg, "ed25519");
});

test('response algFallback "infer": wrong ed25519 key still reports SIGNATURE_MISMATCH', () => {
  const { signed } = ed25519Wire();
  const { publicKey: otherPublic } = generateEd25519KeyPair();
  const result = verifyResponse(signed, {
    key: otherPublic,
    now: CREATED + 60,
    algFallback: "infer",
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test('response algFallback "infer": wrong hmac secret still reports SIGNATURE_MISMATCH', () => {
  const { signed } = hmacWire();
  const result = verifyResponse(signed, {
    key: secretKey(randomBytes(32)),
    now: CREATED + 60,
    algFallback: "infer",
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test('response algFallback "infer": body-less (@status-only) ed25519 response verifies', () => {
  const { signed, publicKey } = ed25519Wire({ body: undefined });
  const result = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    algFallback: "infer",
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.alg, "ed25519");
  assert.deepEqual(result.coveredComponents, ["@status"]);
});

test('response algFallback "infer": body-less (@status-only) hmac response verifies', () => {
  const { signed, secret } = hmacWire({ body: undefined });
  const result = verifyResponse(signed, {
    key: secret,
    now: CREATED + 60,
    algFallback: "infer",
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.alg, "hmac-sha256");
  assert.deepEqual(result.coveredComponents, ["@status"]);
});

test('response algFallback unset: body-less (@status-only) hmac response fails with VERIFICATION_ERROR', () => {
  const { signed, secret } = hmacWire({ body: undefined });
  const result = verifyResponse(signed, { key: secret, now: CREATED + 60 });
  assert.equal(result.ok, false);
  assert.equal(result.code, "VERIFICATION_ERROR");
});
