import test from "node:test";
import assert from "node:assert/strict";
import { createSign, type KeyObject } from "node:crypto";
import {
  addSignature,
  buildSignatureBase,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  isVerifyError,
  secretKey,
  signatureInputValue,
  signRequest,
  signResponse,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  verifyResponse,
  type RequestLike,
  type SignatureParams,
  type SignedHttpRequest,
} from "../src/index.js";

// Backlog #1410: the sign side has always refused an `alg` that does
// not match the key's shape (`signRequest` throws before any crypto
// runs), but the verify side only enforced the pairing under the
// `algFallback: "infer"` opt-in. On the default path a foreign ECDSA
// signature whose declared curve did not match the configured key
// (e.g. `ecdsa-p256-sha256` verified against a P-384 key) reached the
// crypto dispatch, which only separates the curves by signature
// length. `verifyWithKey` now rejects every wire-carried `alg` that
// contradicts the resolved key's shape before any crypto work.
//
// Decision (execution round, documented): the default-path rejection
// is an `ALG_NOT_ALLOWED` verdict, not the `assertAlgMatchesKeyShape`
// throw — the backlog sketch says "always call assert" for the
// single-key path but recommends a verdict for the `candidateKeys`
// walk, and one mechanism must serve both. A verdict keeps
// `verifyAllLabels` per-label isolation (one label's mismatched key
// fails only that label, pinned below) and keeps a foreign signer
// from forcing an exception by declaring a mismatched `alg`, which
// matches how the two most recent verify-side hardenings
// (`NONCE_TOO_LONG` #1399, `EMPTY_COVERED_COMPONENTS` #1409) report
// wire-driven rejections. The `infer` opt-in still throws exactly as
// before (pinned by `test/algFallback.test.ts`), and `hmac-*` /
// `rsa-v1_5-sha256` keep their dedicated pre-crypto configuration
// throws (secret-length / modulus checks), so only the five
// algorithms without a dedicated check take the verdict path.

const CREATED = 1700000000;
const NOW = CREATED + 60;

function req(): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
  };
}

const ed = generateEd25519KeyPair();
const p256 = generateP256KeyPair();
const p384 = generateP384KeyPair();
const p521 = generateP521KeyPair();
const hmac32 = secretKey("a".repeat(32));

function sign(
  alg: "ecdsa-p256-sha256" | "ecdsa-p384-sha384" | "ecdsa-p521-sha512" | "ed25519" | "hmac-sha256",
  key: KeyObject,
): SignedHttpRequest {
  return signRequest(req(), { alg, key, created: CREATED });
}

/** Hand-mint a P-256 signature whose `signature-input` carries no `alg`. */
function signAlgLessP256(): SignedHttpRequest {
  const baseReq = req();
  const params: SignatureParams = { created: CREATED, keyid: "p256" };
  const base = buildSignatureBase(["@method", "@authority"], baseReq, params);
  const sig = createSign("sha256")
    .update(base, "utf8")
    .sign({ key: p256.privateKey, dsaEncoding: "ieee-p1363" });
  return {
    method: baseReq.method,
    url: baseReq.url,
    headers: {
      ...baseReq.headers,
      "signature-input": signatureInputValue("sig1", ["@method", "@authority"], params),
      signature: `sig1=:${sig.toString("base64")}:`,
    },
  };
}

function assertShapeVerdict(
  result: ReturnType<typeof verifyRequest>,
  alg: string,
  keyDescription: string,
): void {
  assert.equal(result.ok, false);
  assert.equal(result.code, "ALG_NOT_ALLOWED");
  assert.equal(
    result.reason,
    `wire alg "${alg}" is incompatible with the configured key (${keyDescription}) — pass a key of the matching type for the algorithm`,
  );
  assert.equal(result.alg, alg);
}

test("P-384 key + ecdsa-p256-sha256 wire alg is rejected with ALG_NOT_ALLOWED", () => {
  const signed = sign("ecdsa-p256-sha256", p256.privateKey);
  const result = verifyRequest(signed, { key: p384.publicKey, now: NOW });
  assertShapeVerdict(result, "ecdsa-p256-sha256", "an asymmetric ec key (secp384r1)");
});

test("P-256 key + ecdsa-p384-sha384 wire alg is rejected with ALG_NOT_ALLOWED", () => {
  const signed = sign("ecdsa-p384-sha384", p384.privateKey);
  const result = verifyRequest(signed, { key: p256.publicKey, now: NOW });
  assertShapeVerdict(result, "ecdsa-p384-sha384", "an asymmetric ec key (prime256v1)");
});

test("P-521 key + ecdsa-p256-sha256 wire alg is rejected with ALG_NOT_ALLOWED", () => {
  const signed = sign("ecdsa-p256-sha256", p256.privateKey);
  const result = verifyRequest(signed, { key: p521.publicKey, now: NOW });
  assertShapeVerdict(result, "ecdsa-p256-sha256", "an asymmetric ec key (secp521r1)");
});

test("the three correct ECDSA pairings still verify", () => {
  const pairings = [
    { alg: "ecdsa-p256-sha256", pair: p256 },
    { alg: "ecdsa-p384-sha384", pair: p384 },
    { alg: "ecdsa-p521-sha512", pair: p521 },
  ] as const;
  for (const { alg, pair } of pairings) {
    const signed = sign(alg, pair.privateKey);
    const result = verifyRequest(signed, { key: pair.publicKey, now: NOW });
    assert.equal(result.ok, true, `${alg} should verify with its matching key`);
  }
});

test("ed25519 wire alg + HMAC secret key is rejected with ALG_NOT_ALLOWED on the default path", () => {
  const signed = sign("ed25519", ed.privateKey);
  const result = verifyRequest(signed, { key: hmac32, now: NOW });
  assertShapeVerdict(result, "ed25519", "a secret (symmetric) key");
});

test("hmac-sha256 wire alg + ed25519 key keeps its dedicated secret-length throw", () => {
  // `hmac-*` has its own pre-crypto check (`assertHmacSecretLength`),
  // which already fails fast with a more specific configuration error
  // — the generic shape verdict does not replace it.
  const signed = sign("hmac-sha256", hmac32);
  assert.throws(
    () => verifyRequest(signed, { key: ed.publicKey, now: NOW }),
    /assertHmacSecretLength: expected a symmetric secret KeyObject/,
  );
});

test("an unknown wire alg still reports UNSUPPORTED_ALG, never the shape verdict", () => {
  const signed = sign("ed25519", ed.privateKey);
  const input = signed.headers["signature-input"] as string;
  assert.match(input, /;alg="ed25519"/);
  const tampered: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": input.replace(';alg="ed25519"', ';alg="rsa-pss-sha256"'),
    },
  };
  const result = verifyRequest(tampered, { key: ed.publicKey, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "UNSUPPORTED_ALG");
});

test("alg-less signature + infer still verifies (behavior unchanged)", () => {
  const signed = signAlgLessP256();
  const result = verifyRequest(signed, {
    key: p256.publicKey,
    algFallback: "infer",
    now: NOW,
  });
  assert.equal(result.ok, true);
});

test("alg-less signature without infer does not get a shape verdict: legacy ed25519 default", () => {
  const signed = signAlgLessP256();
  const result = verifyRequest(signed, { key: p256.publicKey, now: NOW });
  assert.equal(result.ok, false);
  assert.notEqual(result.code, "ALG_NOT_ALLOWED");
});

test("candidateKeys: a shape-mismatched candidate returns ALG_NOT_ALLOWED at once, never rotated past", () => {
  const signed = sign("ecdsa-p256-sha256", p256.privateKey);
  // The matching P-256 key sits second: if the walk advanced past the
  // mismatched P-384 candidate, this would verify. Returning the
  // verdict at once proves a configuration error never masquerades
  // as a rotation.
  const result = verifyRequest(signed, {
    candidateKeys: [p384.publicKey, p256.publicKey],
    now: NOW,
  });
  assertShapeVerdict(result, "ecdsa-p256-sha256", "an asymmetric ec key (secp384r1)");
});

test("candidateKeys: rotation across same-shape candidates still works", () => {
  const other256 = generateP256KeyPair();
  const signed = sign("ecdsa-p256-sha256", p256.privateKey);
  const result = verifyRequest(signed, {
    candidateKeys: [other256.publicKey, p256.publicKey],
    now: NOW,
  });
  assert.equal(result.ok, true);
});

test("verifyResponse inherits the verdict: cross-curve response key is ALG_NOT_ALLOWED", () => {
  const signed = signResponse(
    { status: 200, headers: {} },
    { alg: "ecdsa-p256-sha256", key: p256.privateKey, created: CREATED },
  );
  const result = verifyResponse(signed, { key: p384.publicKey, now: NOW });
  assertShapeVerdict(result, "ecdsa-p256-sha256", "an asymmetric ec key (secp384r1)");
});

test("verifyAllLabels inherits the verdict per label and keeps the other label verifying", () => {
  // Merchant ed25519 (sig1) + gateway hmac-sha256 (sig2) on one
  // request; only the merchant label is given a mismatched key.
  const merchantSigned = signRequest(req(), {
    label: "sig1",
    keyId: "merchant-key",
    alg: "ed25519",
    key: ed.privateKey,
    created: CREATED,
  });
  const dual = addSignature(merchantSigned, {
    label: "sig2",
    keyId: "gateway-key",
    alg: "hmac-sha256",
    key: hmac32,
    created: CREATED,
  });
  const results = verifyAllLabels(dual, {
    keys: { sig1: p384.publicKey, sig2: hmac32 },
    now: NOW,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "sig1");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "ALG_NOT_ALLOWED");
  assert.equal(results[1].label, "sig2");
  assert.equal(results[1].ok, true);
});

test("verifyRequestOrThrow throws a VerifyError carrying ALG_NOT_ALLOWED", () => {
  const signed = sign("ecdsa-p256-sha256", p256.privateKey);
  assert.throws(
    () => verifyRequestOrThrow(signed, { key: p384.publicKey, now: NOW }),
    (e: unknown) =>
      isVerifyError(e) &&
      e.code === "ALG_NOT_ALLOWED" &&
      /incompatible with the configured key/.test(e.message),
  );
});

test("a disallowed wire alg still reports ALG_NOT_ALLOWED from the whitelist, not the shape check", () => {
  // Precedence pin: with `allowedAlgs: ["ed25519"]` a P-384-keyed
  // ecdsa-p256-sha256 signature reports the whitelist reason, because
  // the shape verdict runs after the whitelist gate.
  const signed = sign("ecdsa-p256-sha256", p256.privateKey);
  const result = verifyRequest(signed, {
    key: p384.publicKey,
    allowedAlgs: ["ed25519"],
    now: NOW,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "ALG_NOT_ALLOWED");
  assert.match(result.reason ?? "", /is not in the allowedAlgs whitelist/);
});
