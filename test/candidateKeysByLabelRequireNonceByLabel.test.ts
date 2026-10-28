import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #689: `candidateKeysByLabel` (per-label key rotation) and
// `requireNonceByLabel` (per-label nonce presence) have each been tested
// on their own, but never in combination. This file pins the orthogonal
// semantics for a dual-label gateway: the merchant label rotates
// ed25519 keys and must carry a nonce, the gateway label uses one
// static key and must carry no nonce requirement at all. The open
// questions are which dimension refuses first when both fail, and
// whether one dimension can mask the other — answered here by
// measurement, not by assumption (see the forged no-nonce test).

const CREATED = 1700000000;
const NOW = CREATED + 60;
const COVERED = ["@method", "@authority", "@path", "content-digest"];
const NONCE = "merchant-nonce-1";

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
  };
}

function mergeSignatures(
  a: SignedHttpRequest,
  b: SignedHttpRequest,
): SignedHttpRequest {
  return {
    ...a,
    headers: {
      ...a.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  };
}

type KeyPair = ReturnType<typeof generateEd25519KeyPair>;

const merchantOld = generateEd25519KeyPair();
const merchantNew = generateEd25519KeyPair();
const merchantRetired = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

function signMerchant(pair: KeyPair, keyId: string, nonce?: string) {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId,
    alg: "ed25519",
    key: pair.privateKey,
    created: CREATED,
    coveredComponents: COVERED,
    ...(nonce === undefined ? {} : { nonce }),
  });
}

function signGateway() {
  // Static key, no nonce: the legacy gateway shape, and the gateway
  // label is mapped to neither requirement in OPTS below.
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-1",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

// Merchant: rotating candidate keys + nonce required. Gateway: static
// key, no per-label nonce entry (and no global flag), so it passes
// with or without a nonce.
const OPTS = {
  now: NOW,
  candidateKeysByLabel: {
    merchant: [merchantOld.publicKey, merchantNew.publicKey],
  },
  keys: { gateway: gateway.publicKey },
  requireNonceByLabel: { merchant: true },
};

test("candidateKeysByLabel x requireNonceByLabel: rotated merchant key with a nonce verifies, nonce-less static gateway still passes", () => {
  const dual = mergeSignatures(
    signMerchant(merchantNew, "merchant-key-new", NONCE),
    signGateway(),
  );
  const results = verifyAllLabels(dual, OPTS);
  assert.equal(results.length, 2);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].nonce, NONCE);
  assert.equal(by["merchant"].keyId, "merchant-key-new");
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].nonce, undefined);
});

test("candidateKeysByLabel x requireNonceByLabel: nonce-less merchant with a valid rotated key fails MISSING_NONCE, not a key error", () => {
  // The merchant key here is valid and in the rotation list, so the
  // crypto walk succeeds; the only failing check is the nonce
  // presence check. A key problem would surface as
  // SIGNATURE_MISMATCH instead.
  const dual = mergeSignatures(
    signMerchant(merchantNew, "merchant-key-new"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_NONCE");
  assert.equal(by["gateway"].ok, true);
});

test("candidateKeysByLabel x requireNonceByLabel: merchant old key with a nonce still verifies inside the rotation window", () => {
  const dual = mergeSignatures(
    signMerchant(merchantOld, "merchant-key-old", NONCE),
    signGateway(),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].keyId, "merchant-key-old");
  assert.equal(by["merchant"].nonce, NONCE);
  assert.equal(by["gateway"].ok, true);
});

test("candidateKeysByLabel x requireNonceByLabel: a key removed from the rotation list reports SIGNATURE_MISMATCH even with a nonce present", () => {
  // Retirement means removal from the list: the retired key is not in
  // the narrowed list, so the walk exhausts it and reports a key
  // failure — even though the nonce requirement is satisfied. The
  // nonce dimension therefore cannot mask a key failure.
  const dual = mergeSignatures(
    signMerchant(merchantRetired, "merchant-key-retired", NONCE),
    signGateway(),
  );
  const results = verifyAllLabels(dual, {
    ...OPTS,
    candidateKeysByLabel: { merchant: [merchantNew.publicKey] },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});

test("candidateKeysByLabel x requireNonceByLabel: a forged nonce-less merchant signature reports SIGNATURE_MISMATCH, not MISSING_NONCE", () => {
  // Check order: the nonce presence check runs only after the crypto
  // walk passes. A signature from a key outside the rotation list
  // must therefore report the key failure even though it also
  // carries no nonce — the two dimensions do not mask each other in
  // either direction.
  const dual = mergeSignatures(
    signMerchant(merchantRetired, "merchant-key-retired"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});

test("candidateKeysByLabel x requireNonceByLabel: global true plus a mapped-false gateway leaves only the merchant checked", () => {
  // This test exists so the gateway pass above cannot be misread as
  // "the nonce map ignores the gateway": turn the global flag on and
  // the same nonce-less gateway still passes only because of its
  // explicit `gateway: false` override, while the nonce-less merchant
  // keeps failing.
  const dual = mergeSignatures(
    signMerchant(merchantNew, "merchant-key-new"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    candidateKeysByLabel: {
      merchant: [merchantOld.publicKey, merchantNew.publicKey],
    },
    keys: { gateway: gateway.publicKey },
    requireNonce: true,
    requireNonceByLabel: { merchant: true, gateway: false },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_NONCE");
  assert.equal(by["gateway"].ok, true);
});
