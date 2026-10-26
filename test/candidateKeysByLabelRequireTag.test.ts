import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #618: `candidateKeysByLabel` (per-label key rotation) and the
// global `requireTag` presence check have each been tested on their own,
// but never in combination. This file pins the orthogonal semantics for
// a dual-label gateway: the merchant label rotates ed25519 keys, the
// gateway label uses one static key, and the tag requirement is global
// with an explicit per-label opt-out for the gateway (a tag-less legacy
// gateway that must keep verifying).
//
// The fixture is deliberately the mirror image of
// `test/candidateKeysByLabel.test.ts` (there the merchant is static and
// the gateway rotates): here the merchant is the rotating label, so
// this file — not a copy of that file — is what proves the rotation
// list, not the label name, drives key selection.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const COVERED = ["@method", "@authority", "@path", "content-digest"];
const TAG = "merchant-webhook-v1";

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

function signMerchant(pair: KeyPair, keyId: string, tag?: string) {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId,
    alg: "ed25519",
    key: pair.privateKey,
    created: CREATED,
    coveredComponents: COVERED,
    ...(tag === undefined ? {} : { tag }),
  });
}

function signGateway() {
  // Static key, no tag: the legacy gateway shape.
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

// Global tag requirement on, gateway explicitly opted out via the
// per-label map (the `requireTagByLabel: { gateway: false }` override
// is what lets the tag-less gateway through — see the last test, which
// proves the global flag alone would reject it).
const OPTS = {
  now: NOW,
  candidateKeysByLabel: {
    merchant: [merchantOld.publicKey, merchantNew.publicKey],
  },
  keys: { gateway: gateway.publicKey },
  requireTag: true,
  requireTagByLabel: { gateway: false },
};

test("candidateKeysByLabel x requireTag: rotated merchant key with a tag verifies, static tag-less gateway still passes", () => {
  const dual = mergeSignatures(
    signMerchant(merchantNew, "merchant-key-new", TAG),
    signGateway(),
  );
  const results = verifyAllLabels(dual, OPTS);
  assert.equal(results.length, 2);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].tag, TAG);
  assert.equal(by["merchant"].keyId, "merchant-key-new");
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].tag, undefined);
});

test("candidateKeysByLabel x requireTag: tag-less merchant with a valid rotated key fails MISSING_TAG, not a key error", () => {
  // The merchant key here is valid and in the rotation list, so the
  // crypto walk succeeds; the only failing check is the tag presence
  // check. A key problem would surface as SIGNATURE_MISMATCH instead.
  const dual = mergeSignatures(
    signMerchant(merchantNew, "merchant-key-new"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_TAG");
  assert.equal(by["gateway"].ok, true);
});

test("candidateKeysByLabel x requireTag: merchant old key still verifies inside the rotation window", () => {
  const dual = mergeSignatures(
    signMerchant(merchantOld, "merchant-key-old", TAG),
    signGateway(),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].keyId, "merchant-key-old");
  assert.equal(by["gateway"].ok, true);
});

test("candidateKeysByLabel x requireTag: a key removed from the rotation list no longer verifies", () => {
  // Retirement means removal from the list: the retired key is not in
  // the narrowed list, so the walk exhausts it and reports a key
  // failure — while the static gateway label still verifies. This is
  // the counterpart of the previous test: list membership, not key
  // age, decides whether a signature verifies.
  const dual = mergeSignatures(
    signMerchant(merchantRetired, "merchant-key-retired", TAG),
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

test("candidateKeysByLabel x requireTag: a forged tag-less merchant signature reports SIGNATURE_MISMATCH, not MISSING_TAG", () => {
  // Check order: the tag check runs only after the crypto walk passes.
  // A signature from a key outside the rotation list must therefore
  // report the key failure even though it also carries no tag.
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

test("candidateKeysByLabel x requireTag: without the gateway opt-out, the global flag rejects the tag-less gateway too", () => {
  // This test exists so the gateway pass in the tests above cannot be
  // misread as "the global flag ignores the gateway": drop the
  // per-label `gateway: false` override and the same dual fails on
  // both labels with MISSING_TAG (the merchant is tagged here, so its
  // failure is the gateway's — asserted separately below).
  const dual = mergeSignatures(
    signMerchant(merchantNew, "merchant-key-new", TAG),
    signGateway(),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    candidateKeysByLabel: {
      merchant: [merchantOld.publicKey, merchantNew.publicKey],
    },
    keys: { gateway: gateway.publicKey },
    requireTag: true,
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "MISSING_TAG");
});
