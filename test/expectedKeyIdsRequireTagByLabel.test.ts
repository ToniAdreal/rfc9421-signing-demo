import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #640: `expectedKeyIds` (per-label keyid pinning) and
// `requireTagByLabel` (per-label tag presence) have each been tested on
// their own, but never in combination. This file pins the orthogonal
// semantics for a dual-label gateway: both labels carry a pinned keyid,
// and only the merchant label is required to carry a `tag` — the
// gateway is a tag-less legacy signer whose verdict must stay
// independent of the merchant's tag rule, and whose own keyid pin must
// still hold.
//
// The fixture mirrors `test/keyidPinningPerLabel.test.ts` (there the
// tag dimension is absent): here the merchant is the tagged label and
// the gateway is the untagged one, so this file — not a copy of that
// file — is what proves a tag failure is reported as MISSING_TAG and
// never masked as, or mistaken for, a keyid failure.

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

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

function signMerchant(keyId: string, tag?: string) {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId,
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    coveredComponents: COVERED,
    ...(tag === undefined ? {} : { tag }),
  });
}

function signGateway(keyId: string) {
  // Tag-less legacy gateway shape: no tag, pinned keyid only.
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId,
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

// Both keyids pinned; the tag rule maps only the merchant. The gateway
// is unmapped, so it falls back to the global `requireTag` — unset
// here, i.e. no tag check for it.
const OPTS = {
  now: NOW,
  keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
  expectedKeyIds: { merchant: "merchant-key-1", gateway: "gateway-key-7" },
  requireTagByLabel: { merchant: true },
};

test("expectedKeyIds x requireTagByLabel: pinned dual with a tagged merchant and a tag-less gateway both pass, keyids echoed", () => {
  const dual = mergeSignatures(
    signMerchant("merchant-key-1", TAG),
    signGateway("gateway-key-7"),
  );
  const results = verifyAllLabels(dual, OPTS);
  assert.equal(results.length, 2);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].keyId, "merchant-key-1");
  assert.equal(by["merchant"].tag, TAG);
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].keyId, "gateway-key-7");
  assert.equal(by["gateway"].tag, undefined);
});

test("expectedKeyIds x requireTagByLabel: tag-less merchant with a correctly pinned keyid fails MISSING_TAG, not a keyid error", () => {
  // The merchant keyid matches its pin and the signature is valid, so
  // the only failing check is the tag presence check. A keyid problem
  // would surface as KEYID_MISMATCH instead.
  const dual = mergeSignatures(
    signMerchant("merchant-key-1"),
    signGateway("gateway-key-7"),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_TAG");
  assert.equal(by["gateway"].ok, true);
});

test("expectedKeyIds x requireTagByLabel: merchant keyid mismatch fails KEYID_MISMATCH, gateway unaffected", () => {
  const dual = mergeSignatures(
    signMerchant("merchant-key-OTHER", TAG),
    signGateway("gateway-key-7"),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "KEYID_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});

test("expectedKeyIds x requireTagByLabel: gateway keyid mismatch fails KEYID_MISMATCH, merchant unaffected", () => {
  // Mirror of the previous test: pinning is per label, so a gateway
  // keyid failure never drags the merchant verdict down with it.
  const dual = mergeSignatures(
    signMerchant("merchant-key-1", TAG),
    signGateway("gateway-key-OTHER"),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "KEYID_MISMATCH");
});

test("expectedKeyIds x requireTagByLabel: a label unmapped in the tag map falls back to the global (unset) tag rule", () => {
  // The map mentions only the merchant, and no global `requireTag`
  // is set, so a gateway-only wire with no tag must still verify —
  // the merchant-only map entry must not leak onto other labels.
  const solo = signGateway("gateway-key-7");
  const results = verifyAllLabels(solo, OPTS);
  assert.equal(results.length, 1);
  assert.equal(results[0].label, "gateway");
  assert.equal(results[0].ok, true);
  assert.equal(results[0].keyId, "gateway-key-7");
});
