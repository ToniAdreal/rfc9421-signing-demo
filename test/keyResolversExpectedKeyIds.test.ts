import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #641: `keyResolvers` (per-label keyid→key resolution) and
// `expectedKeyIds` (per-label keyid pinning) have each been tested on
// their own (`test/keyResolversPerLabel.test.ts`,
// `test/keyidPinningPerLabel.test.ts`), but never in combination.
// The combination has a real ambiguity: when the resolver returns a
// key, is the pin checked against the signature's keyid, against the
// resolved key, or not at all? This file pins the actual order in
// `src/verify.ts`: resolution runs first (unknown keyid ->
// KEY_RESOLUTION_FAILED), crypto runs second (a resolved key that
// does not match the signature -> SIGNATURE_MISMATCH), and the pin
// check runs only after crypto passes (a resolved, authenticated
// keyid that is not the pinned one -> KEYID_MISMATCH). So a pin
// rejection is never a substitute for a crypto failure, and a
// successful resolution is never a substitute for the pin.
//
// That order clarifies the backlog wording "resolver returns a wrong
// key -> KEYID_MISMATCH takes precedence": the KEYID_MISMATCH case is
// the resolver returning the *correct* key for an *unpinned* keyid
// (rotation the pin has not followed yet) — crypto passes, then the
// pin fires. A resolver returning the wrong public key for the
// pinned keyid is a different case and is pinned below as
// SIGNATURE_MISMATCH, because the pin check is never reached.

const CREATED = 1700000000;
const NOW = CREATED + 60;

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
const merchantRotated = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

function signMerchant(keyId: string, pair: KeyPair = merchant) {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId,
    alg: "ed25519",
    key: pair.privateKey,
    created: CREATED,
  });
}

function signGateway(keyId: string) {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId,
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
  });
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

function store(pairs: [string, KeyObject][]) {
  const map = new Map(pairs);
  return (id: string) => map.get(id);
}

const PINS = {
  merchant: "merchant-key-1",
  gateway: "gateway-key-7",
};

test("keyResolvers x expectedKeyIds: consistent per-label resolver + pin both pass, keyids echoed", () => {
  const dual = mergeSignatures(
    signMerchant("merchant-key-1"),
    signGateway("gateway-key-7"),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    keyResolvers: {
      merchant: store([["merchant-key-1", merchant.publicKey]]),
      gateway: store([["gateway-key-7", gateway.publicKey]]),
    },
    expectedKeyIds: PINS,
  });
  assert.equal(results.length, 2);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].keyId, "merchant-key-1");
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].keyId, "gateway-key-7");
});

test("keyResolvers x expectedKeyIds: resolver follows a rotation to an unpinned keyid, pin rejects KEYID_MISMATCH, other label unaffected", () => {
  // The merchant rotated to "merchant-key-2" and its resolver
  // followed the rotation, so crypto passes — but the pin still
  // expects "merchant-key-1". The pin, not a pass, is the verdict.
  const dual = mergeSignatures(
    signMerchant("merchant-key-2", merchantRotated),
    signGateway("gateway-key-7"),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    keyResolvers: {
      merchant: store([["merchant-key-2", merchantRotated.publicKey]]),
      gateway: store([["gateway-key-7", gateway.publicKey]]),
    },
    expectedKeyIds: PINS,
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "KEYID_MISMATCH");
  assert.equal(by["merchant"].keyId, "merchant-key-2");
  assert.equal(by["gateway"].ok, true);
});

test("keyResolvers x expectedKeyIds: resolver maps a pinned keyid to the wrong public key, result is SIGNATURE_MISMATCH not KEYID_MISMATCH", () => {
  // The signature's keyid equals its pin, so the pin check would
  // pass — but it is never reached: the resolver hands back the
  // gateway's public key for the merchant's keyid, crypto fails
  // first, and that failure is the verdict. This is the precedence
  // the pin-after-crypto order in verifyWithKey actually gives.
  const dual = mergeSignatures(
    signMerchant("merchant-key-1"),
    signGateway("gateway-key-7"),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    keyResolvers: {
      merchant: store([["merchant-key-1", gateway.publicKey]]),
      gateway: store([["gateway-key-7", gateway.publicKey]]),
    },
    expectedKeyIds: PINS,
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});

test("keyResolvers x expectedKeyIds: unknown keyid fails KEY_RESOLUTION_FAILED before any pin check, other label unaffected", () => {
  // The pin matches, but the resolver cannot resolve the keyid at
  // all — resolution runs before crypto and before the pin, so
  // the verdict is the resolution failure, not a pin verdict.
  const dual = mergeSignatures(
    signMerchant("merchant-key-1"),
    signGateway("gateway-key-7"),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    keyResolvers: {
      merchant: store([]),
      gateway: store([["gateway-key-7", gateway.publicKey]]),
    },
    expectedKeyIds: PINS,
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "KEY_RESOLUTION_FAILED");
  assert.equal(by["merchant"].keyId, "merchant-key-1");
  assert.equal(by["gateway"].ok, true);
});

test("keyResolvers x expectedKeyIds: label unmapped in keyResolvers falls back to the global keyResolver while its pin still holds", () => {
  const dual = mergeSignatures(
    signMerchant("merchant-key-1"),
    signGateway("gateway-key-7"),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    keyResolver: store([["gateway-key-7", gateway.publicKey]]),
    keyResolvers: {
      merchant: store([["merchant-key-1", merchant.publicKey]]),
    },
    expectedKeyIds: PINS,
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].keyId, "gateway-key-7");
});

test("keyResolvers x expectedKeyIds: label unmapped in expectedKeyIds has no pin check, resolved key alone passes", () => {
  // Only the merchant is pinned. The gateway resolves through its
  // own resolver and carries an unpinned keyid, so it passes on
  // resolution + crypto alone — the merchant-only pin must not
  // leak onto it.
  const dual = mergeSignatures(
    signMerchant("merchant-key-1"),
    signGateway("gateway-key-7"),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    keyResolvers: {
      merchant: store([["merchant-key-1", merchant.publicKey]]),
      gateway: store([["gateway-key-7", gateway.publicKey]]),
    },
    expectedKeyIds: { merchant: "merchant-key-1" },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, true);
});
