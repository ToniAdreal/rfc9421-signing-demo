import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #642: `maxSignatureAgeSecByLabel` (per-label freshness
// window) and `requireNonceByLabel` (per-label nonce presence)
// have each been tested on their own
// (`test/maxSignatureAgeSecByLabel.test.ts`,
// `test/requireNonceByLabel.test.ts`), but never in combination.
// The combination has a real ambiguity: a merchant signature that
// is BOTH too old for its 60s window AND nonce-less — which code
// wins, SIGNATURE_TOO_OLD or MISSING_NONCE?
//
// This file pins the actual order in `src/verify.ts`: the age
// check runs before the nonce-presence check (age at ~line 1173,
// nonce at ~line 1202, both after the cryptographic check), so a
// signature violating both reports SIGNATURE_TOO_OLD, and
// MISSING_NONCE is only reachable when the signature is still
// inside its window. That corrects the backlog wording, which
// read as "old signature without nonce -> MISSING_NONCE": as
// written, that case cannot produce MISSING_NONCE, because the
// age check fires first. The isolated cases below still cover
// every verdict the backlog asked for — MISSING_NONCE for a
// fresh nonce-less merchant, SIGNATURE_TOO_OLD for an old
// nonce-carrying merchant, and a gateway signature inside its
// 3600s window passing throughout — plus the both-violations
// precedence case itself, so the correction is tested, not
// just asserted in a comment.

const CREATED = 1700000000;
const FRESH_NOW = CREATED + 30; // inside the merchant's 60s window
const OLD_NOW = CREATED + 300; // past 60s, inside the gateway's 3600s window

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

function signMerchant(opts: { nonce?: string; created?: number }) {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: opts.created ?? CREATED,
    ...(opts.nonce !== undefined ? { nonce: opts.nonce } : {}),
  });
}

function signGateway(opts: { nonce?: string; created?: number } = {}) {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-7",
    alg: "ed25519",
    key: gateway.privateKey,
    created: opts.created ?? CREATED,
    ...(opts.nonce !== undefined ? { nonce: opts.nonce } : {}),
  });
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

function options(now: number) {
  return {
    now,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    maxSignatureAgeSecByLabel: { merchant: 60, gateway: 3600 },
    requireNonceByLabel: { merchant: true },
  };
}

test("maxSignatureAge x requireNonce by label: fresh nonce-less merchant fails MISSING_NONCE, gateway without nonce passes", () => {
  // The merchant is 30s old — inside its 60s window — so the age
  // check passes and the nonce check is what fires. The gateway
  // carries no nonce either, but it is unmapped in
  // requireNonceByLabel and the global requireNonce is unset, so
  // no nonce check applies to it.
  const dual = mergeSignatures(signMerchant({}), signGateway());
  const results = verifyAllLabels(dual, options(FRESH_NOW));
  const by = byLabel(results);
  assert.equal(results.length, 2);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_NONCE");
  assert.equal(by["gateway"].ok, true);
});

test("maxSignatureAge x requireNonce by label: old nonce-carrying merchant fails SIGNATURE_TOO_OLD, gateway inside its window passes", () => {
  // The merchant is 300s old — past its 60s window — and carries
  // a nonce, so only the age check can fire. The gateway is the
  // same age but inside its 3600s window, so it still passes.
  const dual = mergeSignatures(
    signMerchant({ nonce: "merchant-nonce-1" }),
    signGateway(),
  );
  const results = verifyAllLabels(dual, options(OLD_NOW));
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_TOO_OLD");
  assert.equal(by["merchant"].nonce, "merchant-nonce-1");
  assert.equal(by["gateway"].ok, true);
});

test("maxSignatureAge x requireNonce by label: old AND nonce-less merchant fails SIGNATURE_TOO_OLD, not MISSING_NONCE", () => {
  // Both violations are present, and the age check runs first in
  // verifyRequest: the verdict is the age failure, and the
  // nonce failure is never reached. This is the precedence the
  // backlog wording got backwards — a test that asserted
  // MISSING_NONCE here would fail against the shipped code.
  const dual = mergeSignatures(signMerchant({}), signGateway());
  const results = verifyAllLabels(dual, options(OLD_NOW));
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_TOO_OLD");
  assert.equal(by["gateway"].ok, true);
});

test("maxSignatureAge x requireNonce by label: fresh nonce-carrying merchant and gateway both pass, nonce echoed", () => {
  const dual = mergeSignatures(
    signMerchant({ nonce: "merchant-nonce-1" }),
    signGateway({ nonce: "gateway-nonce-1" }),
  );
  const results = verifyAllLabels(dual, options(FRESH_NOW));
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].nonce, "merchant-nonce-1");
  assert.equal(by["merchant"].keyId, "merchant-key-1");
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].nonce, "gateway-nonce-1");
  assert.equal(by["gateway"].keyId, "gateway-key-7");
});

test("maxSignatureAge x requireNonce by label: a forgery still reports SIGNATURE_MISMATCH, not an age or nonce code", () => {
  // Both policy checks run after the cryptographic check, so a
  // forged merchant signature — old and nonce-less — must still
  // report the crypto failure, not either policy code. The
  // gateway label is unaffected.
  const dual = mergeSignatures(signMerchant({}), signGateway());
  const forged: SignedHttpRequest = {
    ...dual,
    headers: {
      ...dual.headers,
      signature: dual.headers["signature"]!.replace(
        "merchant=:",
        "merchant=:AAAA",
      ),
    },
  };
  const results = verifyAllLabels(forged, options(OLD_NOW));
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});
