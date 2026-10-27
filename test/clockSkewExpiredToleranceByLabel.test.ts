import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
} from "../src/index.js";

// Merchant: one fixed ed25519 key, strict on both time windows
// (clock skew 5s, expired tolerance 0s). Gateway: one HMAC secret,
// loose on both (clock skew 300s, expired tolerance 120s). Clock skew
// and expired tolerance are two independent windows on the same
// verify chain — #631 and #633 each pin their own map, but nothing
// pinned what happens when both maps are configured at once: does one
// dimension mask the other, or does each label keep its own verdict?
//
// One shape cannot be exercised with a minted signature: a single
// signature that violates both windows at once. `signRequest` refuses
// to mint `expires < created` (that shape is already expired at birth
// and surfaces as INVALID_TIME_WINDOW for hand-built signatures), and
// with `created <= expires` a signature cannot be both past its
// expiry and ahead of the verifier's clock at the same `now`. So the
// both-violated case is pinned at the verifyAllLabels-call level:
// one label violates the clock dimension, the other violates the
// expiry dimension, in a single call.
const NOW = 1700000000;
const COVERED = ["@method", "@authority", "@path", "content-digest"];

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

const merchant = generateEd25519KeyPair();
const GATEWAY = secretKey(randomBytes(32));

function signMerchant(created: number, expires: number): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created,
    expires,
    coveredComponents: COVERED,
  });
}

function signGateway(created: number, expires: number): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-9",
    alg: "hmac-sha256",
    key: GATEWAY,
    created,
    expires,
    coveredComponents: COVERED,
  });
}

function keys() {
  return { merchant: merchant.publicKey, gateway: GATEWAY };
}

// Merchant strict on both windows, gateway loose on both.
const STRICT_MERCHANT = {
  clockSkewToleranceSecByLabel: { merchant: 5, gateway: 300 },
  expiredToleranceSecByLabel: { merchant: 0, gateway: 120 },
};

// Strictness swapped: the maps follow the label, not the position.
const STRICT_GATEWAY = {
  clockSkewToleranceSecByLabel: { merchant: 300, gateway: 5 },
  expiredToleranceSecByLabel: { merchant: 120, gateway: 0 },
};

test("clockSkew x expired by label: future-created dual splits on the clock dimension only, expired map does not mask it", () => {
  // Both signatures are 120s in the future with a far-future expiry,
  // so only the clock dimension is in play — yet the expired map is
  // configured too, and must not change the clock verdict.
  const dual = mergeSignatures(
    signMerchant(NOW + 120, NOW + 3600),
    signGateway(NOW + 120, NOW + 3600),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    keys: keys(),
    ...STRICT_MERCHANT,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "CREATED_IN_FUTURE");
  assert.equal(
    results[0].reason,
    "signature created in the future (clock skew)",
  );
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("clockSkew x expired by label: expired dual splits on the expiry dimension only, clock map does not mask it", () => {
  // Both signatures were created an hour ago and expired 60s ago, so
  // only the expiry dimension is in play — yet the clock map is
  // configured too, and must not change the expiry verdict.
  const dual = mergeSignatures(
    signMerchant(NOW - 3600, NOW - 60),
    signGateway(NOW - 3600, NOW - 60),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    keys: keys(),
    ...STRICT_MERCHANT,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "EXPIRED");
  assert.equal(results[0].reason, "signature expired");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("clockSkew x expired by label: both dimensions violated in one call, each label keeps its own code", () => {
  // Merchant violates the clock dimension (120s ahead, 5s tolerance);
  // gateway violates the expiry dimension (expired 180s ago, 120s
  // grace). Neither violation leaks into the other label's verdict.
  const dual = mergeSignatures(
    signMerchant(NOW + 120, NOW + 3600),
    signGateway(NOW - 3600, NOW - 180),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    keys: keys(),
    ...STRICT_MERCHANT,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "CREATED_IN_FUTURE");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "EXPIRED");
});

test("clockSkew x expired by label: swapped strictness flips both splits, maps follow the label", () => {
  const future = mergeSignatures(
    signMerchant(NOW + 120, NOW + 3600),
    signGateway(NOW + 120, NOW + 3600),
  );
  const futureResults = verifyAllLabels(future, {
    now: NOW,
    keys: keys(),
    ...STRICT_GATEWAY,
  });
  assert.deepEqual(
    futureResults.map((r) => [r.label, r.ok, r.code]),
    [
      ["merchant", true, undefined],
      ["gateway", false, "CREATED_IN_FUTURE"],
    ],
  );

  const expired = mergeSignatures(
    signMerchant(NOW - 3600, NOW - 60),
    signGateway(NOW - 3600, NOW - 60),
  );
  const expiredResults = verifyAllLabels(expired, {
    now: NOW,
    keys: keys(),
    ...STRICT_GATEWAY,
  });
  assert.deepEqual(
    expiredResults.map((r) => [r.label, r.ok, r.code]),
    [
      ["merchant", true, undefined],
      ["gateway", false, "EXPIRED"],
    ],
  );
});
