import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
} from "../src/index.js";

// Merchant signs the payment initiation; gateway signs the same
// request when forwarding it. The two per-label maps live on the
// same verifyAllLabels chain but guard different time dimensions:
// `expiredToleranceSecByLabel` forgives a signature that has just
// passed its `expires`, while `maxSignatureAgeSecByLabel` caps how
// old a signature may be regardless of its `expires`. A signature
// can violate both at once (old *and* expired), so the combination
// has a real ordering question: which code does it report, and does
// a failure on one label mask anything on the other? These tests pin
// the measured order instead of assuming it.
const NOW = 1700000000;

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
      ...b.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  };
}

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

function signMerchant(created: number, expires: number): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created,
    expires,
    coveredComponents: ["@method", "@authority", "@path", "content-digest"],
  });
}

function signGateway(created: number, expires: number): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-9",
    alg: "ed25519",
    key: gateway.privateKey,
    created,
    expires,
    coveredComponents: ["@method", "@authority", "@path", "content-digest"],
  });
}

function dual(
  merchantCreated: number,
  merchantExpires: number,
  gatewayCreated: number,
  gatewayExpires: number,
): SignedHttpRequest {
  return mergeSignatures(
    signMerchant(merchantCreated, merchantExpires),
    signGateway(gatewayCreated, gatewayExpires),
  );
}

function keys() {
  return { merchant: merchant.publicKey, gateway: gateway.publicKey };
}

// Merchant: no expiry grace, 60s maximum age.
// Gateway: 120s expiry grace, 3600s maximum age.
const OPTIONS = {
  now: NOW,
  keys: keys(),
  expiredToleranceSecByLabel: { merchant: 0, gateway: 120 },
  maxSignatureAgeSecByLabel: { merchant: 60, gateway: 3600 },
};

test("expiredTolerance x maxAge: signature expired 60s ago is rejected for the 0s merchant, accepted for the 120s gateway", () => {
  // Both signatures are 3600s old and expired 60s ago. The gateway
  // survives both dimensions (60s within its 120s grace; 3600s is
  // exactly its maximum age, and the age check is strict-greater).
  // The merchant violates both dimensions at once — 60s past its
  // zero grace *and* 3600s old against a 60s window — yet reports
  // EXPIRED: the expiry check runs before the maximum-age check.
  const results = verifyAllLabels(
    dual(NOW - 3600, NOW - 60, NOW - 3600, NOW - 60),
    OPTIONS,
  );
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "EXPIRED");
  assert.equal(results[0].reason, "signature expired");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("expiredTolerance x maxAge: signature too old but not yet expired is rejected for the 60s merchant, accepted for the 3600s gateway", () => {
  // Both signatures are 300s old with an `expires` an hour in the
  // future, so only the age dimension can fail: the merchant's 60s
  // window rejects, the gateway's 3600s window passes.
  const results = verifyAllLabels(
    dual(NOW - 300, NOW + 3600, NOW - 300, NOW + 3600),
    OPTIONS,
  );
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_TOO_OLD");
  assert.equal(
    results[0].reason,
    "signature is too old: created 300s ago, older than maxSignatureAgeSec=60",
  );
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("expiredTolerance x maxAge: fresh, unexpired signatures pass both labels", () => {
  const results = verifyAllLabels(
    dual(NOW - 30, NOW + 3600, NOW - 30, NOW + 3600),
    OPTIONS,
  );
  assert.deepEqual(
    results.map((r) => r.ok),
    [true, true],
  );
});

test("expiredTolerance x maxAge: a gateway-only expiry failure does not mask a passing merchant", () => {
  // The merchant signature is fresh and unexpired; the gateway
  // signature is 3600s old but expired 180s ago — past even its
  // 120s grace (its age, exactly 3600s, is still within its window,
  // so the failure is purely the expiry dimension).
  const results = verifyAllLabels(
    dual(NOW - 30, NOW + 3600, NOW - 3600, NOW - 180),
    OPTIONS,
  );
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "EXPIRED");
  assert.equal(results[1].reason, "signature expired");
});

test("expiredTolerance x maxAge: expiry exactly at the gateway tolerance still passes while the merchant is already dead", () => {
  // Both signatures expired exactly 120s ago: the gateway's 120s
  // grace absorbs it (the expiry check is strict-greater) and its
  // 3600s age is exactly at its window, while the merchant's zero
  // grace rejects.
  const results = verifyAllLabels(
    dual(NOW - 3600, NOW - 120, NOW - 3600, NOW - 120),
    OPTIONS,
  );
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "EXPIRED");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("expiredTolerance x maxAge: age exactly at the merchant window still passes (strict-greater comparison)", () => {
  const results = verifyAllLabels(
    dual(NOW - 60, NOW + 3600, NOW - 60, NOW + 3600),
    OPTIONS,
  );
  assert.deepEqual(
    results.map((r) => r.ok),
    [true, true],
  );
});
