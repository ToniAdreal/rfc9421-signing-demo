import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
} from "../src/index.js";

// Merchant signs the payment initiation; gateway signs the same
// request when forwarding it. The two per-label maps live on
// different stages of the verifyAllLabels chain: the required-
// components check is a fail-fast policy gate that runs before any
// cryptography, while the clock-skew window is evaluated after the
// signature itself has been verified. Combining the maps therefore
// has a real ordering question: when one label violates both
// dimensions at once, which code does it report, and does a failure
// on one label mask anything on the other? These tests pin the
// measured order instead of assuming it.
const NOW = 1700000000;
const CREATED = NOW + 120; // both signatures are 120s in the future

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments?ref=abc",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
  };
}

function mergeSignatures(
  a: SignedHttpRequest,
  b: SignedHttpRequest,
): SignedHttpRequest {
  // Union the headers (so a content-digest header produced by either
  // signer survives), then combine the two signature dictionaries.
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
const stranger = generateEd25519KeyPair();

function signMerchant(coveredComponents: string[]): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    coveredComponents,
  });
}

function signGateway(coveredComponents: string[]): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-9",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    coveredComponents,
  });
}

function dual(
  merchantCovered: string[],
  gatewayCovered: string[],
): SignedHttpRequest {
  return mergeSignatures(
    signMerchant(merchantCovered),
    signGateway(gatewayCovered),
  );
}

function keys() {
  return { merchant: merchant.publicKey, gateway: gateway.publicKey };
}

// Merchant: 5s clock tolerance, must cover @path.
// Gateway: 300s clock tolerance, must cover content-digest.
// Both signatures are 120s in the future, so the merchant always
// violates its clock window while the gateway never does.
const OPTIONS = {
  now: NOW,
  keys: keys(),
  clockSkewToleranceSecByLabel: { merchant: 5, gateway: 300 },
  requiredComponentsByLabel: {
    merchant: ["@path"],
    gateway: ["content-digest"],
  },
};

test("clockSkew x requiredComponents: future created and missing @path reports the component code, not the clock code", () => {
  const results = verifyAllLabels(
    dual(["@method", "@authority"], ["@method", "@path", "content-digest"]),
    OPTIONS,
  );
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  // The merchant violates both dimensions (120s ahead against a 5s
  // tolerance, and no @path coverage), yet the component gate runs
  // first: the policy failure is reported, not the clock failure.
  assert.equal(results[0].code, "MISSING_REQUIRED_COMPONENT");
  assert.match(results[0].reason ?? "", /@path/);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("clockSkew x requiredComponents: future created with components complete reports the clock code", () => {
  const results = verifyAllLabels(
    dual(["@method", "@path"], ["@method", "@path", "content-digest"]),
    OPTIONS,
  );
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

test("clockSkew x requiredComponents: each label reports its own dimension, with no cross-label masking", () => {
  // Merchant covers @path (so only its clock window fails); gateway
  // drops content-digest (so only its coverage fails — its 300s
  // tolerance absorbs the same 120s skew).
  const results = verifyAllLabels(
    dual(["@method", "@path"], ["@method", "@path"]),
    OPTIONS,
  );
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "CREATED_IN_FUTURE");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "MISSING_REQUIRED_COMPONENT");
  assert.match(results[1].reason ?? "", /content-digest/);
});

test("clockSkew x requiredComponents: a missing component beats a bad signature, so the component gate precedes cryptography", () => {
  // The merchant signature is verified against a stranger's key, so
  // cryptography would fail — but the merchant also misses @path,
  // and the policy gate runs before any crypto.
  const results = verifyAllLabels(
    dual(["@method", "@authority"], ["@method", "@path", "content-digest"]),
    {
      ...OPTIONS,
      keys: { merchant: stranger.publicKey, gateway: gateway.publicKey },
    },
  );
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "MISSING_REQUIRED_COMPONENT");
  assert.match(results[0].reason ?? "", /@path/);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("clockSkew x requiredComponents: a bad signature beats the clock code, so the clock window is evaluated after cryptography", () => {
  // Same wrong-key setup, but now the merchant covers @path: with
  // the policy gate satisfied, cryptography fails first and the
  // clock window is never reached, even though the signature is
  // also 120s ahead of a 5s tolerance.
  const results = verifyAllLabels(
    dual(["@method", "@path"], ["@method", "@path", "content-digest"]),
    {
      ...OPTIONS,
      keys: { merchant: stranger.publicKey, gateway: gateway.publicKey },
    },
  );
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_MISMATCH");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});
