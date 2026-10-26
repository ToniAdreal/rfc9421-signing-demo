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

// Merchant: one fixed ed25519 key, tight clock discipline.
// Gateway: one HMAC secret, looser clock discipline. Both signatures
// are minted at the same instant, 120 seconds ahead of the verifier's
// clock, so a single global tolerance cannot express "merchant too
// far ahead, gateway within tolerance" — the per-label map is what
// splits them.
const NOW = 1700000000;
const CREATED = NOW + 120; // both signatures are 120s in the future
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

function signMerchant(): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
}

function signGateway(): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-9",
    alg: "hmac-sha256",
    key: GATEWAY,
    created: CREATED,
    coveredComponents: COVERED,
  });
}

function dual(): SignedHttpRequest {
  return mergeSignatures(signMerchant(), signGateway());
}

function keys() {
  return { merchant: merchant.publicKey, gateway: GATEWAY };
}

test("clockSkewToleranceSecByLabel: 120s skew rejected for the 5s merchant, accepted for the 300s gateway", () => {
  const results = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    clockSkewToleranceSecByLabel: { merchant: 5, gateway: 300 },
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

test("clockSkewToleranceSecByLabel: skew exactly at the tolerance still passes (strict-greater comparison)", () => {
  const results = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    clockSkewToleranceSecByLabel: { merchant: 120, gateway: 120 },
  });
  assert.deepEqual(
    results.map((r) => r.ok),
    [true, true],
  );
});

test("clockSkewToleranceSecByLabel: unmapped label falls back to the global tolerance", () => {
  // Only the merchant is pinned (5s); the gateway falls back to the
  // global 300s and passes.
  const merchantOnly = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    clockSkewToleranceSec: 300,
    clockSkewToleranceSecByLabel: { merchant: 5 },
  });
  assert.equal(merchantOnly[0].ok, false);
  assert.equal(merchantOnly[0].code, "CREATED_IN_FUTURE");
  assert.equal(merchantOnly[1].ok, true);

  // Only the gateway is pinned (300s); the merchant falls back to the
  // global 5s and fails.
  const gatewayOnly = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    clockSkewToleranceSec: 5,
    clockSkewToleranceSecByLabel: { gateway: 300 },
  });
  assert.equal(gatewayOnly[0].ok, false);
  assert.equal(gatewayOnly[0].code, "CREATED_IN_FUTURE");
  assert.equal(gatewayOnly[1].ok, true);
});

test("clockSkewToleranceSecByLabel: without the map the global tolerance (or its 60s default) applies to both labels", () => {
  const wide = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    clockSkewToleranceSec: 300,
  });
  assert.deepEqual(
    wide.map((r) => r.ok),
    [true, true],
  );

  const byDefault = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
  });
  assert.deepEqual(
    byDefault.map((r) => r.code),
    ["CREATED_IN_FUTURE", "CREATED_IN_FUTURE"],
  );
});

test("clockSkewToleranceSecByLabel: non-positive, non-finite, or non-numeric values fail fast", () => {
  for (const bad of [0, -5, Number.NaN, Number.POSITIVE_INFINITY, "300"]) {
    assert.throws(
      () =>
        verifyAllLabels(dual(), {
          now: NOW,
          keys: keys(),
          clockSkewToleranceSecByLabel: { merchant: bad as never },
        }),
      /clockSkewToleranceSecByLabel/,
    );
  }
  assert.throws(
    () =>
      verifyAllLabels(dual(), {
        now: NOW,
        keys: keys(),
        clockSkewToleranceSecByLabel: [] as never,
      }),
    /clockSkewToleranceSecByLabel/,
  );
});
