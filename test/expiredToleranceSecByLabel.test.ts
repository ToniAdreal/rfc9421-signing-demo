import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  verifyRequest,
  verifyAllLabels,
  type SignedHttpRequest,
} from "../src/index.js";

// Merchant: one fixed ed25519 key, strict expiry (no grace period).
// Gateway: one HMAC secret, a wider grace period for clock lag and
// retries. Both signatures carry the same timestamps — created an
// hour ago, expired 60 seconds ago — so a single global tolerance
// cannot express "merchant already dead, gateway still within grace":
// the per-label map is what splits them.
const NOW = 1700000000;
const CREATED = NOW - 3600;
const EXPIRES = NOW - 60; // both signatures expired 60s ago
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
    expires: EXPIRES,
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
    expires: EXPIRES,
    coveredComponents: COVERED,
  });
}

function dual(): SignedHttpRequest {
  return mergeSignatures(signMerchant(), signGateway());
}

function keys() {
  return { merchant: merchant.publicKey, gateway: GATEWAY };
}

test("expiredToleranceSecByLabel: 60s-expired signature rejected for the 0s merchant, accepted for the 120s gateway", () => {
  const results = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    expiredToleranceSecByLabel: { merchant: 0, gateway: 120 },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "EXPIRED");
  assert.equal(results[0].reason, "signature expired");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("expiredToleranceSecByLabel: expiry exactly at the tolerance still passes (strict-greater comparison)", () => {
  const results = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    expiredToleranceSecByLabel: { merchant: 60, gateway: 60 },
  });
  assert.deepEqual(
    results.map((r) => r.ok),
    [true, true],
  );
});

test("expiredToleranceSecByLabel: one second past the tolerance is expired", () => {
  const results = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    expiredToleranceSecByLabel: { merchant: 59, gateway: 59 },
  });
  assert.deepEqual(
    results.map((r) => r.code),
    ["EXPIRED", "EXPIRED"],
  );
});

test("expiredToleranceSecByLabel: unmapped label falls back to the global tolerance", () => {
  // Only the merchant is pinned (0s); the gateway falls back to the
  // global 120s and passes.
  const merchantOnly = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    expiredToleranceSec: 120,
    expiredToleranceSecByLabel: { merchant: 0 },
  });
  assert.equal(merchantOnly[0].ok, false);
  assert.equal(merchantOnly[0].code, "EXPIRED");
  assert.equal(merchantOnly[1].ok, true);

  // Only the gateway is pinned (120s); the merchant falls back to
  // the global 0s and fails.
  const gatewayOnly = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    expiredToleranceSec: 0,
    expiredToleranceSecByLabel: { gateway: 120 },
  });
  assert.equal(gatewayOnly[0].ok, false);
  assert.equal(gatewayOnly[0].code, "EXPIRED");
  assert.equal(gatewayOnly[1].ok, true);
});

test("expiredToleranceSecByLabel: without the map the global tolerance (or its 0s default) applies to both labels", () => {
  const wide = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    expiredToleranceSec: 120,
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
    ["EXPIRED", "EXPIRED"],
  );
});

test("expiredToleranceSecByLabel: negative, non-finite, or non-numeric values fail fast, zero stays valid", () => {
  for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY, "120"]) {
    assert.throws(
      () =>
        verifyAllLabels(dual(), {
          now: NOW,
          keys: keys(),
          expiredToleranceSecByLabel: { merchant: bad as never },
        }),
      /expiredToleranceSecByLabel/,
    );
  }
  assert.throws(
    () =>
      verifyAllLabels(dual(), {
        now: NOW,
        keys: keys(),
        expiredToleranceSecByLabel: [] as never,
      }),
    /expiredToleranceSecByLabel/,
  );
  // Zero is the strict global default, so mapping a label to 0 must
  // not throw — it rejects (EXPIRED), it does not fail fast.
  const zero = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    expiredToleranceSecByLabel: { merchant: 0, gateway: 0 },
  });
  assert.deepEqual(
    zero.map((r) => r.code),
    ["EXPIRED", "EXPIRED"],
  );
});

test("expiredToleranceSecByLabel: single-label verifyRequest global path is unchanged", () => {
  const gatewayOnly = signGateway();
  const tolerated = verifyRequest(gatewayOnly, {
    now: NOW,
    label: "gateway",
    key: GATEWAY,
    expiredToleranceSec: 120,
  });
  assert.equal(tolerated.ok, true);

  const strict = verifyRequest(gatewayOnly, {
    now: NOW,
    label: "gateway",
    key: GATEWAY,
  });
  assert.equal(strict.ok, false);
  assert.equal(strict.code, "EXPIRED");
});
