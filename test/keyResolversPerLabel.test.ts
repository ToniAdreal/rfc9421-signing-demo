import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;

function baseRequest(body?: string) {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body,
  };
}

/**
 * Combine two single-signature requests into one genuinely multi-label
 * RFC 9421 request, as a proxy would when appending its own signature.
 */
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

/**
 * Merchant signs with ed25519, gateway signs with hmac-sha256 —
 * the classic two-party payments scenario.
 */
function twoPartyRequest() {
  const merchant = generateEd25519KeyPair();
  const gatewaySecret = secretKey("keyResolvers-test-secret-32-bytes!!");
  const body = JSON.stringify({ amount: 250 });
  const a = signRequest(baseRequest(body), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
  });
  const b = signRequest(baseRequest(body), {
    keyId: "gateway-key-1",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
  });
  return { merged: mergeSignatures(a, b), merchant, gatewaySecret };
}

test("keyResolvers: each label resolves through its own keystore", () => {
  const { merged, merchant, gatewaySecret } = twoPartyRequest();
  const merchantStore = new Map<string, KeyObject>([
    ["merchant-key-1", merchant.publicKey],
  ]);
  const gatewayStore = new Map<string, KeyObject>([
    ["gateway-key-1", gatewaySecret],
  ]);
  const results = verifyAllLabels(merged, {
    now: NOW,
    keyResolvers: {
      merchant: (id) => merchantStore.get(id),
      gateway: (id) => gatewayStore.get(id),
    },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].alg, "hmac-sha256");
});

test("keyResolvers: label missing from the map falls back to the global keyResolver", () => {
  const { merged, merchant, gatewaySecret } = twoPartyRequest();
  const merchantStore = new Map<string, KeyObject>([
    ["merchant-key-1", merchant.publicKey],
  ]);
  const globalStore = new Map<string, KeyObject>([
    ["gateway-key-1", gatewaySecret],
  ]);
  const results = verifyAllLabels(merged, {
    now: NOW,
    keyResolver: (id) => globalStore.get(id),
    keyResolvers: { merchant: (id) => merchantStore.get(id) },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});

test("keyResolvers: unknown keyid fails with KEY_RESOLUTION_FAILED, other label unaffected", () => {
  const { merged, merchant, gatewaySecret } = twoPartyRequest();
  // The gateway's store is missing "gateway-key-1" (rotated out).
  const merchantStore = new Map<string, KeyObject>([
    ["merchant-key-1", merchant.publicKey],
  ]);
  const gatewayStore = new Map<string, KeyObject>();
  const results = verifyAllLabels(merged, {
    now: NOW,
    keyResolvers: {
      merchant: (id) => merchantStore.get(id),
      gateway: (id) => gatewayStore.get(id),
    },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "KEY_RESOLUTION_FAILED");
  assert.equal(results[1].label, "gateway");
  void gatewaySecret;
});

test("keyResolvers: combined with `key` throws a configuration error", () => {
  const { merged, merchant } = twoPartyRequest();
  assert.throws(
    () =>
      verifyAllLabels(merged, {
        now: NOW,
        key: merchant.publicKey,
        keyResolvers: { merchant: () => merchant.publicKey },
      }),
    /mutually exclusive with `keyResolver`\/`keyResolvers`/,
  );
});

test("keyResolvers: combined with `keys` throws a configuration error", () => {
  const { merged, merchant } = twoPartyRequest();
  assert.throws(
    () =>
      verifyAllLabels(merged, {
        now: NOW,
        keys: { merchant: merchant.publicKey },
        keyResolvers: { merchant: () => merchant.publicKey },
      }),
    /mutually exclusive with `keyResolver`\/`keyResolvers`/,
  );
});

test("keyResolvers: a throwing resolver converges to VERIFICATION_ERROR without polluting the other label", () => {
  const { merged, gatewaySecret } = twoPartyRequest();
  const gatewayStore = new Map<string, KeyObject>([
    ["gateway-key-1", gatewaySecret],
  ]);
  const results = verifyAllLabels(merged, {
    now: NOW,
    keyResolvers: {
      merchant: () => {
        throw new Error("merchant keystore is down");
      },
      gateway: (id) => gatewayStore.get(id),
    },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "VERIFICATION_ERROR");
  assert.match(results[0].reason ?? "", /merchant keystore is down/);
  assert.equal(results[1].ok, true);
});

test("keyResolvers: a non-function value throws a configuration error", () => {
  const { merged } = twoPartyRequest();
  assert.throws(
    () =>
      verifyAllLabels(merged, {
        now: NOW,
        keyResolvers: { merchant: "not-a-function" as never },
      }),
    /`keyResolvers\["merchant"\]` must be a function, got string/,
  );
});

test("keyResolvers: a non-object value throws a configuration error", () => {
  const { merged } = twoPartyRequest();
  assert.throws(
    () =>
      verifyAllLabels(merged, {
        now: NOW,
        keyResolvers: ["oops"] as never,
      }),
    /`keyResolvers` must be a label→resolver-function object/,
  );
});

test("keyResolvers: label missing from the map with no global keyResolver throws a configuration error", () => {
  const { merged, merchant } = twoPartyRequest();
  const merchantStore = new Map<string, KeyObject>([
    ["merchant-key-1", merchant.publicKey],
  ]);
  assert.throws(
    () =>
      verifyAllLabels(merged, {
        now: NOW,
        keyResolvers: { merchant: (id) => merchantStore.get(id) },
      }),
    /either `key` or `keyResolver` must be provided/,
  );
});
