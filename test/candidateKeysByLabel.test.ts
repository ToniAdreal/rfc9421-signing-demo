import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  generateEd25519KeyPair,
  ReplayCache,
  secretKey,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
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

// Merchant: one fixed ed25519 key. Gateway: an HMAC secret rotation
// window (old + new), the Stripe-style rollover scenario.
const merchant = generateEd25519KeyPair();
const GATEWAY_OLD = secretKey(randomBytes(32));
const GATEWAY_NEW = secretKey(randomBytes(32));
const WRONG = secretKey(randomBytes(32));

function signMerchant(opts: { nonce?: string } = {}): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    nonce: opts.nonce,
    coveredComponents: COVERED,
  });
}

function signGateway(
  secret: ReturnType<typeof secretKey>,
  opts: { nonce?: string } = {},
): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-9",
    alg: "hmac-sha256",
    key: secret,
    created: CREATED,
    nonce: opts.nonce,
    coveredComponents: COVERED,
  });
}

function dual(nonce?: string): SignedHttpRequest {
  return mergeSignatures(signMerchant(), signGateway(GATEWAY_NEW, { nonce }));
}

test("candidateKeysByLabel: merchant + gateway each verify with their own rotation list", () => {
  const results = verifyAllLabels(dual(), {
    now: NOW,
    candidateKeysByLabel: {
      merchant: [merchant.publicKey],
      gateway: [GATEWAY_OLD, GATEWAY_NEW],
    },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("candidateKeysByLabel: gateway still verifies with the old secret during rotation", () => {
  const merged = mergeSignatures(signMerchant(), signGateway(GATEWAY_OLD));
  const results = verifyAllLabels(merged, {
    now: NOW,
    candidateKeysByLabel: {
      merchant: [merchant.publicKey],
      gateway: [GATEWAY_OLD, GATEWAY_NEW],
    },
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});

test("candidateKeysByLabel: merchant key is never tried against the gateway label", () => {
  // The merchant's ed25519 key is shape-incompatible with the gateway's
  // hmac-sha256 wire: if it were ever tried there, the candidate walk
  // would throw "wire alg incompatible" out of the rotation instead of
  // returning a result. Both passing with no throw proves the per-label
  // lists are strictly isolated.
  const results = verifyAllLabels(dual(), {
    now: NOW,
    candidateKeysByLabel: {
      merchant: [merchant.publicKey],
      gateway: [GATEWAY_OLD, GATEWAY_NEW],
    },
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});

test("candidateKeysByLabel: per-label list is what actually gets tried for that label", () => {
  // The merchant's list here contains a key that did not sign anything,
  // so the merchant label must fail while the gateway label (correct
  // list) still passes.
  const results = verifyAllLabels(dual(), {
    now: NOW,
    candidateKeysByLabel: {
      merchant: [WRONG],
      gateway: [GATEWAY_OLD, GATEWAY_NEW],
    },
  });
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("candidateKeysByLabel: label missing from the map falls back to global candidateKeys", () => {
  const merged = mergeSignatures(signMerchant(), signGateway(GATEWAY_OLD));
  const results = verifyAllLabels(merged, {
    now: NOW,
    candidateKeys: [GATEWAY_OLD, GATEWAY_NEW],
    candidateKeysByLabel: { merchant: [merchant.publicKey] },
  });
  assert.equal(results[0].ok, true);
  // "gateway" is not in the map → the global rotation list is used.
  assert.equal(results[1].ok, true);
});

test("candidateKeysByLabel: empty list for a label is a configuration error", () => {
  assert.throws(
    () =>
      verifyAllLabels(dual(), {
        now: NOW,
        candidateKeysByLabel: { merchant: [] },
      }),
    /verifyAllLabels: `candidateKeysByLabel\["merchant"\]` is invalid: .*non-empty array of KeyObjects/,
  );
});

test("candidateKeysByLabel: non-KeyObject entries are configuration errors", () => {
  assert.throws(
    () =>
      verifyAllLabels(dual(), {
        now: NOW,
        candidateKeysByLabel: {
          gateway: [GATEWAY_NEW, "not-a-key" as unknown as never],
        },
      }),
    /verifyAllLabels: `candidateKeysByLabel\["gateway"\]` is invalid: .*must be a KeyObject/,
  );
});

test("candidateKeysByLabel: a non-object map is a configuration error", () => {
  assert.throws(
    () =>
      verifyAllLabels(dual(), {
        now: NOW,
        candidateKeysByLabel: "nope" as unknown as never,
      }),
    /verifyAllLabels: `candidateKeysByLabel` must be a label→candidate-keys object/,
  );
});

test("candidateKeysByLabel: mutually exclusive with per-label keys", () => {
  assert.throws(
    () =>
      verifyAllLabels(dual(), {
        now: NOW,
        keys: { merchant: merchant.publicKey, gateway: GATEWAY_NEW },
        candidateKeysByLabel: { merchant: [merchant.publicKey] },
      }),
    /mutually exclusive/,
  );
});

test("candidateKeysByLabel: mutually exclusive with per-label keyResolvers", () => {
  assert.throws(
    () =>
      verifyAllLabels(dual(), {
        now: NOW,
        keyResolvers: { merchant: () => merchant.publicKey },
        candidateKeysByLabel: { merchant: [merchant.publicKey] },
      }),
    /mutually exclusive/,
  );
});

test("candidateKeysByLabel: mutually exclusive with the global key on that label", () => {
  assert.throws(
    () =>
      verifyAllLabels(signMerchant(), {
        now: NOW,
        key: merchant.publicKey,
        candidateKeysByLabel: { merchant: [merchant.publicKey] },
      }),
    /mutually exclusive/,
  );
});

test("candidateKeysByLabel: a label with no key source at all throws the same error as verifyRequest", () => {
  assert.throws(
    () =>
      verifyAllLabels(dual(), {
        now: NOW,
        candidateKeysByLabel: { merchant: [merchant.publicKey] },
        // "gateway" has no per-label list, no global key, resolver, or
        // candidates — verifyRequest's own "one of ..." rule fires.
      }),
    /one of `key`, `keyResolver`, or `candidateKeys` must be provided/,
  );
});

test("candidateKeysByLabel: failed rotation attempts never pollute the replay cache", () => {
  const cache = new ReplayCache();
  const nonce = "replay-probe-1";
  // First attempt: wrong secret — both candidates mismatch, the walk
  // records nothing.
  const bad = mergeSignatures(signMerchant(), signGateway(WRONG, { nonce }));
  const r1 = verifyAllLabels(bad, {
    now: NOW,
    candidateKeysByLabel: {
      merchant: [merchant.publicKey],
      gateway: [GATEWAY_OLD, GATEWAY_NEW],
    },
    replayCache: cache,
  });
  assert.equal(r1[1].ok, false);
  assert.equal(r1[1].code, "SIGNATURE_MISMATCH");
  // Same nonce with the correct (new) secret must still pass — a failed
  // rotation walk must not have recorded the nonce.
  const good = mergeSignatures(signMerchant(), signGateway(GATEWAY_NEW, { nonce }));
  const r2 = verifyAllLabels(good, {
    now: NOW,
    candidateKeysByLabel: {
      merchant: [merchant.publicKey],
      gateway: [GATEWAY_OLD, GATEWAY_NEW],
    },
    replayCache: cache,
  });
  assert.equal(r2[1].ok, true);
  assert.equal(r2[1].nonce, nonce);
});
