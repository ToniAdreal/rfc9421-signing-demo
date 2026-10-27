import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  isVerifyError,
  ReplayCache,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #643: `verifyAllLabels` used to consult one shared
// `replayCache` for every label, keyed by the bare nonce string, so a
// merchant signature and a payment-gateway signature that happened to
// reuse the same nonce string could never both pass in one request:
// the first label recorded the nonce and the second was rejected as
// `NONCE_REPLAY` (pinned by `test/requireNonceByLabel.test.ts`).
// `replayCacheByLabel` partitions the namespace per label: a label in
// the map is checked against its own `NonceStore`, and only unmapped
// labels fall back to the global `replayCache`. This file pins that
// contract, including the opt-in nature — without the map, the shared
// behavior is unchanged.

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
const gateway = generateEd25519KeyPair();
const gatewayWrong = generateEd25519KeyPair();

function signLabel(label: string, pair: KeyPair, nonce: string) {
  return signRequest(baseRequest(), {
    label,
    keyId: label,
    alg: "ed25519",
    key: pair.privateKey,
    created: CREATED,
    nonce,
  });
}

function dual(nonce: string, gatewayPair: KeyPair = gateway) {
  return mergeSignatures(
    signLabel("merchant", merchant, nonce),
    signLabel("gateway", gatewayPair, nonce),
  );
}

function keys() {
  return { merchant: merchant.publicKey, gateway: gateway.publicKey };
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

function cache(ttlSec = 3600, now: () => number = () => NOW) {
  return new ReplayCache({ ttlSec, now });
}

test("replayCacheByLabel: same nonce in both labels passes in one call, and re-verifying replays in each label's own store", () => {
  const merchantCache = cache();
  const gatewayCache = cache();
  const req = dual("shared-nonce-1");
  const first = byLabel(
    verifyAllLabels(req, {
      now: NOW,
      keys: keys(),
      replayCacheByLabel: { merchant: merchantCache, gateway: gatewayCache },
    }),
  );
  // With a shared store this first call would already reject the
  // gateway label; per-label stores let both labels record the same
  // bare nonce string independently.
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);
  assert.equal(gatewayCache.size, 1);

  const second = byLabel(
    verifyAllLabels(req, {
      now: NOW,
      keys: keys(),
      replayCacheByLabel: { merchant: merchantCache, gateway: gatewayCache },
    }),
  );
  // Recording really happened in both stores (nothing was bypassed):
  // each label now replays against its own store.
  assert.equal(second["merchant"].ok, false);
  assert.equal(second["merchant"].code, "NONCE_REPLAY");
  assert.equal(second["gateway"].ok, false);
  assert.equal(second["gateway"].code, "NONCE_REPLAY");
});

test("replayCacheByLabel: a nonce already seen by the merchant store is still fresh in the gateway store", () => {
  const merchantCache = cache();
  const gatewayCache = cache();
  // Pre-seed only the merchant store, via a single-label verification
  // of the merchant's signature with the same nonce.
  const merchantOnly = signLabel("merchant", merchant, "shared-nonce-2");
  assert.equal(
    verifyRequest(merchantOnly, {
      label: "merchant",
      key: merchant.publicKey,
      now: NOW,
      replayCache: merchantCache,
    }).ok,
    true,
  );
  const results = byLabel(
    verifyAllLabels(dual("shared-nonce-2"), {
      now: NOW,
      keys: keys(),
      replayCacheByLabel: { merchant: merchantCache, gateway: gatewayCache },
    }),
  );
  assert.equal(results["merchant"].ok, false);
  assert.equal(results["merchant"].code, "NONCE_REPLAY");
  assert.equal(results["gateway"].ok, true);
});

test("replayCacheByLabel: an unmapped label falls back to the global replayCache", () => {
  const merchantCache = cache();
  const globalCache = cache();
  const req = dual("shared-nonce-3");
  const first = byLabel(
    verifyAllLabels(req, {
      now: NOW,
      keys: keys(),
      replayCache: globalCache,
      replayCacheByLabel: { merchant: merchantCache },
    }),
  );
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);
  assert.equal(globalCache.size, 1);

  const second = byLabel(
    verifyAllLabels(req, {
      now: NOW,
      keys: keys(),
      replayCache: globalCache,
      replayCacheByLabel: { merchant: merchantCache },
    }),
  );
  assert.equal(second["merchant"].code, "NONCE_REPLAY");
  assert.equal(second["gateway"].code, "NONCE_REPLAY");
});

test("replayCacheByLabel: with no global cache, an unmapped label is never replay-checked", () => {
  const merchantCache = cache();
  const req = dual("shared-nonce-4");
  for (let i = 0; i < 2; i++) {
    const results = byLabel(
      verifyAllLabels(req, {
        now: NOW,
        keys: keys(),
        replayCacheByLabel: { merchant: merchantCache },
      }),
    );
    // The gateway label has no store at all (no global, no map
    // entry), so it passes on every verification; the merchant
    // label replays on the second pass.
    assert.equal(results["gateway"].ok, true);
    if (i === 0) assert.equal(results["merchant"].ok, true);
    else assert.equal(results["merchant"].code, "NONCE_REPLAY");
  }
  assert.equal(merchantCache.size, 1);
});

test("replayCacheByLabel: a malformed map is a caller configuration error, not a verification failure", () => {
  const req = dual("shared-nonce-5");
  assert.throws(
    () =>
      verifyAllLabels(req, {
        now: NOW,
        keys: keys(),
        // @ts-expect-error deliberately malformed: a string is not a map
        replayCacheByLabel: "merchant-store",
      }),
    /replayCacheByLabel.*must be a label→store object/,
  );
  assert.throws(
    () =>
      verifyAllLabels(req, {
        now: NOW,
        keys: keys(),
        // @ts-expect-error deliberately malformed: an array is not a map
        replayCacheByLabel: [cache()],
      }),
    /replayCacheByLabel.*must be a label→store object/,
  );
});

test("replayCacheByLabel: a store value without a check function is a caller configuration error, even for an absent label", () => {
  const req = dual("shared-nonce-6");
  for (const bad of [
    {},
    { check: "not-a-function" },
    null,
    42,
  ] as unknown[]) {
    assert.throws(
      () =>
        verifyAllLabels(req, {
          now: NOW,
          keys: keys(),
          replayCacheByLabel: { merchant: bad as never },
        }),
      /replayCacheByLabel\["merchant"\].*must be a NonceStore with a check function/,
    );
  }
  // Validation covers the whole map, not just labels present in the
  // request: an invalid store for an absent label still fails fast.
  assert.throws(
    () =>
      verifyAllLabels(req, {
        now: NOW,
        keys: keys(),
        replayCacheByLabel: { absent: {} as never },
      }),
    /replayCacheByLabel\["absent"\]/,
  );
});

test("replayCacheByLabel: a failed verification pollutes neither label's store", () => {
  const merchantCache = cache();
  const gatewayCache = cache();
  // The gateway signature is forged (signed with the wrong key) but
  // carries the same nonce string as the valid merchant signature.
  const forged = byLabel(
    verifyAllLabels(dual("shared-nonce-7", gatewayWrong), {
      now: NOW,
      keys: keys(),
      replayCacheByLabel: { merchant: merchantCache, gateway: gatewayCache },
    }),
  );
  assert.equal(forged["merchant"].ok, true);
  assert.equal(forged["gateway"].ok, false);
  assert.equal(forged["gateway"].code, "SIGNATURE_MISMATCH");
  assert.equal(merchantCache.size, 1);
  assert.equal(gatewayCache.size, 0);

  // The correctly signed gateway signature with the same nonce still
  // passes: the forgery never reached (or recorded into) its store.
  const retried = byLabel(
    verifyAllLabels(dual("shared-nonce-7"), {
      now: NOW,
      keys: keys(),
      replayCacheByLabel: { merchant: merchantCache, gateway: gatewayCache },
    }),
  );
  assert.equal(retried["merchant"].code, "NONCE_REPLAY");
  assert.equal(retried["gateway"].ok, true);
  assert.equal(gatewayCache.size, 1);
});

test("replayCacheByLabel: without the map, the shared-store contract is unchanged", () => {
  const globalCache = cache();
  const results = byLabel(
    verifyAllLabels(dual("shared-nonce-8"), {
      now: NOW,
      keys: keys(),
      replayCache: globalCache,
    }),
  );
  assert.equal(results["merchant"].ok, true);
  // The gateway label carries the same bare nonce and shares the
  // store, so it is still rejected — per-label partitioning is
  // opt-in via the map, not a change to the default.
  assert.equal(results["gateway"].ok, false);
  assert.equal(results["gateway"].code, "NONCE_REPLAY");
});

test("replayCacheByLabel: per-label stores can carry different TTLs", () => {
  let t = NOW;
  const merchantCache = new ReplayCache({ ttlSec: 60, now: () => t });
  const gatewayCache = new ReplayCache({ ttlSec: 3600, now: () => t });
  const opts = {
    keys: keys(),
    replayCacheByLabel: { merchant: merchantCache, gateway: gatewayCache },
  };
  const first = byLabel(verifyAllLabels(dual("shared-nonce-9"), { ...opts, now: t }));
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);

  t = NOW + 120; // past the merchant TTL, inside the gateway TTL
  const second = byLabel(verifyAllLabels(dual("shared-nonce-9"), { ...opts, now: t }));
  assert.equal(second["merchant"].ok, true);
  assert.equal(second["gateway"].ok, false);
  assert.equal(second["gateway"].code, "NONCE_REPLAY");
});

test("replayCacheByLabel: a nonce recorded through the per-label map still throws NONCE_REPLAY from verifyRequestOrThrow", () => {
  const merchantCache = cache();
  const gatewayCache = cache();
  assert.equal(
    byLabel(
      verifyAllLabels(dual("shared-nonce-10"), {
        now: NOW,
        keys: keys(),
        replayCacheByLabel: { merchant: merchantCache, gateway: gatewayCache },
      }),
    )["merchant"].ok,
    true,
  );
  // The throwing single-label path reports the same stable code for
  // the same store: the map changes partitioning, not the code.
  assert.throws(
    () =>
      verifyRequestOrThrow(signLabel("merchant", merchant, "shared-nonce-10"), {
        label: "merchant",
        key: merchant.publicKey,
        now: NOW,
        replayCache: merchantCache,
      }),
    (e: unknown) => isVerifyError(e) && e.code === "NONCE_REPLAY",
  );
});

test("replayCacheByLabel: a map entry for a label absent from the request is ignored", () => {
  const merchantCache = cache();
  const absentCache = cache();
  const results = byLabel(
    verifyAllLabels(dual("shared-nonce-11"), {
      now: NOW,
      keys: keys(),
      replayCacheByLabel: { merchant: merchantCache, absent: absentCache },
    }),
  );
  assert.equal(results["merchant"].ok, true);
  assert.equal(results["gateway"].ok, true);
  assert.equal(absentCache.size, 0);
});
