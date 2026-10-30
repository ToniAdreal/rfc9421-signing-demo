import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #727: `replayCacheByLabel` already has requireNonce /
// requireTag combination tests, and `maxSignatureAgeSecByLabel`
// already has its own tests, but no file combines the two. The
// interesting questions are all about interaction, not about either
// surface alone:
//
// - When one request carries a nonce already seen AND is past one
//   label's age window, which rejection wins? `verify.ts` checks
//   maximum age *before* consulting the replay cache (and the cache
//   is only consulted after every other check passes), so the
//   expected answer is SIGNATURE_TOO_OLD, not NONCE_REPLAY — but
//   that ordering was nowhere pinned for the per-label pair.
// - Are the two labels' windows and stores truly independent? A
//   merchant window of 60s must not clamp the gateway label, and a
//   replay (or an age failure) in one label's store must not leak
//   into the other label's store.
// - Does an age failure record anything? A failed check must never
//   pollute the cache, so the same nonce must still verify fresh
//   later (with a fresh `created`) after an age-failed attempt.
//
// This file pins all three, reading the check order from
// `src/verify.ts` rather than assuming it.

const CREATED = 1700000000;
const MERCHANT_WINDOW = 60;
const GATEWAY_WINDOW = 3600;

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

function signLabel(
  label: string,
  pair: KeyPair,
  nonce: string,
  created: number = CREATED,
) {
  return signRequest(baseRequest(), {
    label,
    keyId: label,
    alg: "ed25519",
    key: pair.privateKey,
    created,
    nonce,
  });
}

function dual(
  merchantNonce: string,
  gatewayNonce: string,
  created: number = CREATED,
) {
  return mergeSignatures(
    signLabel("merchant", merchant, merchantNonce, created),
    signLabel("gateway", gateway, gatewayNonce, created),
  );
}

function keys() {
  return { merchant: merchant.publicKey, gateway: gateway.publicKey };
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

function setup() {
  // Mutable clock shared by both stores so `size`/`stats` readings
  // stay consistent with the verification time passed to
  // `verifyAllLabels` (see the `size` doc on `ReplayCache`).
  let clockNow = CREATED + 30;
  const merchantCache = new ReplayCache({
    ttlSec: 3600,
    now: () => clockNow,
  });
  const gatewayCache = new ReplayCache({
    ttlSec: 3600,
    now: () => clockNow,
  });
  const verify = (req: SignedHttpRequest, now: number) => {
    clockNow = now;
    return byLabel(
      verifyAllLabels(req, {
        now,
        keys: keys(),
        maxSignatureAgeSecByLabel: {
          merchant: MERCHANT_WINDOW,
          gateway: GATEWAY_WINDOW,
        },
        replayCacheByLabel: {
          merchant: merchantCache,
          gateway: gatewayCache,
        },
      }),
    );
  };
  return { merchantCache, gatewayCache, verify };
}

test("replayCacheByLabel x maxAgeByLabel: fresh dual passes and each label records into its own store", () => {
  const { merchantCache, gatewayCache, verify } = setup();
  const results = verify(dual("shared-nonce-1", "shared-nonce-1"), CREATED + 30);
  assert.equal(results["merchant"].ok, true);
  assert.equal(results["gateway"].ok, true);
  // The same bare nonce string is tracked independently per label.
  assert.equal(merchantCache.size, 1);
  assert.equal(gatewayCache.size, 1);
  assert.deepEqual(merchantCache.stats(), {
    size: 1,
    hits: 0,
    misses: 1,
    evictions: 0,
  });
  assert.deepEqual(gatewayCache.stats(), {
    size: 1,
    hits: 0,
    misses: 1,
    evictions: 0,
  });
});

test("replayCacheByLabel x maxAgeByLabel: re-verifying the fresh dual replays in both labels", () => {
  const { merchantCache, gatewayCache, verify } = setup();
  const req = dual("shared-nonce-2", "shared-nonce-2");
  const first = verify(req, CREATED + 30);
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  const second = verify(req, CREATED + 30);
  assert.equal(second["merchant"].ok, false);
  assert.equal(second["merchant"].code, "NONCE_REPLAY");
  assert.equal(second["gateway"].ok, false);
  assert.equal(second["gateway"].code, "NONCE_REPLAY");
  assert.equal(merchantCache.stats().hits, 1);
  assert.equal(gatewayCache.stats().hits, 1);
});

test("replayCacheByLabel x maxAgeByLabel: age beats replay for the tight-window label", () => {
  const { merchantCache, gatewayCache, verify } = setup();
  const req = dual("seen-then-old", "seen-then-old");
  // First pass, well inside both windows: the nonce is recorded in
  // both stores.
  const first = verify(req, CREATED + 30);
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  // Second pass at +120s: past the merchant 60s window, inside the
  // gateway 3600s window, with a nonce seen in both stores. The
  // merchant label must report its true failure mode (age), not the
  // replay it would also match — `verify.ts` checks maximum age
  // before the replay cache.
  const second = verify(req, CREATED + 120);
  assert.equal(second["merchant"].ok, false);
  assert.equal(second["merchant"].code, "SIGNATURE_TOO_OLD");
  assert.equal(second["gateway"].ok, false);
  assert.equal(second["gateway"].code, "NONCE_REPLAY");
  // The age failure never consulted the merchant store: its
  // counters are exactly as after the first pass.
  assert.deepEqual(merchantCache.stats(), {
    size: 1,
    hits: 0,
    misses: 1,
    evictions: 0,
  });
  // The gateway label did consult its store and took the replay hit.
  assert.deepEqual(gatewayCache.stats(), {
    size: 1,
    hits: 1,
    misses: 1,
    evictions: 0,
  });
});

test("replayCacheByLabel x maxAgeByLabel: window boundary is inclusive, and one second past it only the tight label ages out", () => {
  const { merchantCache, gatewayCache, verify } = setup();
  // Age exactly equal to the window passes: the check is
  // `now - created > maxAge`, strictly greater.
  const atBoundary = verify(dual("boundary-nonce", "boundary-nonce"), CREATED + 60);
  assert.equal(atBoundary["merchant"].ok, true);
  assert.equal(atBoundary["gateway"].ok, true);
  // One second past the merchant window, with a fresh nonce: only
  // the merchant label fails, the gateway label still verifies and
  // records — the tight window does not clamp the wide one.
  const pastBoundary = verify(dual("past-nonce", "past-nonce"), CREATED + 61);
  assert.equal(pastBoundary["merchant"].ok, false);
  assert.equal(pastBoundary["merchant"].code, "SIGNATURE_TOO_OLD");
  assert.equal(pastBoundary["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);
  assert.equal(gatewayCache.size, 2);
  assert.equal(merchantCache.stats().misses, 1);
  assert.equal(gatewayCache.stats().misses, 2);
});

test("replayCacheByLabel x maxAgeByLabel: a replay in one label does not fail the other label", () => {
  const { merchantCache, gatewayCache, verify } = setup();
  const first = verify(dual("merchant-nonce", "gateway-nonce"), CREATED + 30);
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  // Same merchant nonce (replay), fresh gateway nonce, same time:
  // only the merchant label fails.
  const second = verify(dual("merchant-nonce", "gateway-nonce-2"), CREATED + 30);
  assert.equal(second["merchant"].ok, false);
  assert.equal(second["merchant"].code, "NONCE_REPLAY");
  assert.equal(second["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);
  assert.equal(gatewayCache.size, 2);
});

test("replayCacheByLabel x maxAgeByLabel: an age failure records nothing, so the same nonce verifies fresh later", () => {
  const { merchantCache, gatewayCache, verify } = setup();
  // First attempt is already past the merchant window: merchant
  // fails on age, gateway passes and records the nonce.
  const old = verify(dual("later-nonce", "later-nonce"), CREATED + 120);
  assert.equal(old["merchant"].ok, false);
  assert.equal(old["merchant"].code, "SIGNATURE_TOO_OLD");
  assert.equal(old["gateway"].ok, true);
  assert.equal(merchantCache.size, 0);
  assert.equal(gatewayCache.size, 1);
  // Same nonce string, freshly created at the verification time:
  // the merchant label must pass — the age-failed attempt left no
  // record — while the gateway label replays its earlier record.
  const fresh = verify(dual("later-nonce", "later-nonce", CREATED + 120), CREATED + 120);
  assert.equal(fresh["merchant"].ok, true);
  assert.equal(fresh["gateway"].ok, false);
  assert.equal(fresh["gateway"].code, "NONCE_REPLAY");
  assert.equal(merchantCache.size, 1);
  assert.equal(gatewayCache.size, 1);
});
