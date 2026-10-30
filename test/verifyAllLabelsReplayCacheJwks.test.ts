import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  ReplayCache,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type JwksFetchImpl,
  type JwksKeyStoreSnapshot,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #742: the two per-label maps were each pinned in isolation
// (`test/replayCacheByLabel.test.ts` pins per-label replay stores with
// static keys; `test/verifyAllLabelsJwksKeyResolvers.test.ts` pins
// per-label JwksKeyStore resolvers with no replay cache), but a dual
// signed gateway request in production uses both at once: each label
// resolves through its own JWKS endpoint and records its nonce in
// its own replay cache. This file pins that the two maps compose
// orthogonally — neither map leaks into the other label's verdict,
// and a failure on one axis (key rotation, replay) never drags the
// other label down with it. All JWKS paths are offline: snapshots
// are restored with a fetch that throws if called, except the
// rotation leg, whose fetch is a stub returning a rotated document
// (still zero real network).

const CREATED = 1700000000;
const NOW = CREATED + 60;

const MERCHANT_URL = "https://merchant.example.com/.well-known/jwks.json";
const GATEWAY_URL = "https://gateway.example.com/.well-known/jwks.json";

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ amount: 250 }),
  };
}

/**
 * Combine single-signature requests into one genuinely multi-label
 * RFC 9421 request, as a proxy would when appending its own signature
 * (same shape as the merge helpers in the two parent test files).
 */
function mergeSignatures(
  ...signed: SignedHttpRequest[]
): SignedHttpRequest {
  const first = signed[0];
  return {
    ...first,
    headers: {
      ...first.headers,
      "signature-input": signed
        .map((s) => s.headers["signature-input"])
        .join(", "),
      signature: signed.map((s) => s.headers["signature"]).join(", "),
    },
  };
}

function signAs(
  keyId: string,
  privateKey: KeyObject,
  label: string,
  nonce: string,
): SignedHttpRequest {
  return signRequest(baseRequest(), {
    keyId,
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label,
    nonce,
  });
}

/** A fetch that must never be called: restore paths are offline. */
const noFetch: JwksFetchImpl = async () => {
  throw new Error("fetch must not be called by snapshot restore");
};

function snapshotFor(
  publicKey: KeyObject,
  kid: string,
): JwksKeyStoreSnapshot {
  return {
    v: 1,
    fetchedAtSec: CREATED,
    keys: [{ ...exportPublicKeyJwk(publicKey), kid }],
  };
}

interface StoreOpts {
  fetchImpl?: JwksFetchImpl;
  ttlSec?: number;
  now?: () => number;
}

function restoredStore(
  url: string,
  publicKey: KeyObject,
  kid: string,
  opts: StoreOpts = {},
): JwksKeyStore {
  return JwksKeyStore.restore(snapshotFor(publicKey, kid), url, {
    fetchImpl: noFetch,
    ttlSec: 300,
    ...opts,
  });
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

function cache(ttlSec = 3600, now: () => number = () => NOW) {
  return new ReplayCache({ ttlSec, now });
}

/**
 * One merchant + one gateway signature on the same request, both
 * carrying the same bare nonce string, each party's public key held
 * in its own offline-restored JwksKeyStore.
 */
function twoParty(
  nonce: string,
  opts: {
    merchantStoreOpts?: StoreOpts;
    gatewayStoreOpts?: StoreOpts;
  } = {},
) {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signAs("merchant-key-1", merchant.privateKey, "merchant", nonce),
    signAs("gateway-key-1", gateway.privateKey, "gateway", nonce),
  );
  const merchantStore = restoredStore(
    MERCHANT_URL,
    merchant.publicKey,
    "merchant-key-1",
    opts.merchantStoreOpts,
  );
  const gatewayStore = restoredStore(
    GATEWAY_URL,
    gateway.publicKey,
    "gateway-key-1",
    opts.gatewayStoreOpts,
  );
  return { merged, merchant, gateway, merchantStore, gatewayStore };
}

function verifyDual(
  merged: SignedHttpRequest,
  merchantStore: JwksKeyStore,
  gatewayStore: JwksKeyStore,
  merchantCache: ReplayCache,
  gatewayCache: ReplayCache,
  now = NOW,
) {
  return byLabel(
    verifyAllLabels(merged, {
      now,
      keyResolvers: {
        merchant: merchantStore.resolve,
        gateway: gatewayStore.resolve,
      },
      replayCacheByLabel: {
        merchant: merchantCache,
        gateway: gatewayCache,
      },
    }),
  );
}

test("verifyAllLabels x replayCacheByLabel x JwksKeyStore: dual labels resolve through their own stores and record the same nonce independently", () => {
  const { merged, merchantStore, gatewayStore } = twoParty("shared-nonce-742-a");
  const merchantCache = cache();
  const gatewayCache = cache();
  // Cross-kid isolation on the resolver axis, as in #724: neither
  // store resolves the other party's kid.
  assert.equal(merchantStore.resolve("gateway-key-1"), undefined);
  assert.equal(gatewayStore.resolve("merchant-key-1"), undefined);
  const results = verifyDual(
    merged,
    merchantStore,
    gatewayStore,
    merchantCache,
    gatewayCache,
  );
  assert.equal(results["merchant"].ok, true);
  assert.equal(results["merchant"].keyId, "merchant-key-1");
  assert.equal(results["gateway"].ok, true);
  assert.equal(results["gateway"].keyId, "gateway-key-1");
  // The same bare nonce string was recorded once per label, not
  // once globally: with a shared store the second label would
  // already have failed on this first call.
  assert.equal(merchantCache.size, 1);
  assert.equal(gatewayCache.size, 1);
});

test("verifyAllLabels x replayCacheByLabel x JwksKeyStore: re-verifying the same dual request replays in each label's own store", () => {
  const { merged, merchantStore, gatewayStore } = twoParty("shared-nonce-742-b");
  const merchantCache = cache();
  const gatewayCache = cache();
  const first = verifyDual(
    merged,
    merchantStore,
    gatewayStore,
    merchantCache,
    gatewayCache,
  );
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  const second = verifyDual(
    merged,
    merchantStore,
    gatewayStore,
    merchantCache,
    gatewayCache,
  );
  assert.equal(second["merchant"].ok, false);
  assert.equal(second["merchant"].code, "NONCE_REPLAY");
  assert.equal(second["gateway"].ok, false);
  assert.equal(second["gateway"].code, "NONCE_REPLAY");
});

test("verifyAllLabels x replayCacheByLabel x JwksKeyStore: a nonce already seen by the merchant store is still fresh in the gateway store", () => {
  const { merged, merchant, merchantStore, gatewayStore } =
    twoParty("shared-nonce-742-c");
  const merchantCache = cache();
  const gatewayCache = cache();
  // Pre-seed only the merchant store, via a single-label verification
  // of the merchant's signature through its own JWKS resolver.
  const merchantOnly = signAs(
    "merchant-key-1",
    merchant.privateKey,
    "merchant",
    "shared-nonce-742-c",
  );
  assert.equal(
    verifyRequest(merchantOnly, {
      label: "merchant",
      keyResolver: merchantStore.resolve,
      now: NOW,
      replayCache: merchantCache,
    }).ok,
    true,
  );
  assert.equal(merchantCache.size, 1);
  assert.equal(gatewayCache.size, 0);
  const results = verifyDual(
    merged,
    merchantStore,
    gatewayStore,
    merchantCache,
    gatewayCache,
  );
  // One label's replay does not drag the other label: the merchant
  // label replays, the gateway label passes and records its nonce.
  assert.equal(results["merchant"].ok, false);
  assert.equal(results["merchant"].code, "NONCE_REPLAY");
  assert.equal(results["gateway"].ok, true);
  assert.equal(gatewayCache.size, 1);
});

test("verifyAllLabels x replayCacheByLabel x JwksKeyStore: a rotated-out kid fails only its own label and pollutes neither replay record it did not earn", async () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signAs("merchant-key-1", merchant.privateKey, "merchant", "shared-nonce-742-d"),
    signAs("gateway-key-1", gateway.privateKey, "gateway", "shared-nonce-742-d"),
  );
  // The merchant rotates: its endpoint now serves only the new kid.
  const rotated = generateEd25519KeyPair();
  const rotatedFetch: JwksFetchImpl = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      keys: [
        { ...exportPublicKeyJwk(rotated.publicKey), kid: "merchant-key-2" },
      ],
    }),
  });
  const merchantStore = restoredStore(
    MERCHANT_URL,
    merchant.publicKey,
    "merchant-key-1",
    { fetchImpl: rotatedFetch, now: () => CREATED },
  );
  await merchantStore.refresh();
  assert.equal(merchantStore.size, 1);
  assert.equal(merchantStore.resolve("merchant-key-1"), undefined);
  const gatewayStore = restoredStore(
    GATEWAY_URL,
    gateway.publicKey,
    "gateway-key-1",
  );
  const merchantCache = cache();
  const gatewayCache = cache();
  const first = verifyDual(
    merged,
    merchantStore,
    gatewayStore,
    merchantCache,
    gatewayCache,
  );
  // Fail-closed with KEY_RESOLUTION_FAILED, never a silent fallback
  // to the new key, while the gateway label still verifies.
  assert.equal(first["merchant"].ok, false);
  assert.equal(first["merchant"].code, "KEY_RESOLUTION_FAILED");
  assert.equal(first["merchant"].keyId, "merchant-key-1");
  assert.equal(first["gateway"].ok, true);
  // The failed label recorded nothing; the passing label recorded.
  assert.equal(merchantCache.size, 0);
  assert.equal(gatewayCache.size, 1);
  // A second attempt proves the two axes stay independent: the
  // merchant label still fails resolution (not replay), while the
  // gateway label now replays against the record it earned.
  const second = verifyDual(
    merged,
    merchantStore,
    gatewayStore,
    merchantCache,
    gatewayCache,
  );
  assert.equal(second["merchant"].code, "KEY_RESOLUTION_FAILED");
  assert.equal(second["gateway"].ok, false);
  assert.equal(second["gateway"].code, "NONCE_REPLAY");
});

test("verifyAllLabels x replayCacheByLabel x JwksKeyStore: a stale gateway snapshot still resolves and still records its nonce", () => {
  // The gateway snapshot is past its 300s TTL (clock pinned at
  // CREATED + 1000) and has never been re-pulled, yet resolve keeps
  // serving the last good snapshot — and the store's fetch throws if
  // anything ever calls it, so a passing verify proves no fetch ran.
  const { merged, merchantStore, gatewayStore } = twoParty(
    "shared-nonce-742-e",
    { gatewayStoreOpts: { now: () => CREATED + 1000 } },
  );
  assert.equal(gatewayStore.isStale(), true);
  const merchantCache = cache();
  const gatewayCache = cache();
  const first = verifyDual(
    merged,
    merchantStore,
    gatewayStore,
    merchantCache,
    gatewayCache,
  );
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  assert.equal(first["gateway"].keyId, "gateway-key-1");
  assert.equal(merchantCache.size, 1);
  assert.equal(gatewayCache.size, 1);
  const second = verifyDual(
    merged,
    merchantStore,
    gatewayStore,
    merchantCache,
    gatewayCache,
  );
  assert.equal(second["merchant"].code, "NONCE_REPLAY");
  assert.equal(second["gateway"].code, "NONCE_REPLAY");
});

test("verifyAllLabels x replayCacheByLabel x JwksKeyStore: per-label replay TTLs stay independent under per-label resolvers", () => {
  let t = NOW;
  const { merged, merchantStore, gatewayStore } = twoParty("shared-nonce-742-f");
  const merchantCache = new ReplayCache({ ttlSec: 60, now: () => t });
  const gatewayCache = new ReplayCache({ ttlSec: 3600, now: () => t });
  const opts = {
    keyResolvers: {
      merchant: merchantStore.resolve,
      gateway: gatewayStore.resolve,
    },
    replayCacheByLabel: {
      merchant: merchantCache,
      gateway: gatewayCache,
    },
  };
  const first = byLabel(verifyAllLabels(merged, { ...opts, now: t }));
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);

  t = NOW + 120; // past the merchant TTL, inside the gateway TTL
  const second = byLabel(verifyAllLabels(merged, { ...opts, now: t }));
  // The merchant nonce expired from its own store, so it passes
  // again and re-records; the gateway nonce is still live, so only
  // the gateway label replays. Resolver identity is unchanged by
  // the replay outcome on either side.
  assert.equal(second["merchant"].ok, true);
  assert.equal(second["merchant"].keyId, "merchant-key-1");
  assert.equal(second["gateway"].ok, false);
  assert.equal(second["gateway"].code, "NONCE_REPLAY");
});
