import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  signRequest,
  verifyAllLabels,
  type JwksFetchImpl,
  type JwksKeyStoreSnapshot,
  type SignedHttpRequest,
} from "../src/index.js";

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
 * (same shape as the merge helper in keyResolversPerLabel.test.ts).
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
): SignedHttpRequest {
  return signRequest(baseRequest(), {
    keyId,
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label,
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

/**
 * One merchant + one gateway signature on the same request, each
 * party's public key held in its own offline-restored JwksKeyStore.
 * Per-test store options (e.g. a pinned clock) ride through so a
 * single fixture serves the fresh, rotated, and stale legs.
 */
function twoParty(opts: {
  merchantStoreOpts?: StoreOpts;
  gatewayStoreOpts?: StoreOpts;
} = {}) {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signAs("merchant-key-1", merchant.privateKey, "merchant"),
    signAs("gateway-key-1", gateway.privateKey, "gateway"),
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

test("verifyAllLabels x JwksKeyStore: each label resolves through its own restored store, by reference, with keyid echo", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  // The stores are independent: neither resolves the other party's kid.
  assert.equal(merchantStore.resolve("gateway-key-1"), undefined);
  assert.equal(gatewayStore.resolve("merchant-key-1"), undefined);
  // `store.resolve` is passed by reference, unbound, exactly as the
  // VerifyOptions.keyResolver shape requires.
  const results = verifyAllLabels(merged, {
    now: NOW,
    keyResolvers: {
      merchant: merchantStore.resolve,
      gateway: gatewayStore.resolve,
    },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[0].alg, "ed25519");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].keyId, "gateway-key-1");
  assert.equal(results[1].alg, "ed25519");
});

test("verifyAllLabels x JwksKeyStore: after a rotation refresh retires a kid, that label fails KEY_RESOLUTION_FAILED and the other still passes", async () => {
  const { merged, merchant, gatewayStore } = twoParty();
  // The merchant rotates: its endpoint now serves only the new kid.
  // The fetch is a stub returning the rotated document — still zero
  // real network — and refresh() is the re-pull that retires the old kid.
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
  assert.notEqual(merchantStore.resolve("merchant-key-1"), undefined);
  await merchantStore.refresh();
  assert.equal(merchantStore.size, 1);
  assert.equal(merchantStore.resolve("merchant-key-1"), undefined);
  assert.notEqual(merchantStore.resolve("merchant-key-2"), undefined);
  // The request still carries the old merchant kid, so only that label
  // fails — fail-closed with KEY_RESOLUTION_FAILED, never a silent
  // fallback to the new key — while the gateway label still verifies.
  const results = verifyAllLabels(merged, {
    now: NOW,
    keyResolvers: {
      merchant: merchantStore.resolve,
      gateway: gatewayStore.resolve,
    },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "KEY_RESOLUTION_FAILED");
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("verifyAllLabels x JwksKeyStore: a stale snapshot still resolves (stale-but-serving), with no fetch attempted", () => {
  // The gateway snapshot is past its 300s TTL (clock pinned at
  // CREATED + 1000) and has never been re-pulled, yet resolve keeps
  // serving the last good snapshot — and the store's fetch throws if
  // anything ever calls it, so a passing verify proves no fetch ran.
  const { merged, merchantStore, gatewayStore } = twoParty({
    gatewayStoreOpts: { now: () => CREATED + 1000 },
  });
  assert.equal(gatewayStore.isStale(), true);
  assert.notEqual(gatewayStore.resolve("gateway-key-1"), undefined);
  const results = verifyAllLabels(merged, {
    now: NOW,
    keyResolvers: {
      merchant: merchantStore.resolve,
      gateway: gatewayStore.resolve,
    },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
  assert.equal(results[1].keyId, "gateway-key-1");
});

test("verifyAllLabels x JwksKeyStore: a label absent from the map falls back to the global keyResolver", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  // A third, auditor signature on the same request, whose key lives
  // nowhere in the per-label stores — only in the global resolver.
  const auditor = generateEd25519KeyPair();
  const threeParty = mergeSignatures(
    merged,
    signAs("auditor-key-1", auditor.privateKey, "auditor"),
  );
  void merged;
  const results = verifyAllLabels(threeParty, {
    now: NOW,
    keyResolver: (id) =>
      id === "auditor-key-1" ? auditor.publicKey : undefined,
    keyResolvers: {
      merchant: merchantStore.resolve,
      gateway: gatewayStore.resolve,
    },
  });
  assert.equal(results.length, 3);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
  assert.equal(results[2].label, "auditor");
  assert.equal(results[2].ok, true);
  assert.equal(results[2].keyId, "auditor-key-1");
});
