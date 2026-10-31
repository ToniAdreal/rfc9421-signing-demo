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

// Backlog #751: `verifyAllLabelsContentDigest.test.ts` never mentions
// Jwks, and `verifyAllLabelsJwksKeyResolvers.test.ts` never mentions
// contentDigest. The three-way question is about interaction, not
// about any surface alone: in a dual-signed gateway flow, each label
// resolves through its own JWKS store AND each label covers the
// content-digest component. Do the per-label resolver mapping and
// the shared wire digest stay orthogonal — a digest failure on one
// label, or a key-resolution failure on one label, must not drag
// the other label down, and a stale or rotated store must not
// change the digest semantics pinned in #730?
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. All JWKS paths are offline snapshot
// restores (or stub fetches); zero real network.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const URL = "https://api.example.com/v1/payments";
const BODY_A = '{"amount":100}';
const BODY_B = '{"amount":1}';

const MERCHANT_URL = "https://merchant.example.com/.well-known/jwks.json";
const GATEWAY_URL = "https://gateway.example.com/.well-known/jwks.json";

/** A fetch that must never be called: restore paths are offline. */
const noFetch: JwksFetchImpl = async () => {
  throw new Error("fetch must not be called by snapshot restore");
};

function baseRequest(body: string) {
  return {
    method: "POST",
    url: URL,
    headers: { "content-type": "application/json" },
    body,
  };
}

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

function signAs(
  body: string,
  keyId: string,
  privateKey: KeyObject,
  label: string,
  contentDigestAlg?: "sha-256" | "sha-512",
): SignedHttpRequest {
  return signRequest(baseRequest(body), {
    keyId,
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label,
    ...(contentDigestAlg ? { contentDigestAlg } : {}),
  });
}

/**
 * One merchant + one gateway signature on the same request, each
 * party's public key held in its own offline-restored JwksKeyStore.
 * Both labels cover content-digest by default (a body is present),
 * so the wire carries a single sha-512 digest header.
 */
function twoParty(opts: {
  merchantStoreOpts?: StoreOpts;
  gatewayStoreOpts?: StoreOpts;
  digestAlg?: "sha-256" | "sha-512";
} = {}) {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signAs(BODY_A, "merchant-key-1", merchant.privateKey, "merchant", opts.digestAlg),
    signAs(BODY_A, "gateway-key-1", gateway.privateKey, "gateway", opts.digestAlg),
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

function verifyWithStores(
  req: SignedHttpRequest,
  merchantStore: JwksKeyStore,
  gatewayStore: JwksKeyStore,
) {
  return verifyAllLabels(req, {
    now: NOW,
    keyResolvers: {
      merchant: merchantStore.resolve,
      gateway: gatewayStore.resolve,
    },
  });
}

test("verifyAllLabels x content-digest x JwksKeyStore: dual labels each resolve via their own store and both cover the digest", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  assert.equal(merchantStore.resolve("gateway-key-1"), undefined);
  assert.equal(gatewayStore.resolve("merchant-key-1"), undefined);
  assert.ok(
    merged.headers["content-digest"]?.startsWith("sha-512="),
    "wire must carry the shared sha-512 digest",
  );
  const results = verifyWithStores(merged, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  for (const r of results) {
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(
      r.coveredComponents?.includes("content-digest"),
      `${r.label} must cover content-digest`,
    );
  }
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[1].keyId, "gateway-key-1");
});

test("verifyAllLabels x content-digest x JwksKeyStore: body swapped after signing fails both labels as BODY_DIGEST_MISMATCH, not a key failure", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  const swapped = { ...merged, body: BODY_B };
  const results = verifyWithStores(swapped, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  for (const r of results) {
    // Key resolution still succeeds for both labels (the stores are
    // untouched), so the digest dimension must surface on its own:
    // the crypto check passes over the untouched header value and
    // the body-vs-digest check rejects, exactly as in #730.
    assert.equal(r.ok, false);
    assert.equal(r.code, "BODY_DIGEST_MISMATCH");
    assert.equal(r.reason, "body does not match content-digest");
  }
});

test("verifyAllLabels x content-digest x JwksKeyStore: a label signed over a different digest fails alone, the other label still verifies", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  // Per-label divergence comes from signing history (as in #730):
  // the gateway label is minted over BODY_B's digest while the wire
  // header/body stay at BODY_A's values (merge keeps the first
  // signature's digest header).
  const divergent = mergeSignatures(
    signAs(BODY_A, "merchant-key-1", merchant.privateKey, "merchant"),
    signAs(BODY_B, "gateway-key-1", gateway.privateKey, "gateway"),
  );
  assert.ok(
    divergent.headers["content-digest"]?.startsWith("sha-512="),
    "wire digest must be the merchant's BODY_A line",
  );
  const merchantStore = restoredStore(
    MERCHANT_URL,
    merchant.publicKey,
    "merchant-key-1",
  );
  const gatewayStore = restoredStore(
    GATEWAY_URL,
    gateway.publicKey,
    "gateway-key-1",
  );
  const results = verifyWithStores(divergent, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("verifyAllLabels x content-digest x JwksKeyStore: rotated-out merchant key fails KEY_RESOLUTION_FAILED while the gateway digest label still verifies", async () => {
  const { merged, merchant, gatewayStore } = twoParty();
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
  assert.equal(merchantStore.resolve("merchant-key-1"), undefined);
  assert.notEqual(merchantStore.resolve("merchant-key-2"), undefined);
  const results = verifyWithStores(merged, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "KEY_RESOLUTION_FAILED");
  assert.equal(results[0].keyId, "merchant-key-1");
  // The gateway label's key still resolves and its digest still
  // binds the same wire body: a neighbour's key failure must not
  // turn into a digest or signature failure on this label.
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
  assert.ok(results[1].coveredComponents?.includes("content-digest"));
});

test("verifyAllLabels x content-digest x JwksKeyStore: a stale gateway snapshot still resolves and its digest label still verifies, with no fetch attempted", () => {
  const { merged, merchantStore, gatewayStore } = twoParty({
    gatewayStoreOpts: { now: () => CREATED + 1000 },
  });
  assert.equal(gatewayStore.isStale(), true);
  assert.notEqual(gatewayStore.resolve("gateway-key-1"), undefined);
  const results = verifyWithStores(merged, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  for (const r of results) {
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(r.coveredComponents?.includes("content-digest"));
  }
  assert.equal(results[1].keyId, "gateway-key-1");
});

test("verifyAllLabels x content-digest x JwksKeyStore: sha-256-only dual via per-label stores verifies via the sha-256 fallback", () => {
  const { merged, merchantStore, gatewayStore } = twoParty({
    digestAlg: "sha-256",
  });
  assert.ok(
    merged.headers["content-digest"]?.startsWith("sha-256="),
    "both labels must emit the sha-256 line",
  );
  const results = verifyWithStores(merged, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  for (const r of results) assert.equal(r.ok, true, JSON.stringify(r));
});
