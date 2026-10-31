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

// Two parties, one request, one expiry story split by label: both
// signatures were created an hour ago and expired 60 seconds ago.
// The merchant runs a strict 0s expiry tolerance; the gateway allows
// 120s for clock lag and retries. Each party's public key lives in
// its own offline-restored JwksKeyStore, so the question this file
// answers is whether JWKS resolution and per-label expiry tolerance
// compose orthogonally: resolution decides *which* key verifies,
// tolerance decides *whether* an expired signature still counts —
// and neither may leak into the other label's verdict.
const NOW = 1700000000;
const CREATED = NOW - 3600;
const EXPIRES = NOW - 60; // both signatures expired 60s ago
const COVERED = ["@method", "@authority", "@path", "content-digest"];

const MERCHANT_URL = "https://merchant.example.com/.well-known/jwks.json";
const GATEWAY_URL = "https://gateway.example.com/.well-known/jwks.json";

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
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
    expires: EXPIRES,
    coveredComponents: COVERED,
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

function verifyTwoParty(
  merged: SignedHttpRequest,
  merchantStore: JwksKeyStore,
  gatewayStore: JwksKeyStore,
  expiredToleranceSecByLabel: Record<string, number>,
) {
  return verifyAllLabels(merged, {
    now: NOW,
    keyResolvers: {
      merchant: merchantStore.resolve,
      gateway: gatewayStore.resolve,
    },
    expiredToleranceSecByLabel,
  });
}

test("verifyAllLabels x JwksKeyStore x expiredToleranceSecByLabel: 60s-expired merchant fails at 0s, gateway passes at 120s, each resolved from its own store", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  const results = verifyTwoParty(merged, merchantStore, gatewayStore, {
    merchant: 0,
    gateway: 120,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "EXPIRED");
  assert.equal(results[0].reason, "signature expired");
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].keyId, "gateway-key-1");
});

test("verifyAllLabels x JwksKeyStore x expiredToleranceSecByLabel: expiry exactly at the per-label tolerance still passes through JWKS resolvers", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  const results = verifyTwoParty(merged, merchantStore, gatewayStore, {
    merchant: 60,
    gateway: 60,
  });
  assert.deepEqual(
    results.map((r) => r.ok),
    [true, true],
  );
});

test("verifyAllLabels x JwksKeyStore x expiredToleranceSecByLabel: refresh re-publishing the signing kids leaves both tolerance verdicts unchanged", async () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signAs("merchant-key-1", merchant.privateKey, "merchant"),
    signAs("gateway-key-1", gateway.privateKey, "gateway"),
  );
  const republishFetch = (key: KeyObject, kid: string, newKid: string) =>
    (async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        keys: [
          { ...exportPublicKeyJwk(key), kid },
          {
            ...exportPublicKeyJwk(generateEd25519KeyPair().publicKey),
            kid: newKid,
          },
        ],
      }),
    })) as JwksFetchImpl;
  const merchantStore = restoredStore(
    MERCHANT_URL,
    merchant.publicKey,
    "merchant-key-1",
    {
      fetchImpl: republishFetch(
        merchant.publicKey,
        "merchant-key-1",
        "merchant-key-2",
      ),
      now: () => CREATED,
    },
  );
  const gatewayStore = restoredStore(
    GATEWAY_URL,
    gateway.publicKey,
    "gateway-key-1",
    {
      fetchImpl: republishFetch(
        gateway.publicKey,
        "gateway-key-1",
        "gateway-key-2",
      ),
      now: () => CREATED,
    },
  );
  const before = verifyTwoParty(merged, merchantStore, gatewayStore, {
    merchant: 0,
    gateway: 120,
  });
  assert.deepEqual(
    before.map((r) => [r.ok, r.code]),
    [
      [false, "EXPIRED"],
      [true, undefined],
    ],
  );
  await merchantStore.refresh();
  await gatewayStore.refresh();
  assert.equal(merchantStore.size, 2);
  assert.equal(gatewayStore.size, 2);
  const after = verifyTwoParty(merged, merchantStore, gatewayStore, {
    merchant: 0,
    gateway: 120,
  });
  assert.deepEqual(
    after.map((r) => [r.ok, r.code, r.keyId]),
    [
      [false, "EXPIRED", "merchant-key-1"],
      [true, undefined, "gateway-key-1"],
    ],
  );
});

test("verifyAllLabels x JwksKeyStore x expiredToleranceSecByLabel: retiring a kid fails that label with KEY_RESOLUTION_FAILED, tolerance cannot rescue it, and the other label's tolerance verdict stands", async () => {
  const { merged, merchant, gatewayStore } = twoParty();
  const rotated = generateEd25519KeyPair();
  const merchantStore = restoredStore(
    MERCHANT_URL,
    merchant.publicKey,
    "merchant-key-1",
    {
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          keys: [
            {
              ...exportPublicKeyJwk(rotated.publicKey),
              kid: "merchant-key-2",
            },
          ],
        }),
      }),
      now: () => CREATED,
    },
  );
  await merchantStore.refresh();
  assert.equal(merchantStore.resolve("merchant-key-1"), undefined);
  // Even a generous tolerance cannot rescue an unresolvable key:
  // resolution failure is reported before expiry is ever considered.
  const results = verifyTwoParty(merged, merchantStore, gatewayStore, {
    merchant: 120,
    gateway: 120,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "KEY_RESOLUTION_FAILED");
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});
