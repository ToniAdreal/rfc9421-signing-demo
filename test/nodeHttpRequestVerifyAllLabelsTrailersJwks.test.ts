import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  fromNodeRequest,
  generateEd25519KeyPair,
  JwksKeyStore,
  signRequest,
  verifyAllLabels,
  type IncomingRequestLike,
  type JwksFetchImpl,
  type JwksKeyStoreSnapshot,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

// Backlog #769: `test/nodeHttpRequestVerifyAllLabelsTrailers.test.ts`
// (#757) pins a dual-signed trailer request through `fromNodeRequest`
// but resolves both labels from static keys, and
// `test/nodeHttpRequestVerifyAllLabelsJwks.test.ts` (#759) pins
// dual-signed requests resolved from per-party offline-restored
// `JwksKeyStore`s but never covers a `;tr` component in a JWKS
// combination (trailer appears there only in a comment pointing
// back at #757). So whether a dual-signed request received through
// the adapter, with one label binding a trailer and each label's key
// resolved from its own JWKS store, keeps trailer binding and
// per-label key resolution orthogonal was unpinned.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. `fromNodeRequest` already carries
// trailers into `RequestLike.trailers` with the header conventions,
// and `verifyAllLabels` already resolves each label through its own
// `keyResolvers` entry and reports each label independently.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = "hello";
const TRAILER_VALUE = "trailer-value";
const URL = "https://hooks.example.com/webhook";

const MERCHANT_URL = "https://merchant.example.com/.well-known/jwks.json";
const GATEWAY_URL = "https://gateway.example.com/.well-known/jwks.json";

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

function restoredStore(
  url: string,
  publicKey: KeyObject,
  kid: string,
  opts: { fetchImpl?: JwksFetchImpl } = {},
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
 * The merchant label binds the trailer (`@method` + `x-checksum;tr`);
 * the gateway label is the plain counterpart (`@method` only), so a
 * tampered trailer must fail the merchant label alone.
 */
function twoParty() {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const base = {
    method: "POST",
    url: URL,
    headers: { "content-type": "application/json" },
    trailers: { "x-checksum": TRAILER_VALUE },
    body: BODY,
  };
  const merchantSigned = signRequest(base, {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
    coveredComponents: ["@method", "x-checksum;tr"],
  });
  const gatewaySigned = signRequest(base, {
    keyId: "gateway-key-1",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@method"],
  });
  const merged: SignedHttpRequest = {
    ...merchantSigned,
    headers: {
      ...merchantSigned.headers,
      "signature-input": `${merchantSigned.headers["signature-input"]}, ${gatewaySigned.headers["signature-input"]}`,
      signature: `${merchantSigned.headers["signature"]}, ${gatewaySigned.headers["signature"]}`,
    },
  };
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
  return { merged, merchant, gateway, merchantStore, gatewayStore };
}

/** A test double shaped like the fields of http.IncomingMessage. */
function incomingRequest(
  overrides: Partial<IncomingRequestLike> & {
    headers: Record<string, string | string[] | undefined>;
  },
): IncomingRequestLike {
  return {
    method: "POST",
    url: "/webhook",
    socket: { encrypted: true },
    ...overrides,
  };
}

/** Wire-style headers carrying a dual signature, as a client sends them. */
function wireHeaders(
  signed: SignedHttpRequest,
): Record<string, string | undefined> {
  return {
    Host: "hooks.example.com",
    "Signature-Input": signed.headers["signature-input"] as string,
    Signature: signed.headers["signature"] as string,
  };
}

function adapted(
  signed: SignedHttpRequest,
  trailers: Record<string, string> = { "X-Checksum": TRAILER_VALUE },
): RequestLike {
  return fromNodeRequest(
    incomingRequest({ headers: wireHeaders(signed), trailers }),
    BODY,
  );
}

function resolvers(stores: {
  merchantStore: JwksKeyStore;
  gatewayStore: JwksKeyStore;
}) {
  return {
    merchant: stores.merchantStore.resolve,
    gateway: stores.gatewayStore.resolve,
  };
}

test("verifyAllLabels x fromNodeRequest x trailers x JwksKeyStore: a dual-signed request verifies both labels through the adapter, trailer label resolved from its own store", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  // The stores are independent: neither resolves the other party's kid.
  assert.equal(merchantStore.resolve("gateway-key-1"), undefined);
  assert.equal(gatewayStore.resolve("merchant-key-1"), undefined);
  const req = adapted(merged);
  // Mixed-case trailer name exercises the adapter's lowercasing, the
  // same convention it applies to headers.
  assert.deepEqual(req.trailers, { "x-checksum": TRAILER_VALUE });
  const results = verifyAllLabels(req, {
    now: NOW,
    keyResolvers: resolvers({ merchantStore, gatewayStore }),
  });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.ok(results[0].coveredComponents?.includes("@method"));
  assert.ok(results[0].coveredComponents?.includes("x-checksum;tr"));
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
  assert.equal(results[1].keyId, "gateway-key-1");
  assert.ok(results[1].coveredComponents?.includes("@method"));
  assert.equal(
    results[1].coveredComponents?.includes("x-checksum;tr"),
    false,
    "the plain gateway label must not claim trailer coverage",
  );
});

test("verifyAllLabels x fromNodeRequest x trailers x JwksKeyStore: a tampered trailer fails only the trailer label, the JWKS-resolved plain label still verifies", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  const results = verifyAllLabels(
    adapted(merged, { "x-checksum": "forged-value" }),
    {
      now: NOW,
      keyResolvers: resolvers({ merchantStore, gatewayStore }),
    },
  );
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_MISMATCH");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});

test("verifyAllLabels x fromNodeRequest x trailers x JwksKeyStore: after a rotation retires the merchant kid, only the trailer label fails with KEY_RESOLUTION_FAILED", async () => {
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
    { fetchImpl: rotatedFetch },
  );
  assert.notEqual(merchantStore.resolve("merchant-key-1"), undefined);
  await merchantStore.refresh();
  assert.equal(merchantStore.size, 1);
  assert.equal(merchantStore.resolve("merchant-key-1"), undefined);
  // The request still carries the old merchant kid, so only the
  // trailer label fails — fail-closed with KEY_RESOLUTION_FAILED,
  // never a silent fallback to the new key — while the gateway
  // plain label still verifies through the same adapted request.
  const results = verifyAllLabels(adapted(merged), {
    now: NOW,
    keyResolvers: resolvers({ merchantStore, gatewayStore }),
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "KEY_RESOLUTION_FAILED");
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});

test("verifyAllLabels x fromNodeRequest x trailers x JwksKeyStore: after a rotation retires the gateway kid, only the plain label fails with KEY_RESOLUTION_FAILED", async () => {
  const { merged, merchantStore, gateway } = twoParty();
  // Mirror of the merchant-retirement case in the other direction:
  // the gateway rotates, so only its plain label must fail while
  // the merchant trailer label, resolved from its own untouched
  // store, still verifies over the same adapted request.
  const rotated = generateEd25519KeyPair();
  const rotatedFetch: JwksFetchImpl = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      keys: [
        { ...exportPublicKeyJwk(rotated.publicKey), kid: "gateway-key-2" },
      ],
    }),
  });
  const gatewayStore = restoredStore(
    GATEWAY_URL,
    gateway.publicKey,
    "gateway-key-1",
    { fetchImpl: rotatedFetch },
  );
  assert.notEqual(gatewayStore.resolve("gateway-key-1"), undefined);
  await gatewayStore.refresh();
  assert.equal(gatewayStore.size, 1);
  assert.equal(gatewayStore.resolve("gateway-key-1"), undefined);
  const results = verifyAllLabels(adapted(merged), {
    now: NOW,
    keyResolvers: resolvers({ merchantStore, gatewayStore }),
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "KEY_RESOLUTION_FAILED");
  assert.equal(results[1].keyId, "gateway-key-1");
});
