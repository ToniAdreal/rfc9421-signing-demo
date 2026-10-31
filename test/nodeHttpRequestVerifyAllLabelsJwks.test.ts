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

// Backlog #759: `test/nodeHttpTrailers.test.ts` only ever walks the
// single-label `verifyRequest` path, and
// `test/verifyAllLabelsJwksKeyResolvers.test.ts` plus
// `test/verifyAllLabelsReplayCacheJwks.test.ts` never mention
// `fromNodeRequest` at all (grep count 0 in both) — so whether a
// dual-signed request received through the Node adapter, with each
// label's key resolved from its own offline-restored JwksKeyStore,
// keeps per-label isolation together was unpinned.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. `fromNodeRequest` already carries
// the wire signature headers verbatim (lowercasing names, joining
// multi-value fields exactly as `signRequest` does), and
// `verifyAllLabels` already resolves each label through its own
// `keyResolvers` entry and reports each label independently.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const EVENT_TYPE = "payment.settled";
const URL = "https://hooks.example.com/webhook?event=push";

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
 * The merchant label covers `@method` and the business header
 * `x-event-type`; the gateway label covers only `@method`, so a
 * tampered event type must fail the merchant label alone.
 */
function twoParty() {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const base = {
    method: "POST",
    url: URL,
    headers: { "content-type": "application/json", "x-event-type": EVENT_TYPE },
  };
  const merchantSigned = signRequest(base, {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
    coveredComponents: ["@method", "x-event-type"],
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
    url: "/webhook?event=push",
    socket: { encrypted: true },
    ...overrides,
  };
}

/** Wire-style headers carrying a dual signature, as a client sends them. */
function wireHeaders(
  signed: SignedHttpRequest,
  eventType: string = EVENT_TYPE,
): Record<string, string | undefined> {
  return {
    Host: "hooks.example.com",
    // Mixed-case name exercises the adapter's lowercasing, the same
    // convention `signRequest` applies to covered header names.
    "X-Event-Type": eventType,
    "Content-Type": "application/json",
    "Signature-Input": signed.headers["signature-input"] as string,
    Signature: signed.headers["signature"] as string,
  };
}

function adapted(
  signed: SignedHttpRequest,
  eventType: string = EVENT_TYPE,
): RequestLike {
  return fromNodeRequest(
    incomingRequest({ headers: wireHeaders(signed, eventType) }),
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

test("verifyAllLabels x fromNodeRequest x JwksKeyStore: a dual-signed request verifies both labels through the adapter, each resolved from its own store", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  // The stores are independent: neither resolves the other party's kid.
  assert.equal(merchantStore.resolve("gateway-key-1"), undefined);
  assert.equal(gatewayStore.resolve("merchant-key-1"), undefined);
  const req = adapted(merged);
  assert.equal(req.url, URL);
  assert.equal(req.headers["x-event-type"], EVENT_TYPE);
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
  assert.ok(results[0].coveredComponents?.includes("x-event-type"));
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
  assert.equal(results[1].keyId, "gateway-key-1");
  assert.ok(results[1].coveredComponents?.includes("@method"));
  assert.equal(
    results[1].coveredComponents?.includes("x-event-type"),
    false,
    "the gateway label must not claim business-header coverage",
  );
});

test("verifyAllLabels x fromNodeRequest x JwksKeyStore: after a rotation retires a kid, only that label fails and the other still verifies through the adapter", async () => {
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
  // The request still carries the old merchant kid, so only that label
  // fails — fail-closed with KEY_RESOLUTION_FAILED, never a silent
  // fallback to the new key — while the gateway label still verifies
  // through the same adapted request.
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

test("verifyAllLabels x fromNodeRequest x JwksKeyStore: a mismatched store key fails only that label, the other still verifies", () => {
  const { merged, merchantStore } = twoParty();
  // The gateway store holds a stranger's key under the gateway kid:
  // resolution succeeds but the signature cannot match, so the
  // gateway label must fail cryptographically while the merchant
  // label, resolved from its own correct store, still verifies.
  const stranger = generateEd25519KeyPair();
  const mismatchedGatewayStore = restoredStore(
    GATEWAY_URL,
    stranger.publicKey,
    "gateway-key-1",
  );
  const results = verifyAllLabels(adapted(merged), {
    now: NOW,
    keyResolvers: resolvers({
      merchantStore,
      gatewayStore: mismatchedGatewayStore,
    }),
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("verifyAllLabels x fromNodeRequest x JwksKeyStore: a tampered covered business header fails only the covering label", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  // The wire event type is rewritten after signing. Only the
  // merchant label covers `x-event-type`, so only it must fail;
  // the gateway label covers `@method` alone and is unaffected.
  const results = verifyAllLabels(adapted(merged, "payment.refunded"), {
    now: NOW,
    keyResolvers: resolvers({ merchantStore, gatewayStore }),
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_MISMATCH");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});
