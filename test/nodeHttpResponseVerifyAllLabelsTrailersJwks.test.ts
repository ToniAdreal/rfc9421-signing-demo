import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  addSignature,
  exportPublicKeyJwk,
  fromNodeResponse,
  generateEd25519KeyPair,
  JwksKeyStore,
  signRequest,
  verifyAllLabels,
  type IncomingResponseLike,
  type JwksFetchImpl,
  type JwksKeyStoreSnapshot,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

// Backlog #781: the response-side combination was covered only two
// at a time — `test/nodeHttpResponseVerifyAllLabelsTrailers.test.ts`
// (#777) pins trailers through `fromNodeResponse` with direct keys,
// and `test/nodeHttpResponseVerifyAllLabelsJwks.test.ts` (#780)
// pins per-label JwksKeyStore resolution without trailers. The
// request side already has the four-way precedent
// (`nodeHttpRequestVerifyAllLabelsTrailersJwks.test.ts`), but
// whether a dual-signed *response* through the adapter keeps
// trailer binding and per-label JWKS resolution together had no
// backing. A gateway-signed settlement response whose checksum
// travels as a trailer, with each signer resolved from its own
// JWKS endpoint, is exactly that case.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. `fromNodeResponse` already carries
// trailers into `RequestLike.trailers`, and `verifyAllLabels`
// already resolves each label through its own `keyResolvers`
// entry and reports each label independently.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const TRAILER_VALUE = "trailer-value";
const URL = "https://api.example.com/v1/charge";

const MERCHANT_URL = "https://merchant.example.com/.well-known/jwks.json";
const GATEWAY_URL = "https://gateway.example.com/.well-known/jwks.json";

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

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

function stores() {
  return {
    merchantStore: restoredStore(
      MERCHANT_URL,
      merchant.publicKey,
      "merchant-key-1",
    ),
    gatewayStore: restoredStore(
      GATEWAY_URL,
      gateway.publicKey,
      "gateway-key-1",
    ),
  };
}

function resolvers(stores_: {
  merchantStore: JwksKeyStore;
  gatewayStore: JwksKeyStore;
}) {
  return {
    merchant: stores_.merchantStore.resolve,
    gateway: stores_.gatewayStore.resolve,
  };
}

/** A dual-signed response: merchant binds the trailer, gateway does not. */
function dualSigned(): SignedHttpRequest {
  const merchantSigned = signRequest(
    {
      method: "GET",
      url: URL,
      headers: {},
      body: BODY,
      status: 200,
      trailers: { "x-checksum": TRAILER_VALUE },
    },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
      coveredComponents: ["@status", "x-checksum;tr"],
    },
  );
  return addSignature(merchantSigned, {
    keyId: "gateway-key-1",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@status"],
  });
}

/** A test double shaped like the fields of a client's IncomingMessage. */
function incomingResponse(
  overrides: Partial<IncomingResponseLike> & {
    headers: Record<string, string | string[] | undefined>;
  },
): IncomingResponseLike {
  return { statusCode: 200, ...overrides };
}

/** Wire-style headers carrying a dual signature, as a server would send them. */
function wireHeaders(
  signed: SignedHttpRequest,
): Record<string, string | undefined> {
  return {
    "Signature-Input": signed.headers["signature-input"] as string,
    Signature: signed.headers["signature"] as string,
  };
}

function adapted(
  signed: SignedHttpRequest,
  extra: Partial<IncomingResponseLike> = {},
): RequestLike {
  return fromNodeResponse(
    incomingResponse({ headers: wireHeaders(signed), ...extra }),
    BODY,
    { method: "GET", url: URL },
  );
}

test("verifyAllLabels x fromNodeResponse x trailers x JwksKeyStore: a dual-signed response verifies both labels through the adapter, each resolved from its own store", () => {
  const { merchantStore, gatewayStore } = stores();
  // The stores are independent: neither resolves the other party's kid.
  assert.equal(merchantStore.resolve("gateway-key-1"), undefined);
  assert.equal(gatewayStore.resolve("merchant-key-1"), undefined);
  const req = adapted(dualSigned(), {
    // Mixed-case name exercises the adapter's lowercasing, the same
    // convention it applies to headers.
    trailers: { "X-Checksum": TRAILER_VALUE },
  });
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
  assert.ok(results[0].coveredComponents?.includes("@status"));
  assert.ok(results[0].coveredComponents?.includes("x-checksum;tr"));
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
  assert.equal(results[1].keyId, "gateway-key-1");
  assert.ok(results[1].coveredComponents?.includes("@status"));
  assert.equal(
    results[1].coveredComponents?.includes("x-checksum;tr"),
    false,
    "the gateway label must not claim trailer coverage",
  );
});

test("verifyAllLabels x fromNodeResponse x trailers x JwksKeyStore: a tampered trailer fails only the merchant label", () => {
  const { merchantStore, gatewayStore } = stores();
  const req = adapted(dualSigned(), {
    trailers: { "x-checksum": "forged-value" },
  });
  const results = verifyAllLabels(req, {
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

test("verifyAllLabels x fromNodeResponse x trailers x JwksKeyStore: after a rotation retires a kid, only that label fails and the other still verifies through the adapter", async () => {
  const { gatewayStore } = stores();
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
  // The response still carries the old merchant kid, so only that label
  // fails — fail-closed with KEY_RESOLUTION_FAILED, never a silent
  // fallback to the new key — while the gateway label still verifies
  // through the same adapted response.
  const req = adapted(dualSigned(), {
    trailers: { "x-checksum": TRAILER_VALUE },
  });
  const results = verifyAllLabels(req, {
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

test("verifyAllLabels x fromNodeResponse x trailers x JwksKeyStore: rawTrailers verify both labels end to end", () => {
  const { merchantStore, gatewayStore } = stores();
  const req = adapted(dualSigned(), {
    rawTrailers: ["X-Checksum", TRAILER_VALUE],
  });
  assert.deepEqual(req.trailers, { "x-checksum": TRAILER_VALUE });
  const results = verifyAllLabels(req, {
    now: NOW,
    keyResolvers: resolvers({ merchantStore, gatewayStore }),
  });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["merchant", true],
      ["gateway", true],
    ],
  );
});
