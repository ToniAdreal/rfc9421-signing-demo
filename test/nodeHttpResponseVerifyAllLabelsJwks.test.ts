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

// Backlog #780: `test/nodeHttpResponseVerifyAllLabels.test.ts`
// (#737) pins a dual-signed response through `fromNodeResponse`,
// but never mentions Jwks/KeyStore; #759 pins the request-side
// mirror (`fromNodeRequest` x `verifyAllLabels` x JwksKeyStore).
// Whether a dual-signed *response* through the adapter, with each
// label's key resolved from its own offline-restored JwksKeyStore,
// keeps per-label isolation together was unpinned. This is the
// response-side mirror of #759.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. `fromNodeResponse` already carries
// the wire signature headers verbatim and `verifyAllLabels` already
// resolves each label through its own `keyResolvers` entry and
// reports each label independently.
//
// Body-tamper honesty note (read before "fixing" the third case):
// a post-signing body swap cannot isolate to one label in this
// library, because `src/verify.ts` runs the body-vs-content-digest
// check whenever a wire content-digest header is present, regardless
// of whether a label's covered list includes `content-digest` (the
// same global-binding behaviour pinned by #730). So the per-label
// body isolation is pinned here as a signing-history divergence
// (one label minted over a different body, wire left at the other
// label's body and digest: only the divergent label fails), and a
// separate case pins the post-signing swap as failing *both*
// labels with BODY_DIGEST_MISMATCH. Asserting a one-label failure
// for a post-signing swap would be asserting false behaviour.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const BODY_OTHER = JSON.stringify({ settled: true, amount: 1 });
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

/** Wire-style headers carrying a signature, as a server would send them. */
function wireHeaders(
  signed: SignedHttpRequest,
): Record<string, string | undefined> {
  const headers: Record<string, string | undefined> = {
    "Signature-Input": signed.headers["signature-input"] as string,
    Signature: signed.headers["signature"] as string,
  };
  if (signed.headers["content-digest"] !== undefined) {
    headers["Content-Digest"] = signed.headers["content-digest"] as string;
  }
  return headers;
}

/** A test double shaped like the fields of a client's IncomingMessage. */
function incomingResponse(
  overrides: Partial<IncomingResponseLike> & {
    headers: Record<string, string | string[] | undefined>;
  },
): IncomingResponseLike {
  return { statusCode: 200, ...overrides };
}

function response(status = 200, body: string = BODY) {
  return { method: "GET", url: URL, headers: {}, body, status };
}

/** A dual-signed response: merchant first, gateway appended. */
function dualSigned(): SignedHttpRequest {
  const merchantSigned = signRequest(response(), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
    coveredComponents: ["@status"],
  });
  return addSignature(merchantSigned, {
    keyId: "gateway-key-1",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@status"],
  });
}

/** Merge two independently signed responses into one wire header set. */
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

function adapted(signed: SignedHttpRequest, body: string = BODY): RequestLike {
  return fromNodeResponse(incomingResponse({ headers: wireHeaders(signed) }), body, {
    method: "GET",
    url: URL,
  });
}

test("verifyAllLabels x fromNodeResponse x JwksKeyStore: a dual-signed response verifies both labels through the adapter, each resolved from its own store", () => {
  const { merchantStore, gatewayStore } = stores();
  // The stores are independent: neither resolves the other party's kid.
  assert.equal(merchantStore.resolve("gateway-key-1"), undefined);
  assert.equal(gatewayStore.resolve("merchant-key-1"), undefined);
  const results = verifyAllLabels(adapted(dualSigned()), {
    now: NOW,
    keyResolvers: resolvers({ merchantStore, gatewayStore }),
    requiredComponents: ["@status"],
  });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  for (const r of results) {
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(
      r.coveredComponents?.includes("@status"),
      `${r.label} must cover @status`,
    );
  }
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[1].keyId, "gateway-key-1");
});

test("verifyAllLabels x fromNodeResponse x JwksKeyStore: after a rotation retires a kid, only that label fails and the other still verifies through the adapter", async () => {
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
  const results = verifyAllLabels(adapted(dualSigned()), {
    now: NOW,
    keyResolvers: resolvers({ merchantStore, gatewayStore }),
    requiredComponents: ["@status"],
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "KEY_RESOLUTION_FAILED");
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});

test("verifyAllLabels x fromNodeResponse x JwksKeyStore: a label minted over a different body fails alone, the other label still verifies", () => {
  // Per-label body isolation, built as signing-history divergence
  // (the #730 pattern): the gateway label is minted over BODY_OTHER
  // with its own content-digest, while the wire body and wire digest
  // are the merchant's. Only the divergent label must fail, with
  // SIGNATURE_MISMATCH — its base covers a digest value that is not
  // on the wire — while the merchant label verifies.
  const divergent = mergeSignatures(
    signRequest(response(200, BODY), {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
      coveredComponents: ["@status", "content-digest"],
    }),
    signRequest(response(200, BODY_OTHER), {
      keyId: "gateway-key-1",
      alg: "ed25519",
      key: gateway.privateKey,
      created: CREATED,
      label: "gateway",
      coveredComponents: ["@status", "content-digest"],
    }),
  );
  const { merchantStore, gatewayStore } = stores();
  const results = verifyAllLabels(adapted(divergent), {
    now: NOW,
    keyResolvers: resolvers({ merchantStore, gatewayStore }),
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.ok(results[0].coveredComponents?.includes("content-digest"));
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("verifyAllLabels x fromNodeResponse x JwksKeyStore: a post-signing body swap fails both content-digest labels as BODY_DIGEST_MISMATCH", () => {
  // The honest counterpart to the divergence case above: swapping
  // the body after signing, with the wire digest untouched, fails
  // both labels — the verifier's body check runs whenever a wire
  // content-digest header is present, even for a label that does not
  // cover it. This is the global body binding pinned by #730, not a
  // per-label failure, and it must not be "fixed" by asserting a
  // one-label failure here.
  const merchantSigned = signRequest(response(200, BODY), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
    coveredComponents: ["@status", "content-digest"],
  });
  const dual = addSignature(merchantSigned, {
    keyId: "gateway-key-1",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@status", "content-digest"],
  });
  const { merchantStore, gatewayStore } = stores();
  const results = verifyAllLabels(adapted(dual, BODY_OTHER), {
    now: NOW,
    keyResolvers: resolvers({ merchantStore, gatewayStore }),
  });
  assert.equal(results.length, 2);
  for (const r of results) {
    assert.equal(r.ok, false);
    assert.equal(r.code, "BODY_DIGEST_MISMATCH");
    assert.equal(r.reason, "body does not match content-digest");
  }
});
