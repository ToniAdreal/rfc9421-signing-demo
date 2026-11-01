import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  fromNodeResponse,
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  verifyAllLabels,
  type IncomingResponseLike,
  type RequestLike,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #782: `test/nodeHttpResponse*` never mentions replayCache
// (grep 0 hits), and the request-side `nodeHttpRequestVerifyAllLabels*`
// files likewise never mention it; #775 only pinned
// `verifyAllLabels` x `replayCacheByLabel` x content-digest on the
// non-adapter path. Whether a dual-signed *response* through
// `fromNodeResponse`, with each label's nonce tracked in its own
// `replayCacheByLabel` store, keeps per-label replay isolation
// together was unpinned.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. `fromNodeResponse` already carries
// the wire signature headers verbatim and `verifyAllLabels` already
// consults each label's own store (falling back to a shared
// `replayCache` only when the map has no entry for that label).
// Zero real network.
//
// Replay-identity honesty note (read before "fixing" the fourth
// case): these labels cover only `@status`, so the signature base
// does not bind the body — a re-signed response over a different
// body with the *same* nonces is still a replay presentation, not a
// first sighting. Fresh nonces are what make the re-signed response
// first-seen again; the body change alone never resets replay.
// That is nonce-keyed replay working as designed, not a body
// binding claim, and the fourth case pins both halves of it.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const BODY_OTHER = JSON.stringify({ settled: true, amount: 1 });
const URL = "https://api.example.com/v1/charge";

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

/** Wire-style headers carrying a signature, as a server would send them. */
function wireHeaders(
  signed: SignedHttpRequest,
): Record<string, string | undefined> {
  return {
    "Signature-Input": signed.headers["signature-input"] as string,
    Signature: signed.headers["signature"] as string,
  };
}

/** A test double shaped like the fields of a client's IncomingMessage. */
function incomingResponse(
  overrides: Partial<IncomingResponseLike> & {
    headers: Record<string, string | string[] | undefined>;
  },
): IncomingResponseLike {
  return { statusCode: 200, ...overrides };
}

function response(body: string = BODY, status = 200) {
  return { method: "GET", url: URL, headers: {}, body, status };
}

/** A dual-signed response: merchant first, gateway appended. */
function dualSigned(
  body: string,
  merchantNonce: string,
  gatewayNonce: string,
  status = 200,
): SignedHttpRequest {
  const merchantSigned = signRequest(response(body, status), {
    keyId: "merchant-key",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
    coveredComponents: ["@status"],
    nonce: merchantNonce,
  });
  return addSignature(merchantSigned, {
    keyId: "gateway-key",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@status"],
    nonce: gatewayNonce,
  });
}

function adapted(signed: SignedHttpRequest, body: string = BODY): RequestLike {
  return fromNodeResponse(incomingResponse({ headers: wireHeaders(signed) }), body, {
    method: "GET",
    url: URL,
  });
}

function freshCaches() {
  return {
    merchantCache: new ReplayCache({ ttlSec: 3600, now: () => NOW }),
    gatewayCache: new ReplayCache({ ttlSec: 3600, now: () => NOW }),
  };
}

function verifyDual(
  signed: SignedHttpRequest,
  body: string,
  caches: { merchantCache: ReplayCache; gatewayCache: ReplayCache },
): VerifyResult[] {
  return verifyAllLabels(adapted(signed, body), {
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    replayCacheByLabel: {
      merchant: caches.merchantCache,
      gateway: caches.gatewayCache,
    },
    requiredComponents: ["@status"],
  });
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

test("verifyAllLabels x fromNodeResponse x replayCacheByLabel: a dual-signed response first verifies both labels through the adapter and records the shared nonce in each label's own store", () => {
  const caches = freshCaches();
  // Both parties mint nonces in their own namespace, so the same
  // bare nonce string on both labels must not cross-contaminate:
  // each store records it independently and the first presentation
  // verifies on both labels.
  const results = byLabel(
    verifyDual(dualSigned(BODY, "shared-782", "shared-782"), BODY, caches),
  );
  assert.equal(results["merchant"].ok, true, JSON.stringify(results["merchant"]));
  assert.equal(results["gateway"].ok, true, JSON.stringify(results["gateway"]));
  assert.equal(results["merchant"].nonce, "shared-782");
  assert.equal(results["gateway"].nonce, "shared-782");
  assert.ok(results["merchant"].coveredComponents?.includes("@status"));
  assert.ok(results["gateway"].coveredComponents?.includes("@status"));
  assert.equal(caches.merchantCache.size, 1);
  assert.equal(caches.gatewayCache.size, 1);
});

test("verifyAllLabels x fromNodeResponse x replayCacheByLabel: re-presenting the same dual-signed response replays on both labels through the adapter", () => {
  const caches = freshCaches();
  const signed = dualSigned(BODY, "shared-782", "shared-782");
  const first = byLabel(verifyDual(signed, BODY, caches));
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  const second = byLabel(verifyDual(signed, BODY, caches));
  assert.equal(second["merchant"].ok, false);
  assert.equal(second["merchant"].code, "NONCE_REPLAY");
  assert.ok(second["merchant"].reason?.includes("shared-782"));
  assert.equal(second["gateway"].ok, false);
  assert.equal(second["gateway"].code, "NONCE_REPLAY");
  assert.ok(second["gateway"].reason?.includes("shared-782"));
  // A replay hit does not double-record: each store still holds one entry.
  assert.equal(caches.merchantCache.size, 1);
  assert.equal(caches.gatewayCache.size, 1);
});

test("verifyAllLabels x fromNodeResponse x replayCacheByLabel: reusing only one label's nonce fails only that label through the adapter", () => {
  const caches = freshCaches();
  const first = byLabel(
    verifyDual(dualSigned(BODY, "reuse-782-m", "first-782-g"), BODY, caches),
  );
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  // A second settlement response reuses the merchant nonce but mints
  // a fresh gateway nonce: only the merchant label is a replay.
  const second = byLabel(
    verifyDual(dualSigned(BODY, "reuse-782-m", "fresh-782-g"), BODY, caches),
  );
  assert.equal(second["merchant"].ok, false);
  assert.equal(second["merchant"].code, "NONCE_REPLAY");
  assert.equal(second["merchant"].nonce, "reuse-782-m");
  assert.equal(second["gateway"].ok, true, JSON.stringify(second["gateway"]));
  assert.equal(second["gateway"].nonce, "fresh-782-g");
  assert.equal(caches.merchantCache.size, 1);
  assert.equal(caches.gatewayCache.size, 2);
});

test("verifyAllLabels x fromNodeResponse x replayCacheByLabel: a re-signed response over a new body is first-seen only with fresh nonces", () => {
  const caches = freshCaches();
  const first = byLabel(
    verifyDual(dualSigned(BODY, "old-782-m", "old-782-g"), BODY, caches),
  );
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  // A new body alone does not reset replay: re-signing over
  // BODY_OTHER with the old nonces is still a replay on both labels,
  // because replay identity is the nonce, not the body.
  const replayed = byLabel(
    verifyDual(dualSigned(BODY_OTHER, "old-782-m", "old-782-g"), BODY_OTHER, caches),
  );
  assert.equal(replayed["merchant"].ok, false);
  assert.equal(replayed["merchant"].code, "NONCE_REPLAY");
  assert.equal(replayed["gateway"].ok, false);
  assert.equal(replayed["gateway"].code, "NONCE_REPLAY");
  assert.equal(caches.merchantCache.size, 1);
  assert.equal(caches.gatewayCache.size, 1);
  // The same new body re-signed with fresh nonces is a first
  // sighting on both labels, through the same stores.
  const fresh = byLabel(
    verifyDual(dualSigned(BODY_OTHER, "new-782-m", "new-782-g"), BODY_OTHER, caches),
  );
  assert.equal(fresh["merchant"].ok, true, JSON.stringify(fresh["merchant"]));
  assert.equal(fresh["gateway"].ok, true, JSON.stringify(fresh["gateway"]));
  assert.equal(fresh["merchant"].nonce, "new-782-m");
  assert.equal(fresh["gateway"].nonce, "new-782-g");
  assert.equal(caches.merchantCache.size, 2);
  assert.equal(caches.gatewayCache.size, 2);
});
