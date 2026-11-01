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

// Backlog #793: `test/nodeHttpResponseVerifyAllLabelsTrailers.test.ts`
// (#777) pins trailer binding for a dual-signed response through
// `fromNodeResponse`, and
// `test/nodeHttpResponseVerifyAllLabelsReplayCache.test.ts` (#782)
// pins per-label replay stores for a dual-signed response through
// the same adapter — but the two pins never meet: whether a
// dual-signed response whose *each* label binds its own `;tr`
// trailer, with each label tracked in its own `replayCacheByLabel`
// store, keeps trailer isolation and per-label replay isolation
// together had no backing. A gateway-signed settlement response
// whose per-party checksums travel as trailers is exactly that case.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. `fromNodeResponse` already carries
// trailers into `RequestLike.trailers` with the header conventions,
// and `verifyAllLabels` already consults each label's own store and
// reports each label independently. Zero real network.
//
// Design note (read before "fixing" the tamper cases): the two
// labels bind *different* trailers (`x-checksum-a` vs
// `x-checksum-b`), so tampering one trailer is a signature-base
// change for that label only — the other label's base is untouched
// and it still verifies. Binding both labels to the *same*
// trailer would make one tamper fail both, which would pin
// nothing about isolation. The labels also cover only `@status`
// plus their own trailer, so the body is not bound here — same
// scope as #777 and #782, not a body-binding claim.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const TRAILER_A_VALUE = "checksum-a-value";
const TRAILER_B_VALUE = "checksum-b-value";
const URL = "https://api.example.com/v1/charge";

/** Wire-style headers carrying a dual signature, as a server would send them. */
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

/** A dual-signed response: each label binds its own trailer. */
function dualSigned(
  nonceA: string,
  nonceB: string,
): {
  signed: SignedHttpRequest;
  aPublicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
  bPublicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const a = generateEd25519KeyPair();
  const b = generateEd25519KeyPair();
  const first = signRequest(
    {
      method: "GET",
      url: URL,
      headers: {},
      body: BODY,
      status: 200,
      trailers: {
        "x-checksum-a": TRAILER_A_VALUE,
        "x-checksum-b": TRAILER_B_VALUE,
      },
    },
    {
      keyId: "a-key",
      alg: "ed25519",
      key: a.privateKey,
      created: CREATED,
      label: "trailer-a",
      coveredComponents: ["@status", "x-checksum-a;tr"],
      nonce: nonceA,
    },
  );
  // `addSignature` preserves status and trailers from the first
  // signed output, so the second label's base can resolve its own
  // trailer without the caller re-attaching anything by hand.
  const signed = addSignature(first, {
    keyId: "b-key",
    alg: "ed25519",
    key: b.privateKey,
    created: CREATED,
    label: "trailer-b",
    coveredComponents: ["@status", "x-checksum-b;tr"],
    nonce: nonceB,
  });
  return { signed, aPublicKey: a.publicKey, bPublicKey: b.publicKey };
}

type Dual = ReturnType<typeof dualSigned>;
type Caches = { aCache: ReplayCache; bCache: ReplayCache };

function freshCaches(): Caches {
  return {
    aCache: new ReplayCache({ ttlSec: 3600, now: () => NOW }),
    bCache: new ReplayCache({ ttlSec: 3600, now: () => NOW }),
  };
}

function adapted(
  signed: SignedHttpRequest,
  trailers: Record<string, string> = {
    // Mixed-case names exercise the adapter's lowercasing, the same
    // convention it applies to headers.
    "X-Checksum-A": TRAILER_A_VALUE,
    "x-checksum-b": TRAILER_B_VALUE,
  },
): RequestLike {
  return fromNodeResponse(
    incomingResponse({ headers: wireHeaders(signed), trailers }),
    BODY,
    { method: "GET", url: URL },
  );
}

function verifyDual(
  dual: Dual,
  caches: Caches,
  trailers?: Record<string, string>,
): VerifyResult[] {
  return verifyAllLabels(adapted(dual.signed, trailers), {
    now: NOW,
    keys: { "trailer-a": dual.aPublicKey, "trailer-b": dual.bPublicKey },
    replayCacheByLabel: {
      "trailer-a": caches.aCache,
      "trailer-b": caches.bCache,
    },
  });
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

test("verifyAllLabels x trailers x replayCacheByLabel: a dual-signed response verifies both labels through the adapter and records each nonce in its own store", () => {
  const caches = freshCaches();
  const dual = dualSigned("nonce-793-a", "nonce-793-b");
  const req = adapted(dual.signed);
  assert.deepEqual(req.trailers, {
    "x-checksum-a": TRAILER_A_VALUE,
    "x-checksum-b": TRAILER_B_VALUE,
  });
  const results = byLabel(verifyDual(dual, caches));
  assert.equal(results["trailer-a"].ok, true, JSON.stringify(results["trailer-a"]));
  assert.equal(results["trailer-b"].ok, true, JSON.stringify(results["trailer-b"]));
  assert.equal(results["trailer-a"].nonce, "nonce-793-a");
  assert.equal(results["trailer-b"].nonce, "nonce-793-b");
  assert.ok(results["trailer-a"].coveredComponents?.includes("@status"));
  assert.ok(results["trailer-a"].coveredComponents?.includes("x-checksum-a;tr"));
  assert.equal(
    results["trailer-a"].coveredComponents?.includes("x-checksum-b;tr"),
    false,
    "label trailer-a must not claim the other label's trailer",
  );
  assert.ok(results["trailer-b"].coveredComponents?.includes("@status"));
  assert.ok(results["trailer-b"].coveredComponents?.includes("x-checksum-b;tr"));
  assert.equal(
    results["trailer-b"].coveredComponents?.includes("x-checksum-a;tr"),
    false,
    "label trailer-b must not claim the other label's trailer",
  );
  // Each label's own store holds exactly its own nonce: no sharing,
  // no cross-contamination between the two trailer parties.
  assert.equal(caches.aCache.size, 1);
  assert.equal(caches.bCache.size, 1);
});

test("verifyAllLabels x trailers x replayCacheByLabel: re-presenting the same dual-signed response replays on both labels", () => {
  const caches = freshCaches();
  const dual = dualSigned("nonce-793-a", "nonce-793-b");
  const first = byLabel(verifyDual(dual, caches));
  assert.equal(first["trailer-a"].ok, true);
  assert.equal(first["trailer-b"].ok, true);
  const second = byLabel(verifyDual(dual, caches));
  assert.equal(second["trailer-a"].ok, false);
  assert.equal(second["trailer-a"].code, "NONCE_REPLAY");
  assert.ok(second["trailer-a"].reason?.includes("nonce-793-a"));
  assert.equal(second["trailer-b"].ok, false);
  assert.equal(second["trailer-b"].code, "NONCE_REPLAY");
  assert.ok(second["trailer-b"].reason?.includes("nonce-793-b"));
  // A replay hit does not double-record: each store still holds one entry.
  assert.equal(caches.aCache.size, 1);
  assert.equal(caches.bCache.size, 1);
});

test("verifyAllLabels x trailers x replayCacheByLabel: reusing only one label's nonce fails only that label", () => {
  const caches = freshCaches();
  const first = byLabel(
    verifyDual(dualSigned("reuse-793-a", "first-793-b"), caches),
  );
  assert.equal(first["trailer-a"].ok, true);
  assert.equal(first["trailer-b"].ok, true);
  // A second settlement response reuses label A's nonce but mints a
  // fresh label-B nonce: only label A is a replay.
  const second = byLabel(
    verifyDual(dualSigned("reuse-793-a", "fresh-793-b"), caches),
  );
  assert.equal(second["trailer-a"].ok, false);
  assert.equal(second["trailer-a"].code, "NONCE_REPLAY");
  assert.equal(second["trailer-a"].nonce, "reuse-793-a");
  assert.equal(second["trailer-b"].ok, true, JSON.stringify(second["trailer-b"]));
  assert.equal(second["trailer-b"].nonce, "fresh-793-b");
  assert.equal(caches.aCache.size, 1);
  assert.equal(caches.bCache.size, 2);
});

test("verifyAllLabels x trailers x replayCacheByLabel: tampering one trailer fails only that label and its failed presentation is never recorded", () => {
  const caches = freshCaches();
  const dual = dualSigned("nonce-793-a", "nonce-793-b");
  const tampered = byLabel(
    verifyDual(dual, caches, {
      "x-checksum-a": "forged-value",
      "x-checksum-b": TRAILER_B_VALUE,
    }),
  );
  assert.equal(tampered["trailer-a"].ok, false);
  assert.equal(tampered["trailer-a"].code, "SIGNATURE_MISMATCH");
  assert.equal(tampered["trailer-b"].ok, true, JSON.stringify(tampered["trailer-b"]));
  // Failed verifications never pollute the store: label A's cache
  // is still empty, while label B's passed presentation is recorded.
  assert.equal(caches.aCache.size, 0);
  assert.equal(caches.bCache.size, 1);
  // Follow-through: the same response over the untampered trailers
  // now passes label A (its nonce was never recorded) but replays
  // label B (its nonce was recorded during the tampered run).
  const corrected = byLabel(verifyDual(dual, caches));
  assert.equal(corrected["trailer-a"].ok, true, JSON.stringify(corrected["trailer-a"]));
  assert.equal(corrected["trailer-b"].ok, false);
  assert.equal(corrected["trailer-b"].code, "NONCE_REPLAY");
  assert.equal(caches.aCache.size, 1);
  assert.equal(caches.bCache.size, 1);
});

test("verifyAllLabels x trailers x replayCacheByLabel: tampering the other trailer is symmetric", () => {
  const caches = freshCaches();
  const dual = dualSigned("nonce-793-a", "nonce-793-b");
  const tampered = byLabel(
    verifyDual(dual, caches, {
      "x-checksum-a": TRAILER_A_VALUE,
      "x-checksum-b": "forged-value",
    }),
  );
  assert.equal(tampered["trailer-a"].ok, true, JSON.stringify(tampered["trailer-a"]));
  assert.equal(tampered["trailer-b"].ok, false);
  assert.equal(tampered["trailer-b"].code, "SIGNATURE_MISMATCH");
  assert.equal(caches.aCache.size, 1);
  assert.equal(caches.bCache.size, 0);
});
