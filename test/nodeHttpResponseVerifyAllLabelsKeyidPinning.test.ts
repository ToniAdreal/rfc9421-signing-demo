import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  fromNodeResponse,
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  type IncomingResponseLike,
  type RequestLike,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #783: `test/keyidPinningPerLabel.test.ts` never mentions
// fromNodeResponse (grep 0 hits), and
// `test/nodeHttpResponseVerifyAllLabels.test.ts` never mentions
// pinning. Per-label `expectedKeyIds` binding was therefore backed
// only on the hand-built `RequestLike` path, never on a dual-signed
// *response* arriving through `fromNodeResponse` — the shape a
// client actually verifies when a gateway-signed settlement
// response comes back over HTTP.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. `fromNodeResponse` already carries
// the wire signature headers verbatim (lowercasing their names,
// the same normalization it applies to ordinary headers), and
// `verifyAllLabels` already resolves each label's pin from
// `expectedKeyIds`, falling back to the global `expectedKeyId`
// only for labels the map does not name. Zero real network.
//
// Pinning-order honesty note: `expectedKeyId` is checked after
// the crypto verification (see `src/verify.ts`), so a re-signed
// label with a rotated kid but the same key still verifies
// cryptographically and then fails with `KEYID_MISMATCH` — the
// pin, not the signature, is what rejects it. The rotated-kid
// case below pins exactly that order, and the wrong-pin case
// pins the same code without re-signing.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
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
  merchantKeyId = "merchant-key-1",
  gatewayKeyId = "gateway-key-1",
): SignedHttpRequest {
  const merchantSigned = signRequest(response(), {
    keyId: merchantKeyId,
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
    coveredComponents: ["@status"],
  });
  return addSignature(merchantSigned, {
    keyId: gatewayKeyId,
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@status"],
  });
}

function adapted(signed: SignedHttpRequest): RequestLike {
  return fromNodeResponse(
    incomingResponse({ headers: wireHeaders(signed) }),
    BODY,
    { method: "GET", url: URL },
  );
}

function verify(
  req: RequestLike,
  opts: {
    expectedKeyIds?: Record<string, string>;
    expectedKeyId?: string;
  },
): VerifyResult[] {
  return verifyAllLabels(req, {
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    ...opts,
  });
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

test("verifyAllLabels x fromNodeResponse x keyid pinning: a dual-signed response verifies both labels through the adapter, each pinned to its own keyid", () => {
  const results = verify(adapted(dualSigned()), {
    expectedKeyIds: { merchant: "merchant-key-1", gateway: "gateway-key-1" },
  });
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.ok(results[0].coveredComponents?.includes("@status"));
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
  assert.equal(results[1].keyId, "gateway-key-1");
  assert.ok(results[1].coveredComponents?.includes("@status"));
});

test("verifyAllLabels x fromNodeResponse x keyid pinning: a label re-signed under a rotated kid fails only that label with KEYID_MISMATCH", () => {
  // The merchant rotates its kid but keeps the same key: the
  // signature still verifies cryptographically, so only the pin
  // rejects it — and only on the merchant label.
  const results = byLabel(
    verify(adapted(dualSigned("merchant-key-2", "gateway-key-1")), {
      expectedKeyIds: { merchant: "merchant-key-1", gateway: "gateway-key-1" },
    }),
  );
  assert.equal(results["merchant"].ok, false);
  assert.equal(results["merchant"].code, "KEYID_MISMATCH");
  assert.equal(results["merchant"].keyId, "merchant-key-2");
  assert.equal(results["gateway"].ok, true, JSON.stringify(results["gateway"]));
  assert.equal(results["gateway"].keyId, "gateway-key-1");
});

test("verifyAllLabels x fromNodeResponse x keyid pinning: a wrong pin on one label fails it with KEYID_MISMATCH, the other unaffected", () => {
  const results = byLabel(
    verify(adapted(dualSigned()), {
      expectedKeyIds: { merchant: "merchant-key-1", gateway: "gateway-key-OTHER" },
    }),
  );
  assert.equal(results["merchant"].ok, true, JSON.stringify(results["merchant"]));
  assert.equal(results["gateway"].ok, false);
  assert.equal(results["gateway"].code, "KEYID_MISMATCH");
  assert.equal(results["gateway"].keyId, "gateway-key-1");
});

test("verifyAllLabels x fromNodeResponse x keyid pinning: a label missing from the pin map is unchecked on both the adapter and the direct path, even after its kid rotates", () => {
  // Only the merchant is pinned; the gateway label carries no pin,
  // so a gateway kid rotation must pass on both paths — pinning
  // absence means no check, not a default rejection.
  const opts = { expectedKeyIds: { merchant: "merchant-key-1" } };
  const signed = dualSigned("merchant-key-1", "gateway-key-9");
  const adaptedResults = byLabel(verify(adapted(signed), opts));
  assert.equal(adaptedResults["merchant"].ok, true, JSON.stringify(adaptedResults["merchant"]));
  assert.equal(adaptedResults["gateway"].ok, true, JSON.stringify(adaptedResults["gateway"]));
  assert.equal(adaptedResults["gateway"].keyId, "gateway-key-9");
  const directResults = byLabel(verify(signed, opts));
  assert.deepEqual(
    directResults,
    adaptedResults,
    "adapter and direct paths must agree on the unpinned label",
  );
});

test("verifyAllLabels x fromNodeResponse x keyid pinning: the global expectedKeyId fallback applies through the adapter to labels the map does not name", () => {
  // The merchant is not pinned per-label, so the global pin
  // applies to it; the gateway uses its own per-label pin.
  const passing = byLabel(
    verify(adapted(dualSigned()), {
      expectedKeyId: "merchant-key-1",
      expectedKeyIds: { gateway: "gateway-key-1" },
    }),
  );
  assert.equal(passing["merchant"].ok, true, JSON.stringify(passing["merchant"]));
  assert.equal(passing["gateway"].ok, true, JSON.stringify(passing["gateway"]));
  // The same global pin, with an empty map, must fail the gateway
  // label through the adapter exactly as on the direct path.
  const failing = byLabel(
    verify(adapted(dualSigned()), {
      expectedKeyId: "merchant-key-1",
      expectedKeyIds: {},
    }),
  );
  assert.equal(failing["merchant"].ok, true, JSON.stringify(failing["merchant"]));
  assert.equal(failing["gateway"].ok, false);
  assert.equal(failing["gateway"].code, "KEYID_MISMATCH");
});
