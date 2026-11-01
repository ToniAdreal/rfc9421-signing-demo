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

// Backlog #784: `test/expectedTagsPerLabel.test.ts` never mentions
// fromNodeResponse (grep 0 hits), and the per-label `expectedTags`
// map was therefore backed only on the hand-built `RequestLike`
// path, never on a dual-signed *response* arriving through
// `fromNodeResponse` — the shape a client actually verifies when
// a gateway-signed settlement response comes back over HTTP.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. `fromNodeResponse` already carries
// the wire signature headers verbatim (lowercasing their names,
// the same normalization it applies to ordinary headers), and
// `verifyAllLabels` already resolves each label's tag pin from
// `expectedTags`, falling back to the global `expectedTag` only
// for labels the map does not name. Zero real network.
//
// Tag-check honesty note: `expectedTag` is checked after the
// crypto verification (see `src/verify.ts`), so a label minted
// for another protocol still verifies cryptographically and then
// fails with `TAG_MISMATCH` — the pin, not the signature, is
// what rejects it. A label carrying no tag at all fails the same
// way when the map pins it (`TAG_MISMATCH`, reported tag
// `undefined`); absence of a pin means no check, not a default
// rejection.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const URL = "https://api.example.com/v1/charge";
const MERCHANT_TAG = "payment-initiation-v1";
const GATEWAY_TAG = "settlement-webhook-v1";

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

/**
 * A dual-signed response: merchant first, gateway appended.
 * Pass a tag of `null` to mint that label tagless.
 */
function dualSigned(
  merchantTag: string | null = MERCHANT_TAG,
  gatewayTag: string | null = GATEWAY_TAG,
): SignedHttpRequest {
  const merchantSigned = signRequest(response(), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
    coveredComponents: ["@status"],
    ...(merchantTag === null ? {} : { tag: merchantTag }),
  });
  return addSignature(merchantSigned, {
    keyId: "gateway-key-1",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@status"],
    ...(gatewayTag === null ? {} : { tag: gatewayTag }),
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
    expectedTags?: Record<string, string>;
    expectedTag?: string;
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

test("verifyAllLabels x fromNodeResponse x expectedTags: a dual-signed response verifies both labels through the adapter, each pinned to its own protocol tag", () => {
  const results = verify(adapted(dualSigned()), {
    expectedTags: { merchant: MERCHANT_TAG, gateway: GATEWAY_TAG },
  });
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[0].tag, MERCHANT_TAG);
  assert.ok(results[0].coveredComponents?.includes("@status"));
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
  assert.equal(results[1].tag, GATEWAY_TAG);
  assert.ok(results[1].coveredComponents?.includes("@status"));
});

test("verifyAllLabels x fromNodeResponse x expectedTags: one label's tag mismatch fails only that label with TAG_MISMATCH, the other unaffected", () => {
  const results = byLabel(
    verify(adapted(dualSigned(MERCHANT_TAG, "other-protocol")), {
      expectedTags: { merchant: MERCHANT_TAG, gateway: GATEWAY_TAG },
    }),
  );
  assert.equal(results["merchant"].ok, true, JSON.stringify(results["merchant"]));
  assert.equal(results["gateway"].ok, false);
  assert.equal(results["gateway"].code, "TAG_MISMATCH");
  assert.equal(results["gateway"].tag, "other-protocol");
});

test("verifyAllLabels x fromNodeResponse x expectedTags: a label minted tagless fails only itself with TAG_MISMATCH when the map pins it, the other unaffected", () => {
  const results = byLabel(
    verify(adapted(dualSigned(null, GATEWAY_TAG)), {
      expectedTags: { merchant: MERCHANT_TAG, gateway: GATEWAY_TAG },
    }),
  );
  assert.equal(results["merchant"].ok, false);
  assert.equal(results["merchant"].code, "TAG_MISMATCH");
  assert.equal(results["merchant"].tag, undefined);
  assert.equal(results["gateway"].ok, true, JSON.stringify(results["gateway"]));
  assert.equal(results["gateway"].tag, GATEWAY_TAG);
});

test("verifyAllLabels x fromNodeResponse x expectedTags: tags swapped between labels fail both labels with TAG_MISMATCH (cross-protocol transplant rejected)", () => {
  // Each signature is cryptographically valid — the merchant
  // label was genuinely minted, just for the gateway's protocol,
  // and vice versa — so only the tag pins reject them, both of
  // them, independently.
  const results = byLabel(
    verify(adapted(dualSigned(GATEWAY_TAG, MERCHANT_TAG)), {
      expectedTags: { merchant: MERCHANT_TAG, gateway: GATEWAY_TAG },
    }),
  );
  assert.equal(results["merchant"].ok, false);
  assert.equal(results["merchant"].code, "TAG_MISMATCH");
  assert.equal(results["merchant"].tag, GATEWAY_TAG);
  assert.equal(results["gateway"].ok, false);
  assert.equal(results["gateway"].code, "TAG_MISMATCH");
  assert.equal(results["gateway"].tag, MERCHANT_TAG);
});

test("verifyAllLabels x fromNodeResponse x expectedTags: adapter and direct paths agree on a mixed pass/fail pair", () => {
  const signed = dualSigned(MERCHANT_TAG, "other-protocol");
  const opts = {
    expectedTags: { merchant: MERCHANT_TAG, gateway: GATEWAY_TAG },
  };
  const adaptedResults = byLabel(verify(adapted(signed), opts));
  const directResults = byLabel(verify(signed, opts));
  assert.deepEqual(
    directResults,
    adaptedResults,
    "adapter and direct paths must agree on the tag check",
  );
  assert.equal(adaptedResults["merchant"].ok, true);
  assert.equal(adaptedResults["gateway"].code, "TAG_MISMATCH");
});

test("verifyAllLabels x fromNodeResponse x expectedTags: a label absent from the map is unchecked through the adapter when no global expectedTag is set", () => {
  // Only the gateway is pinned; the merchant label is tagless,
  // so it must pass through the adapter exactly as on the direct
  // path — pin absence means no check, not a default rejection.
  const opts = { expectedTags: { gateway: GATEWAY_TAG } };
  const signed = dualSigned(null, GATEWAY_TAG);
  const adaptedResults = byLabel(verify(adapted(signed), opts));
  assert.equal(adaptedResults["merchant"].ok, true, JSON.stringify(adaptedResults["merchant"]));
  assert.equal(adaptedResults["merchant"].tag, undefined);
  assert.equal(adaptedResults["gateway"].ok, true, JSON.stringify(adaptedResults["gateway"]));
  const directResults = byLabel(verify(signed, opts));
  assert.deepEqual(
    directResults,
    adaptedResults,
    "adapter and direct paths must agree on the unpinned label",
  );
});

test("verifyAllLabels x fromNodeResponse x expectedTags: the global expectedTag fallback applies through the adapter to labels the map does not name", () => {
  // The merchant is not pinned per-label, so the global tag
  // applies to it; the gateway uses its own per-label pin.
  const passing = byLabel(
    verify(adapted(dualSigned()), {
      expectedTag: MERCHANT_TAG,
      expectedTags: { gateway: GATEWAY_TAG },
    }),
  );
  assert.equal(passing["merchant"].ok, true, JSON.stringify(passing["merchant"]));
  assert.equal(passing["gateway"].ok, true, JSON.stringify(passing["gateway"]));
  // The same global tag, with an empty map, must fail the
  // gateway label through the adapter exactly as on the direct
  // path.
  const failing = byLabel(
    verify(adapted(dualSigned()), {
      expectedTag: MERCHANT_TAG,
      expectedTags: {},
    }),
  );
  assert.equal(failing["merchant"].ok, true, JSON.stringify(failing["merchant"]));
  assert.equal(failing["gateway"].ok, false);
  assert.equal(failing["gateway"].code, "TAG_MISMATCH");
});
