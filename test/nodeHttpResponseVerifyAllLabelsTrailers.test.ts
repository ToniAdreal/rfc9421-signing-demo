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
} from "../src/index.js";

// Backlog #777: `test/nodeHttpResponseVerifyAllLabels.test.ts` (#737)
// pins dual-signed responses through `fromNodeResponse`, and
// `test/nodeHttpRequestVerifyAllLabelsTrailers.test.ts` (#757) pins
// trailer binding for dual-signed requests — but the response-side
// mirror was unpinned: whether a dual-signed response received
// through `fromNodeResponse` keeps trailer binding and per-label
// isolation together had no backing. A gateway-signed settlement
// response whose checksum travels as a trailer is exactly that case.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. `fromNodeResponse` already carries
// trailers (parsed object or raw form) into `RequestLike.trailers`
// with the header conventions, and `verifyAllLabels` already
// reports each label independently.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const TRAILER_VALUE = "trailer-value";
const URL = "https://api.example.com/v1/charge";

/** A dual-signed response: one label binds the trailer, one does not. */
function dualSigned(): {
  signed: SignedHttpRequest;
  trailerPublicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
  plainPublicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const trailer = generateEd25519KeyPair();
  const plain = generateEd25519KeyPair();
  const first = signResponseWithTrailer(trailer.privateKey);
  const signed = addSignature(first, {
    keyId: "plain-key",
    alg: "ed25519",
    key: plain.privateKey,
    created: CREATED,
    label: "plain",
    coveredComponents: ["@status"],
  });
  return {
    signed,
    trailerPublicKey: trailer.publicKey,
    plainPublicKey: plain.publicKey,
  };
}

function signResponseWithTrailer(
  privateKey: ReturnType<typeof generateEd25519KeyPair>["privateKey"],
): SignedHttpRequest {
  return signRequest(
    {
      method: "GET",
      url: URL,
      headers: {},
      body: BODY,
      status: 200,
      trailers: { "x-checksum": TRAILER_VALUE },
    },
    {
      keyId: "trailer-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      label: "trailer",
      coveredComponents: ["@status", "x-checksum;tr"],
    },
  );
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

function keysFor(dual: ReturnType<typeof dualSigned>) {
  return {
    trailer: dual.trailerPublicKey,
    plain: dual.plainPublicKey,
  };
}

test("verifyAllLabels x fromNodeResponse x trailers: a dual-signed response verifies both labels through the adapter", () => {
  const dual = dualSigned();
  const req = adapted(dual.signed, {
    // Mixed-case name exercises the adapter's lowercasing, the same
    // convention it applies to headers.
    trailers: { "X-Checksum": TRAILER_VALUE },
  });
  assert.deepEqual(req.trailers, { "x-checksum": TRAILER_VALUE });
  const results = verifyAllLabels(req, { now: NOW, keys: keysFor(dual) });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["trailer", "plain"],
  );
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[0].keyId, "trailer-key");
  assert.ok(results[0].coveredComponents?.includes("@status"));
  assert.ok(results[0].coveredComponents?.includes("x-checksum;tr"));
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
  assert.equal(results[1].keyId, "plain-key");
  assert.ok(results[1].coveredComponents?.includes("@status"));
  assert.equal(
    results[1].coveredComponents?.includes("x-checksum;tr"),
    false,
    "the plain label must not claim trailer coverage",
  );
});

test("verifyAllLabels x fromNodeResponse x trailers: a tampered trailer fails only the trailer label", () => {
  const dual = dualSigned();
  const req = adapted(dual.signed, {
    trailers: { "x-checksum": "forged-value" },
  });
  const results = verifyAllLabels(req, { now: NOW, keys: keysFor(dual) });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "trailer");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_MISMATCH");
  assert.equal(results[1].label, "plain");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});

test("verifyAllLabels x fromNodeResponse x trailers: a missing trailer fails only the trailer label", () => {
  const dual = dualSigned();
  const req = adapted(dual.signed);
  assert.equal("trailers" in req, false);
  const results = verifyAllLabels(req, { now: NOW, keys: keysFor(dual) });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "trailer");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.equal(results[1].label, "plain");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});

test("verifyAllLabels x fromNodeResponse x trailers: rawTrailers verify both labels end to end", () => {
  const dual = dualSigned();
  const req = adapted(dual.signed, {
    rawTrailers: ["X-Checksum", TRAILER_VALUE],
  });
  assert.deepEqual(req.trailers, { "x-checksum": TRAILER_VALUE });
  const results = verifyAllLabels(req, { now: NOW, keys: keysFor(dual) });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["trailer", true],
      ["plain", true],
    ],
  );
});

test("verifyAllLabels x fromNodeResponse x trailers: each label is checked against its own key", () => {
  const dual = dualSigned();
  const stranger = generateEd25519KeyPair();
  const req = adapted(dual.signed, {
    trailers: { "x-checksum": TRAILER_VALUE },
  });
  const results = verifyAllLabels(req, {
    now: NOW,
    keys: { trailer: stranger.publicKey, plain: dual.plainPublicKey },
  });
  assert.equal(results[0].label, "trailer");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_MISMATCH");
  assert.equal(results[1].label, "plain");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});
