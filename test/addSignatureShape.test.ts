import test from "node:test";
import assert from "node:assert/strict";
import {
  addResponseSignature,
  addSignature,
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  signResponse,
  verifyAllLabels,
  verifyAllResponseLabels,
  type SignedHttpRequest,
  type SignedHttpResponse,
  type SignOptions,
  type SignResponseOptions,
} from "../src/index.js";

// Backlog #1353: the two multi-party append entry points —
// `addSignature` and `addResponseSignature` — dereferenced their
// arguments with no shape guard, so a `null` signed message escaped as
// a bare `TypeError` (`reading 'headers'` from the header scan) and a
// `null` options object as another (`Object.keys` inside
// `assertNoUnknownOptions`); a string `opts` was even misreported as an
// unknown option (`unknown option "0"`). The shared
// `assertObjectParam` guard now runs first in both — before
// `assertNoUnknownOptions` and before the header scan — with the same
// wording as the #1344 entry points, and the headers map carries its
// own guard because the scan copies it with `Object.entries` first.
// These tests pin the exact wording, the plain-`Error` (never
// `TypeError`) shape, and the untouched append contract: a legal
// second signature still lands, and an unsigned message still gets its
// existing named error.

const CREATED = 1700000000;
const NOW = CREATED + 60;

const merchant = generateEd25519KeyPair();
const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");

function asSignedReq(value: unknown): SignedHttpRequest {
  return value as SignedHttpRequest;
}
function asSignedRes(value: unknown): SignedHttpResponse {
  return value as SignedHttpResponse;
}
function asSignOpts(value: unknown): SignOptions {
  return value as SignOptions;
}
function asSignResOpts(value: unknown): SignResponseOptions {
  return value as SignResponseOptions;
}

function paymentRequest(body?: string) {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    ...(body !== undefined ? { body } : {}),
  };
}

function settlementResponse(body?: string) {
  return {
    status: 200,
    headers: { "content-type": "application/json" },
    ...(body !== undefined ? { body } : {}),
  };
}

const BODY = JSON.stringify({ amount: 250, currency: "USD" });

function gatewayOpts(): SignOptions {
  return {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
  };
}

function merchantSignedRequest(): SignedHttpRequest {
  return signRequest(paymentRequest(BODY), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
  });
}

function merchantSignedResponse(): SignedHttpResponse {
  return signResponse(settlementResponse(BODY), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
  });
}

/** The thrown error is a plain `Error`, never a bare `TypeError`. */
function assertNamedError(fn: () => unknown, pattern: RegExp): void {
  assert.throws(fn, (e: unknown) => {
    assert.ok(e instanceof Error, "expected an Error");
    assert.equal(
      e.constructor,
      Error,
      `expected a plain Error, got ${e.constructor.name}`,
    );
    assert.match(e.message, pattern);
    return true;
  });
}

// --- addSignature: the signed request ------------------------------------

test("addSignature: a null signed request throws, naming signedReq", () => {
  assertNamedError(
    () => addSignature(asSignedReq(null), gatewayOpts()),
    /^addSignature: signedReq must be an object$/,
  );
});

test("addSignature: an undefined signed request throws, naming signedReq", () => {
  assertNamedError(
    () => addSignature(asSignedReq(undefined), gatewayOpts()),
    /^addSignature: signedReq must be an object$/,
  );
});

test("addSignature: a string signed request throws, naming signedReq", () => {
  assertNamedError(
    () => addSignature(asSignedReq("x"), gatewayOpts()),
    /^addSignature: signedReq must be an object$/,
  );
});

test("addSignature: a number signed request throws, naming signedReq", () => {
  assertNamedError(
    () => addSignature(asSignedReq(42), gatewayOpts()),
    /^addSignature: signedReq must be an object$/,
  );
});

test("addSignature: an array signed request throws, naming signedReq", () => {
  assertNamedError(
    () => addSignature(asSignedReq([]), gatewayOpts()),
    /^addSignature: signedReq must be an object$/,
  );
});

test("addSignature: null opts throws, naming opts", () => {
  assertNamedError(
    () => addSignature(merchantSignedRequest(), asSignOpts(null)),
    /^addSignature: opts must be an object$/,
  );
});

test("addSignature: string opts throws, naming opts (not an unknown option)", () => {
  // Before the guard this was misreported as
  // `invalid addSignature options: unknown option "0"`.
  assertNamedError(
    () => addSignature(merchantSignedRequest(), asSignOpts("x")),
    /^addSignature: opts must be an object$/,
  );
});

test("addSignature: number opts throws, naming opts", () => {
  assertNamedError(
    () => addSignature(merchantSignedRequest(), asSignOpts(42)),
    /^addSignature: opts must be an object$/,
  );
});

test("addSignature: a null headers map throws, naming headers", () => {
  assertNamedError(
    () =>
      addSignature(
        asSignedReq({
          method: "POST",
          url: "https://api.example.com/v1/payments",
          headers: null,
        }),
        gatewayOpts(),
      ),
    /^addSignature: headers must be an object$/,
  );
});

test("addSignature: an unsigned request still gets its existing named error", () => {
  assertNamedError(
    () => addSignature(asSignedReq(paymentRequest(BODY)), gatewayOpts()),
    /^addSignature: the request has no signature-input\/signature headers; sign it with signRequest first$/,
  );
});

test("addSignature: a legal merchant + gateway append still verifies both labels", () => {
  const signed = merchantSignedRequest();
  const before = JSON.stringify(signed.headers);
  const dual = addSignature(signed, gatewayOpts());
  assert.equal(
    JSON.stringify(signed.headers),
    before,
    "the input request must not be mutated",
  );
  const results = verifyAllLabels(dual, {
    key: merchant.publicKey,
    now: NOW,
    keys: { gateway: gatewaySecret },
  });
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});

// --- addResponseSignature: the signed response -----------------------------

test("addResponseSignature: a null signed response throws, naming signedRes", () => {
  assertNamedError(
    () =>
      addResponseSignature(asSignedRes(null), {
        ...gatewayOpts(),
      }),
    /^addResponseSignature: signedRes must be an object$/,
  );
});

test("addResponseSignature: an undefined signed response throws, naming signedRes", () => {
  assertNamedError(
    () => addResponseSignature(asSignedRes(undefined), gatewayOpts()),
    /^addResponseSignature: signedRes must be an object$/,
  );
});

test("addResponseSignature: a string signed response throws, naming signedRes", () => {
  assertNamedError(
    () => addResponseSignature(asSignedRes("x"), gatewayOpts()),
    /^addResponseSignature: signedRes must be an object$/,
  );
});

test("addResponseSignature: a number signed response throws, naming signedRes", () => {
  assertNamedError(
    () => addResponseSignature(asSignedRes(42), gatewayOpts()),
    /^addResponseSignature: signedRes must be an object$/,
  );
});

test("addResponseSignature: an array signed response throws, naming signedRes", () => {
  assertNamedError(
    () => addResponseSignature(asSignedRes([]), gatewayOpts()),
    /^addResponseSignature: signedRes must be an object$/,
  );
});

test("addResponseSignature: null opts throws, naming opts", () => {
  assertNamedError(
    () =>
      addResponseSignature(
        merchantSignedResponse(),
        asSignResOpts(null),
      ),
    /^addResponseSignature: opts must be an object$/,
  );
});

test("addResponseSignature: string opts throws, naming opts (not an unknown option)", () => {
  assertNamedError(
    () =>
      addResponseSignature(merchantSignedResponse(), asSignResOpts("x")),
    /^addResponseSignature: opts must be an object$/,
  );
});

test("addResponseSignature: a null headers map throws, naming headers", () => {
  assertNamedError(
    () =>
      addResponseSignature(
        asSignedRes({ status: 200, headers: null }),
        gatewayOpts(),
      ),
    /^addResponseSignature: headers must be an object$/,
  );
});

test("addResponseSignature: an unsigned response still gets its existing named error", () => {
  assertNamedError(
    () =>
      addResponseSignature(asSignedRes(settlementResponse(BODY)), gatewayOpts()),
    /^addResponseSignature: the response has no signature-input\/signature headers; sign it with signResponse first$/,
  );
});

test("addResponseSignature: a legal merchant + gateway append still verifies both labels", () => {
  const signed = merchantSignedResponse();
  const before = JSON.stringify(signed.headers);
  const dual = addResponseSignature(signed, gatewayOpts());
  assert.equal(
    JSON.stringify(signed.headers),
    before,
    "the input response must not be mutated",
  );
  const results = verifyAllResponseLabels(dual, {
    key: merchant.publicKey,
    now: NOW,
    keys: { gateway: gatewaySecret },
  });
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});
