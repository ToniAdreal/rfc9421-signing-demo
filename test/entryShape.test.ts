import test from "node:test";
import assert from "node:assert/strict";
import {
  assertObjectParam,
  generateEd25519KeyPair,
  getHeader,
  getHeaderRaw,
  signRequest,
  signResponse,
  verifyAllLabels,
  verifyAllLabelsOrThrow,
  verifyRequest,
  verifyRequestOrThrow,
  verifyResponse,
  verifyResponseOrThrow,
  type HttpResponseLike,
  type RequestLike,
  type SignOptions,
  type VerifyOptions,
} from "../src/index.js";

// Backlog #1344: the five sign/verify entry points dereferenced their
// arguments with no shape guard, so a `null` request, response, or
// options object escaped as a bare `TypeError` (`reading 'headers'`,
// `reading 'body'`, `reading 'status'`, or `Object.keys` on `null`)
// instead of the library's named configuration error. The shared
// `assertObjectParam` guard now runs first in every entry point —
// before `assertNoUnknownOptions`, which dereferences `opts` itself —
// and in `getHeader` / `getHeaderRaw`, so a `null` headers map is a
// named error too. These tests pin the exact wording, the plain-`Error`
// (never `TypeError`) shape, and the untouched wire contract: a
// malformed signature is still a `{ ok: false, code }` result, never
// a throw (backlog #31).

const CREATED = 1700000000;
const NOW = CREATED + 60;

const { publicKey, privateKey } = generateEd25519KeyPair();
const signOpts: SignOptions = {
  keyId: "k1",
  alg: "ed25519",
  key: privateKey,
  created: CREATED,
};
const verifyOpts: VerifyOptions = { key: publicKey, now: NOW };
const req: RequestLike = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: {},
};
const res: HttpResponseLike = { status: 200, headers: {} };

function asReq(value: unknown): RequestLike {
  return value as RequestLike;
}
function asRes(value: unknown): HttpResponseLike {
  return value as HttpResponseLike;
}
function asSignOpts(value: unknown): SignOptions {
  return value as SignOptions;
}
function asVerifyOpts(value: unknown): VerifyOptions {
  return value as VerifyOptions;
}

/** The error must be a plain named `Error` with the exact message — never a bare `TypeError`. */
function assertNamedError(fn: () => unknown, message: string): void {
  assert.throws(fn, (e: unknown) => {
    assert.ok(e instanceof Error, `must throw an Error: ${String(e)}`);
    assert.ok(
      !(e instanceof TypeError),
      `must be a named Error, not a bare TypeError: ${e}`,
    );
    assert.equal(e.name, "Error");
    assert.equal(e.message, message);
    return true;
  });
}

// --- assertObjectParam (direct) -------------------------------------------

test("assertObjectParam rejects null, non-object, and array values with the exact wording", () => {
  for (const bad of [null, undefined, "x", 42, true, []]) {
    assertNamedError(
      () => assertObjectParam("signRequest", "req", bad),
      "signRequest: req must be an object",
    );
  }
});

test("assertObjectParam accepts a plain object and names the caller and parameter", () => {
  assert.doesNotThrow(() => assertObjectParam("verifyResponse", "res", {}));
  assertNamedError(
    () => assertObjectParam("verifyResponse", "opts", null),
    "verifyResponse: opts must be an object",
  );
});

// --- null req / res ---------------------------------------------------------

test("signRequest(null, opts) throws a named error", () => {
  assertNamedError(
    () => signRequest(asReq(null), signOpts),
    "signRequest: req must be an object",
  );
});

test("verifyRequest(null, opts) throws a named error", () => {
  assertNamedError(
    () => verifyRequest(asReq(null), verifyOpts),
    "verifyRequest: req must be an object",
  );
});

test("verifyAllLabels(null, opts) throws a named error", () => {
  assertNamedError(
    () => verifyAllLabels(asReq(null), verifyOpts),
    "verifyAllLabels: req must be an object",
  );
});

test("signResponse(null, opts) throws a named error", () => {
  assertNamedError(
    () => signResponse(asRes(null), signOpts),
    "signResponse: res must be an object",
  );
});

test("verifyResponse(null, opts) throws a named error", () => {
  assertNamedError(
    () => verifyResponse(asRes(null), verifyOpts),
    "verifyResponse: res must be an object",
  );
});

// --- null opts --------------------------------------------------------------

test("signRequest(req, null) throws a named error", () => {
  assertNamedError(
    () => signRequest(req, asSignOpts(null)),
    "signRequest: opts must be an object",
  );
});

test("verifyRequest(req, null) throws a named error", () => {
  assertNamedError(
    () => verifyRequest(req, asVerifyOpts(null)),
    "verifyRequest: opts must be an object",
  );
});

test("verifyAllLabels(req, null) throws a named error", () => {
  assertNamedError(
    () => verifyAllLabels(req, asVerifyOpts(null)),
    "verifyAllLabels: opts must be an object",
  );
});

test("signResponse(res, null) throws a named error", () => {
  assertNamedError(
    () => signResponse(res, asSignOpts(null)),
    "signResponse: opts must be an object",
  );
});

test("verifyResponse(res, null) throws a named error", () => {
  assertNamedError(
    () => verifyResponse(res, asVerifyOpts(null)),
    "verifyResponse: opts must be an object",
  );
});

// --- non-object variants ---------------------------------------------------

test("string, number, and array req/res/opts are rejected with the same named error", () => {
  assertNamedError(
    () => verifyRequest(asReq("x"), verifyOpts),
    "verifyRequest: req must be an object",
  );
  assertNamedError(
    () => verifyRequest(asReq(42), verifyOpts),
    "verifyRequest: req must be an object",
  );
  assertNamedError(
    () => signRequest(asReq([]), signOpts),
    "signRequest: req must be an object",
  );
  assertNamedError(
    () => verifyResponse(asRes([]), verifyOpts),
    "verifyResponse: res must be an object",
  );
  assertNamedError(
    () => verifyRequest(req, asVerifyOpts("x")),
    "verifyRequest: opts must be an object",
  );
  assertNamedError(
    () => signResponse(res, asSignOpts([])),
    "signResponse: opts must be an object",
  );
});

// --- null headers map -------------------------------------------------------

test("verifyRequest on a request with a null headers map throws the getHeader named error", () => {
  assertNamedError(
    () =>
      verifyRequest(
        { method: "GET", url: "https://api.example.com/v1/payments", headers: null } as unknown as RequestLike,
        verifyOpts,
      ),
    "getHeader: headers must be an object",
  );
});

test("signRequest on a null headers map throws the entry's named headers error", () => {
  assertNamedError(
    () =>
      signRequest(
        { method: "GET", url: "https://api.example.com/v1/payments", headers: null } as unknown as RequestLike,
        { ...signOpts, coveredComponents: ["x-custom"] },
      ),
    "signRequest: headers must be an object",
  );
});

test("signResponse on a null headers map throws the entry's named headers error", () => {
  assertNamedError(
    () =>
      signResponse(
        { status: 200, headers: null } as unknown as HttpResponseLike,
        signOpts,
      ),
    "signResponse: headers must be an object",
  );
});

// --- getHeader / getHeaderRaw (direct) --------------------------------------

test("getHeader and getHeaderRaw reject a null or non-object headers map", () => {
  for (const bad of [null, undefined, "x", 42, []]) {
    assertNamedError(
      () => getHeader(bad as never, "x-custom"),
      "getHeader: headers must be an object",
    );
    assertNamedError(
      () => getHeaderRaw(bad as never, "x-custom"),
      "getHeaderRaw: headers must be an object",
    );
  }
});

test("getHeader still reads a valid headers map (control)", () => {
  assert.equal(getHeader({ "X-Custom": "v1", "X-Multi": ["a", "b"] }, "x-custom"), "v1");
  assert.equal(getHeader({ "X-Multi": ["a", "b"] }, "x-multi"), "a, b");
  assert.equal(getHeaderRaw({ "X-Pad": "  v1  " }, "x-pad"), "  v1  ");
  assert.equal(getHeader({}, "x-missing"), undefined);
});

// --- OrThrow variants inherit the guard ------------------------------------

test("verifyRequestOrThrow(null, opts) throws the named entry error, not a VerifyError", () => {
  assertNamedError(
    () => verifyRequestOrThrow(asReq(null), verifyOpts),
    "verifyRequest: req must be an object",
  );
});

test("verifyAllLabelsOrThrow(req, null) throws the named entry error", () => {
  assertNamedError(
    () => verifyAllLabelsOrThrow(req, asVerifyOpts(null)),
    "verifyAllLabels: opts must be an object",
  );
});

test("verifyResponseOrThrow(null, opts) throws the named entry error", () => {
  assertNamedError(
    () => verifyResponseOrThrow(asRes(null), verifyOpts),
    "verifyResponse: res must be an object",
  );
});

// --- legal round-trips unchanged --------------------------------------------

test("legal request and response round-trips still verify", () => {
  const signed = signRequest(req, signOpts);
  const verified = verifyRequest(signed, verifyOpts);
  assert.equal(verified.ok, true);
  assert.equal(verified.label, "sig1");

  const signedRes = signResponse(res, signOpts);
  const verifiedRes = verifyResponse(signedRes, verifyOpts);
  assert.equal(verifiedRes.ok, true);
  assert.equal(verifiedRes.label, "sig1");
});

// --- malformed wire input is still { ok: false, code }, never a throw ------

test("malformed signature-input still returns a failure result, never throws (backlog #31)", () => {
  const bad: RequestLike = {
    method: "GET",
    url: "https://api.example.com/v1/payments",
    headers: {
      "signature-input": "not-a-dictionary",
      signature: "sig1=:AAAA:",
    },
  };
  const result = verifyRequest(bad, verifyOpts);
  assert.equal(result.ok, false);
  assert.equal(result.code, "MALFORMED_SIGNATURE_INPUT");

  const all = verifyAllLabels(bad, verifyOpts);
  assert.equal(all.length, 1);
  assert.equal(all[0]?.ok, false);
  assert.equal(all[0]?.code, "MALFORMED_SIGNATURE_INPUT");
});

test("malformed response signature-input still returns a failure result, never throws", () => {
  const badRes: HttpResponseLike = {
    status: 200,
    headers: {
      "signature-input": "not-a-dictionary",
      signature: "sig1=:AAAA:",
    },
  };
  const result = verifyResponse(badRes, verifyOpts);
  assert.equal(result.ok, false);
  assert.equal(result.code, "MALFORMED_SIGNATURE_INPUT");
});
